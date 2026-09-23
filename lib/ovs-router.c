/*
 * Copyright (c) 2014, 2015, 2016, 2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "ovs-router.h"

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "classifier.h"
#include "command-line.h"
#include "compiler.h"
#include "cmap.h"
#include "dp-hash-map.h"
#include "dpif.h"
#include "fatal-signal.h"
#include "hash.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "netdev.h"
#include "nexthop-table.h"
#include "packets.h"
#include "seq.h"
#include "ovs-thread.h"
#include "route-table.h"
#include "pvector.h"
#include "tnl-ports.h"
#include "unixctl.h"
#include "util.h"
#include "unaligned.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovs_router);

struct clsmap_node {
    struct cmap_node cmap_node;
    uint32_t table;
    struct classifier cls;
};

struct router_rule {
    uint32_t prio;
    bool invert;
    bool ipv4;
    bool user;
    uint8_t src_prefix;
    struct in6_addr from_addr;
    uint32_t lookup_table;
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static struct cmap clsmap = CMAP_INITIALIZER;
static struct pvector rules;

/* By default, use the system routing table.  For system-independent testing,
 * the unit tests disable using the system routing table. */
static bool use_system_routing_table = true;

struct ovs_router_entry_nexthop {
    char output_netdev[IFNAMSIZ];
    struct in6_addr gw;
    struct in6_addr src_addr;
    uint32_t id;
    uint32_t flags;
    uint32_t weight;
};

struct ovs_router_group {
    struct ovs_refcount ref_cnt;
    uint32_t id;
    bool has_external_hash_map;
    size_t n_nexthops;
    struct dp_hash_map hash_map;
    struct ovs_router_entry_nexthop *nexthops;
};

struct ovs_router_entry {
    struct cls_rule cr;
    struct in6_addr nw_addr;
    struct in6_addr prefsrc;
    uint8_t plen;
    uint8_t priority;
    bool user;
    uint32_t mark;
    struct ovs_router_group *group;
};

static void rt_entry_delete__(const struct cls_rule *, struct classifier *);
static void ovs_router_rule_add__(uint32_t prio, bool invert, bool user,
                                  uint8_t src_len,
                                  const struct in6_addr *from,
                                  uint32_t lookup_table, bool ipv4);

static struct classifier *
cls_find(uint32_t table)
{
    struct clsmap_node *node;

    CMAP_FOR_EACH_WITH_HASH (node, cmap_node, hash_int(table, 0), &clsmap) {
        if (node->table == table) {
            return &node->cls;
        }
    }

    return NULL;
}

static struct classifier *
cls_create(uint32_t table)
    OVS_REQUIRES(mutex)
{
    struct clsmap_node *node;

    node = xmalloc(sizeof *node);
    classifier_init(&node->cls, NULL);
    node->table = table;
    cmap_insert(&clsmap, &node->cmap_node, hash_int(table, 0));

    return &node->cls;
}

static void
cls_flush(struct classifier *cls, bool flush_all)
    OVS_REQUIRES(mutex)
{
    struct ovs_router_entry *rt;

    classifier_defer(cls);
    CLS_FOR_EACH (rt, cr, cls) {
        if (flush_all || !rt->user) {
            rt_entry_delete__(&rt->cr, cls);
        }
    }
    classifier_publish(cls);
}

static struct ovs_router_entry *
ovs_router_entry_cast(const struct cls_rule *cr)
{
    return cr ? CONTAINER_OF(cr, struct ovs_router_entry, cr) : NULL;
}

/* Disables obtaining routes from the system routing table, for testing
 * purposes. */
void
ovs_router_disable_system_routing_table(void)
{
    use_system_routing_table = false;
}

static bool
ovs_router_lookup_fallback(const struct in6_addr *ip6_dst,
                           char output_netdev[], struct in6_addr *src6,
                           struct in6_addr *gw6)
{
    ovs_be32 src;

    if (!use_system_routing_table
        || !route_table_fallback_lookup(ip6_dst, output_netdev, gw6)) {
        return false;
    }
    if (netdev_get_in4_by_name(output_netdev, (struct in_addr *)&src)) {
        return false;
    }
    if (src6) {
        in6_addr_set_mapped_ipv4(src6, src);
    }
    return true;
}

static const struct ovs_router_entry *
ovs_router_lookup_entry(uint32_t mark, const struct in6_addr *ip6_dst,
                        const struct in6_addr *src)
{
    struct flow flow = {.ipv6_dst = *ip6_dst, .pkt_mark = mark};
    const struct in6_addr *from_src = src;
    const struct cls_rule *cr = NULL;
    struct router_rule *rule;

    if (src && ipv6_addr_is_set(src)) {
        struct flow flow_src = {.ipv6_dst = *src, .pkt_mark = mark};
        struct classifier *cls_local = cls_find(CLS_LOCAL);
        const struct cls_rule *cr_src;

        if (!cls_local) {
            return NULL;
        }

        cr_src = classifier_lookup(cls_local, OVS_VERSION_MAX, &flow_src,
                                   NULL, NULL);
        if (!cr_src) {
            return NULL;
        }
    }

    if (!from_src) {
        if (IN6_IS_ADDR_V4MAPPED(ip6_dst)) {
            from_src = &in6addr_v4mapped_any;
        } else {
            from_src = &in6addr_any;
        }
    }

    PVECTOR_FOR_EACH (rule, &rules) {
        uint8_t plen = rule->ipv4 ? rule->src_prefix + 96 : rule->src_prefix;
        bool matched;

        if ((IN6_IS_ADDR_V4MAPPED(from_src) && !rule->ipv4) ||
            (!IN6_IS_ADDR_V4MAPPED(from_src) && rule->ipv4)) {
            continue;
        }

        matched = (!rule->src_prefix ||
                   ipv6_addr_equals_masked(&rule->from_addr, from_src, plen));

        if (rule->invert) {
            matched = !matched;
        }

        if (matched) {
            struct classifier *cls = cls_find(rule->lookup_table);

            if (!cls) {
                /* A rule can be added before the table is created. */
                continue;
            }
            cr = classifier_lookup(cls, OVS_VERSION_MAX, &flow, NULL,
                                   NULL);
            if (cr) {
                struct ovs_router_entry *p = ovs_router_entry_cast(cr);
                /* Avoid matching mapped IPv4 of a packet against default IPv6
                 * route entry.  Either packet dst is IPv6 or both packet and
                 * route entry dst are mapped IPv4.
                 */
                if (!IN6_IS_ADDR_V4MAPPED(ip6_dst) ||
                    IN6_IS_ADDR_V4MAPPED(&p->nw_addr)) {
                    break;
                }
            }
        }
    }

    return ovs_router_entry_cast(cr);
}

#define OVS_ROUTE_NH_F_DEAD     (1u << 0)
#define OVS_ROUTE_NH_F_LINKDOWN (1u << 4)

static bool
ovs_router_nexthop_is_usable(const struct ovs_router_entry_nexthop *nexthop)
{
    return nexthop &&
           !(nexthop->flags &
             (OVS_ROUTE_NH_F_DEAD | OVS_ROUTE_NH_F_LINKDOWN));
}

static bool
ovs_router_hash_member_is_usable(uint16_t member, void *entry_)
{
    const struct ovs_router_group *group = entry_;

    return member < group->n_nexthops &&
           ovs_router_nexthop_is_usable(&group->nexthops[member]);
}

static const struct ovs_router_entry_nexthop *
ovs_router_select_weighted_nexthop(const struct ovs_router_group *group,
                                   uint32_t flow_hash)
{
    uint64_t total_weight = 0;

    for (size_t i = 0; i < group->n_nexthops; i++) {
        const struct ovs_router_entry_nexthop *nexthop =
            &group->nexthops[i];

        if (ovs_router_nexthop_is_usable(nexthop)) {
            total_weight += MAX(nexthop->weight, 1);
        }
    }
    if (!total_weight) {
        return NULL;
    }

    uint64_t slot = flow_hash % (total_weight);

    for (size_t i = 0; i < group->n_nexthops; i++) {
        const struct ovs_router_entry_nexthop *nexthop =
            &group->nexthops[i];
        uint32_t weight = MAX(nexthop->weight, 1);

        if (!ovs_router_nexthop_is_usable(nexthop)) {
            continue;
        }
        if (slot < weight) {
            return nexthop;
        }
        slot -= weight;
    }
    return NULL;
}

static bool
ovs_router_group_select__(const struct ovs_router_group *group,
                          const struct in6_addr *src, uint32_t flow_hash,
                          struct ovs_router_result *result)
{
    memset(result, 0, sizeof *result);
    const struct ovs_router_entry_nexthop *best = NULL;
    size_t n_usable = 0;

    for (size_t i = 0; i < group->n_nexthops; i++) {
        const struct ovs_router_entry_nexthop *nexthop = &group->nexthops[i];

        if (ovs_router_nexthop_is_usable(nexthop)) {
            n_usable++;
        }
    }

    uint16_t member;
    bool hash_map_selected =
        dp_hash_map_select(&group->hash_map, flow_hash,
                           ovs_router_hash_member_is_usable,
                           CONST_CAST(struct ovs_router_group *, group),
                           &member);
    if (hash_map_selected) {
        best = &group->nexthops[member];
    }
    if (!best) {
        best = ovs_router_select_weighted_nexthop(group, flow_hash);
    }

    if (!best) {
        return false;
    }

    ovs_strlcpy(result->output_netdev, best->output_netdev, IFNAMSIZ);
    result->src = src && ipv6_addr_is_set(src) ? *src : best->src_addr;
    result->gw = best->gw;
    result->id = best->id;
    result->flags = best->flags;
    result->weight = best->weight;
    result->multipath = n_usable > 1;
    result->hash_mask = !result->multipath ? 0
                        : hash_map_selected
                          ? group->hash_map.hash_mask : UINT32_MAX;
    return true;
}

struct ovs_router_group *
ovs_router_lookup_group(uint32_t mark, const struct in6_addr *ip6_dst,
                        const struct in6_addr *src)
{
    const struct ovs_router_entry *entry =
        ovs_router_lookup_entry(mark, ip6_dst, src);

    if (!entry) {
        return NULL;
    }
    ovs_refcount_ref(&entry->group->ref_cnt);
    return entry->group;
}

bool
ovs_router_group_select(const struct ovs_router_group *group,
                        const struct in6_addr *src, uint32_t flow_hash,
                        struct ovs_router_result *result)
{
    return ovs_router_group_select__(group, src, flow_hash, result);
}

bool
ovs_router_group_is_multipath(const struct ovs_router_group *group)
{
    size_t n_usable = 0;

    for (size_t i = 0; i < group->n_nexthops; i++) {
        if (ovs_router_nexthop_is_usable(&group->nexthops[i]) &&
            ++n_usable > 1) {
            return true;
        }
    }
    return false;
}

uint32_t
ovs_router_group_hash_mask(const struct ovs_router_group *group)
{
    uint16_t member;

    if (!ovs_router_group_is_multipath(group)) {
        return 0;
    }
    return dp_hash_map_select(&group->hash_map, 0,
                              ovs_router_hash_member_is_usable,
                              CONST_CAST(struct ovs_router_group *, group),
                              &member)
           ? group->hash_map.hash_mask : UINT32_MAX;
}

bool
ovs_router_lookup_with_hash(uint32_t mark, const struct in6_addr *ip6_dst,
                            const struct in6_addr *src, uint32_t flow_hash,
                            struct ovs_router_result *result)
{
    const struct ovs_router_entry *entry =
        ovs_router_lookup_entry(mark, ip6_dst, src);

    if (entry) {
        return ovs_router_group_select__(entry->group, src, flow_hash,
                                         result);
    }

    memset(result, 0, sizeof *result);
    struct in6_addr fallback_src = src ? *src : in6addr_any;

    if (!ovs_router_lookup_fallback(ip6_dst, result->output_netdev,
                                    &fallback_src, &result->gw)) {
        return false;
    }
    result->src = src && ipv6_addr_is_set(src) ? *src : fallback_src;
    result->weight = 1;
    return true;
}

bool
ovs_router_lookup(uint32_t mark, const struct in6_addr *ip6_dst,
                  char output_netdev[],
                  struct in6_addr *src, struct in6_addr *gw)
{
    struct ovs_router_result result;

    if (!ovs_router_lookup_with_hash(mark, ip6_dst, src, 0, &result)) {
        return false;
    }

    ovs_strlcpy(output_netdev, result.output_netdev, IFNAMSIZ);
    *gw = result.gw;
    if (src && !ipv6_addr_is_set(src)) {
        *src = result.src;
    }
    return true;
}

static void
ovs_router_group_destroy(struct ovs_router_group *group)
{
    dp_hash_map_destroy(&group->hash_map);
    free(group->nexthops);
    free(group);
}

void
ovs_router_group_unref(struct ovs_router_group *group)
{
    if (group && ovs_refcount_unref_relaxed(&group->ref_cnt) == 1) {
        ovs_router_group_destroy(group);
    }
}

static void
rt_entry_free(struct ovs_router_entry *p)
{
    cls_rule_destroy(&p->cr);
    ovs_router_group_unref(p->group);
    free(p);
}

static void
ovs_router_group_build_hash_map(struct ovs_router_group *group)
{
    if (group->n_nexthops < 2) {
        return;
    }

    uint32_t *weights = xmalloc(group->n_nexthops * sizeof *weights);
    for (size_t i = 0; i < group->n_nexthops; i++) {
        weights[i] = MAX(group->nexthops[i].weight, 1);
    }
    /* Very large or highly skewed groups use weighted modulo selection in
     * ovs_router_lookup_with_hash(). */
    dp_hash_map_init(&group->hash_map, weights, group->n_nexthops, 0);
    free(weights);
}

static void rt_init_match(struct match *match, uint32_t mark,
                          const struct in6_addr *ip6_dst,
                          uint8_t plen)
{
    struct in6_addr dst;
    struct in6_addr mask;

    mask = ipv6_create_mask(plen);

    dst = ipv6_addr_bitand(ip6_dst, &mask);
    memset(match, 0, sizeof *match);
    match->flow.ipv6_dst = dst;
    match->wc.masks.ipv6_dst = mask;
    match->wc.masks.pkt_mark = UINT32_MAX;
    match->flow.pkt_mark = mark;
}

static int
verify_prefsrc(const struct in6_addr *ip6_dst,
               const char netdev_name[],
               struct in6_addr *prefsrc)
{
    struct in6_addr *mask, *addr6;
    struct netdev *dev;
    int err, n_in6, i;

    err = netdev_open(netdev_name, NULL, &dev);
    if (err) {
        return err;
    }

    err = netdev_get_addr_list(dev, &addr6, &mask, &n_in6);
    if (err) {
        goto out;
    }

    for (i = 0; i < n_in6; i++) {
        struct in6_addr a1, a2;
        a1 = ipv6_addr_bitand(ip6_dst, &mask[i]);
        a2 = ipv6_addr_bitand(prefsrc, &mask[i]);

        /* Check that the interface has "prefsrc" and
         * it is same broadcast domain with "ip6_dst". */
        if (IN6_ARE_ADDR_EQUAL(prefsrc, &addr6[i]) &&
            IN6_ARE_ADDR_EQUAL(&a1, &a2)) {
            goto out;
        }
    }
    err = ENOENT;

out:
    free(addr6);
    free(mask);
    netdev_close(dev);
    return err;
}

int
ovs_router_get_netdev_source_address(const struct in6_addr *ip6_dst,
                                     const char netdev_name[],
                                     struct in6_addr *psrc)
{
    struct in6_addr *mask, *addr6;
    int err, n_in6, i, max_plen = -1;
    struct netdev *dev;
    bool is_ipv4;

    err = netdev_open(netdev_name, NULL, &dev);
    if (err) {
        return err;
    }

    err = netdev_get_addr_list(dev, &addr6, &mask, &n_in6);
    if (err) {
        goto out;
    }

    is_ipv4 = IN6_IS_ADDR_V4MAPPED(ip6_dst);

    for (i = 0; i < n_in6; i++) {
        struct in6_addr a1, a2;
        int mask_bits;

        if (is_ipv4 && !IN6_IS_ADDR_V4MAPPED(&addr6[i])) {
            continue;
        }

        a1 = ipv6_addr_bitand(ip6_dst, &mask[i]);
        a2 = ipv6_addr_bitand(&addr6[i], &mask[i]);
        mask_bits = bitmap_count1(ALIGNED_CAST(const unsigned long *, &mask[i]), 128);

        if (!memcmp(&a1, &a2, sizeof (a1)) && mask_bits > max_plen) {
            *psrc = addr6[i];
            max_plen = mask_bits;
        }
    }
    if (max_plen == -1) {
        err = ENOENT;
    }
out:
    free(addr6);
    free(mask);
    netdev_close(dev);
    return err;
}

static int
ovs_router_insert__(uint32_t table, uint32_t mark, uint8_t priority,
                    bool user, const struct in6_addr *ip6_dst,
                    uint8_t plen,
                    const struct ovs_router_nexthop *nexthops,
                    size_t n_nexthops,
                    const uint16_t *hash_map, size_t n_hash,
                    uint32_t nexthop_id,
                    const struct in6_addr *ip6_src)
{
    int (*get_src_addr)(const struct in6_addr *ip6_dst,
                        const char output_netdev[],
                        struct in6_addr *prefsrc);
    const struct cls_rule *cr;
    struct ovs_router_entry *p;
    struct ovs_router_group *group;
    struct classifier *cls;
    struct match match;
    uint16_t *input_to_output = NULL;
    int err;

    rt_init_match(&match, mark, ip6_dst, plen);

    if (!n_nexthops) {
        return EINVAL;
    }

    p = xzalloc(sizeof *p);
    group = xzalloc(sizeof *group);
    ovs_refcount_init(&group->ref_cnt);
    group->id = nexthop_id;
    group->has_external_hash_map = hash_map && n_hash;
    group->nexthops = xcalloc(n_nexthops, sizeof *group->nexthops);
    p->group = group;
    if (hash_map && n_hash && n_nexthops < UINT16_MAX) {
        input_to_output = xmalloc(n_nexthops * sizeof *input_to_output);
        for (size_t i = 0; i < n_nexthops; i++) {
            input_to_output[i] = UINT16_MAX;
        }
    }
    p->mark = mark;
    p->nw_addr = match.flow.ipv6_dst;
    p->prefsrc = ip6_src ? *ip6_src : in6addr_any;
    p->plen = plen;
    p->user = user;
    p->priority = priority;

    get_src_addr = ipv6_addr_is_set(ip6_src)
                   ? verify_prefsrc
                   : ovs_router_get_netdev_source_address;

    for (size_t i = 0; i < n_nexthops; i++) {
        const struct ovs_router_nexthop *input = &nexthops[i];
        struct ovs_router_entry_nexthop *output =
            &group->nexthops[group->n_nexthops];

        output->src_addr = ipv6_addr_is_set(ip6_src)
                           ? *ip6_src : in6addr_any;
        err = get_src_addr(ip6_dst, input->output_netdev,
                           &output->src_addr);
        if (err && ipv6_addr_is_set(&input->gw)) {
            err = get_src_addr(&input->gw, input->output_netdev,
                               &output->src_addr);
        }
        if (err) {
            struct ds ds = DS_EMPTY_INITIALIZER;

            ipv6_format_mapped(ip6_dst, &ds);
            VLOG_DBG_RL(&rl, "src addr not available for route %s via %s",
                        ds_cstr(&ds), input->output_netdev);
            ds_destroy(&ds);
            continue;
        }

        ovs_strlcpy(output->output_netdev, input->output_netdev,
                    sizeof output->output_netdev);
        output->gw = input->gw;
        output->id = input->id;
        output->flags = input->flags;
        output->weight = MAX(input->weight, 1);
        if (input_to_output) {
            input_to_output[i] = group->n_nexthops;
        }
        group->n_nexthops++;
    }

    if (!group->n_nexthops) {
        free(input_to_output);
        ovs_router_group_unref(group);
        free(p);
        return ENOENT;
    }
    if (input_to_output) {
        uint16_t *members = xmalloc(n_hash * sizeof *members);

        for (size_t i = 0; i < n_hash; i++) {
            members[i] = hash_map[i] < n_nexthops
                         ? input_to_output[hash_map[i]] : UINT16_MAX;
        }
        dp_hash_map_init_explicit(&group->hash_map, members, n_hash);
        free(members);
    } else {
        ovs_router_group_build_hash_map(group);
    }
    free(input_to_output);
    /* Longest prefix matches first. */
    cls_rule_init(&p->cr, &match, priority);

    ovs_mutex_lock(&mutex);
    cls = cls_find(table);
    if (!cls) {
        cls = cls_create(table);
    }
    cr = classifier_replace(cls, &p->cr, OVS_VERSION_MIN, NULL, 0);
    ovs_mutex_unlock(&mutex);

    for (size_t i = 0; i < group->n_nexthops; i++) {
        tnl_port_map_insert_ipdev(group->nexthops[i].output_netdev);
    }
    if (cr) {
        /* An old rule with the same match was displaced. */
        struct ovs_router_entry *old = ovs_router_entry_cast(cr);

        for (size_t i = 0; i < old->group->n_nexthops; i++) {
            tnl_port_map_unref_ipdev(
                old->group->nexthops[i].output_netdev);
        }
        ovsrcu_postpone(rt_entry_free, old);
    }
    seq_change(tnl_conf_seq);
    return 0;
}

void
ovs_router_insert(uint32_t table, uint32_t mark, const struct in6_addr *ip_dst,
                  uint8_t plen, bool user, const char output_netdev[],
                  const struct in6_addr *gw, const struct in6_addr *prefsrc)
{
    if (use_system_routing_table) {
        struct ovs_router_nexthop nexthop = {
            .gw = *gw,
            .weight = 1,
        };
        ovs_strlcpy(nexthop.output_netdev, output_netdev,
                    sizeof nexthop.output_netdev);
        ovs_router_insert__(table, mark, plen, user, ip_dst, plen,
                            &nexthop, 1, NULL, 0, 0, prefsrc);
    }
}

void
ovs_router_insert_nexthops(uint32_t table, uint32_t mark,
                           const struct in6_addr *ip_dst, uint8_t plen,
                           bool user,
                           const struct ovs_router_nexthop *nexthops,
                           size_t n_nexthops,
                           const uint16_t *hash_map, size_t n_hash,
                           uint32_t nexthop_id,
                           const struct in6_addr *prefsrc)
{
    if (use_system_routing_table) {
        ovs_router_insert__(table, mark, plen, user, ip_dst, plen,
                            nexthops, n_nexthops, hash_map, n_hash,
                            nexthop_id, prefsrc);
    }
}

/* The same as 'ovs_router_insert', but it adds the route even if updates
 * from the system routing table are disabled.  Used for unit tests. */
void
ovs_router_force_insert(uint32_t table, uint32_t mark,
                        const struct in6_addr *ip_dst,
                        uint8_t plen, const char output_netdev[],
                        const struct in6_addr *gw,
                        const struct in6_addr *prefsrc)
{
    struct ovs_router_nexthop nexthop = {
        .gw = *gw,
        .weight = 1,
    };
    ovs_strlcpy(nexthop.output_netdev, output_netdev,
                sizeof nexthop.output_netdev);
    ovs_router_insert__(table, mark, plen, false, ip_dst, plen, &nexthop, 1,
                        NULL, 0, 0, prefsrc);
}

static void
rt_entry_delete__(const struct cls_rule *cr, struct classifier *cls)
{
    struct ovs_router_entry *p = ovs_router_entry_cast(cr);

    for (size_t i = 0; i < p->group->n_nexthops; i++) {
        tnl_port_map_unref_ipdev(
            p->group->nexthops[i].output_netdev);
    }
    classifier_remove_assert(cls, cr);
    ovsrcu_postpone(rt_entry_free, ovs_router_entry_cast(cr));
}

static bool
rt_entry_delete(struct classifier *cls, uint32_t mark, uint8_t priority,
                const struct in6_addr *ip6_dst, uint8_t plen)
{
    struct classifier *cls_main = cls_find(CLS_MAIN);
    const struct cls_rule *cr;
    struct cls_rule rule;
    struct match match;
    bool res = false;

    if (!cls_main) {
        return false;
    }

    rt_init_match(&match, mark, ip6_dst, plen);

    cls_rule_init(&rule, &match, priority);

    /* Find the exact rule. */
    cr = classifier_find_rule_exactly(cls, &rule, OVS_VERSION_MAX);
    if (cr) {
        ovs_mutex_lock(&mutex);
        rt_entry_delete__(cr, cls);
        ovs_mutex_unlock(&mutex);

        res = true;
    }

    cls_rule_destroy(&rule);
    return res;
}

static bool
scan_ipv6_route(const char *s, struct in6_addr *addr, unsigned int *plen)
{
    char *error = ipv6_parse_cidr(s, addr, plen);
    if (error) {
        free(error);
        return false;
    }
    return true;
}

static bool
scan_ipv4_route(const char *s, ovs_be32 *addr, unsigned int *plen)
{
    char *error = ip_parse_cidr(s, addr, plen);
    if (error) {
        free(error);
        return false;
    }
    return true;
}

static int
ovs_router_insert_nhid(uint32_t table, uint32_t mark, uint8_t priority,
                       const struct in6_addr *ip6, uint8_t plen,
                       uint32_t nhid, const struct in6_addr *src6)
{
    struct route_data rd;
    struct route_data_nexthop *rdnh;
    size_t n_nexthops = 0;

    memset(&rd, 0, sizeof rd);
    ovs_list_init(&rd.nexthops);
    if (!nexthop_table_resolve(nhid, &rd)) {
        route_data_destroy(&rd);
        return ENOENT;
    }

    LIST_FOR_EACH (rdnh, nexthop_node, &rd.nexthops) {
        n_nexthops++;
    }
    struct ovs_router_nexthop *nexthops =
        xcalloc(n_nexthops, sizeof *nexthops);
    size_t i = 0;

    LIST_FOR_EACH (rdnh, nexthop_node, &rd.nexthops) {
        ovs_strlcpy(nexthops[i].output_netdev, rdnh->ifname,
                    sizeof nexthops[i].output_netdev);
        nexthops[i].gw = rdnh->addr;
        nexthops[i].id = rdnh->nh_id;
        nexthops[i].flags = rdnh->flags;
        nexthops[i].weight = rdnh->weight;
        i++;
    }

    int err = ovs_router_insert__(table, mark, priority, true, ip6, plen,
                                  nexthops, n_nexthops, rd.nh_hash_map,
                                  rd.n_nh_hash, nhid, src6);
    free(nexthops);
    route_data_destroy(&rd);
    return err;
}

struct ovs_router_nhid_route {
    uint32_t table;
    uint32_t mark;
    uint32_t nhid;
    struct in6_addr nw_addr;
    struct in6_addr prefsrc;
    uint8_t plen;
    uint8_t priority;
};

void
ovs_router_nexthop_table_change(void)
{
    struct ovs_router_nhid_route *routes = NULL;
    size_t allocated_routes = 0;
    size_t n_routes = 0;
    struct clsmap_node *node;

    CMAP_FOR_EACH (node, cmap_node, &clsmap) {
        struct ovs_router_entry *rt;

        CLS_FOR_EACH (rt, cr, &node->cls) {
            if (!rt->user || !rt->group->id) {
                continue;
            }
            if (n_routes == allocated_routes) {
                routes = x2nrealloc(routes, &allocated_routes,
                                    sizeof *routes);
            }

            routes[n_routes++] = (struct ovs_router_nhid_route) {
                .table = node->table,
                .mark = rt->mark,
                .nhid = rt->group->id,
                .nw_addr = rt->nw_addr,
                .prefsrc = rt->prefsrc,
                .plen = rt->plen,
                .priority = rt->priority,
            };
        }
    }

    for (size_t i = 0; i < n_routes; i++) {
        const struct ovs_router_nhid_route *route = &routes[i];

        if (ovs_router_insert_nhid(route->table, route->mark,
                                   route->priority, &route->nw_addr,
                                   route->plen, route->nhid,
                                   &route->prefsrc)) {
            struct classifier *cls = cls_find(route->table);

            if (cls && rt_entry_delete(cls, route->mark, route->priority,
                                       &route->nw_addr, route->plen)) {
                seq_change(tnl_conf_seq);
            }
        }
    }
    free(routes);
}

static void
ovs_router_add(struct unixctl_conn *conn, int argc,
              const char *argv[], void *aux OVS_UNUSED)
{
    struct in6_addr src6 = in6addr_any;
    char src6_s[IPV6_SCAN_LEN + 1];
    uint32_t table = CLS_MAIN;
    struct in6_addr ip6;
    uint32_t mark = 0;
    unsigned int plen;
    ovs_be32 src = 0;
    bool is_ipv6;
    ovs_be32 ip;
    int err = 0;

    if (scan_ipv4_route(argv[1], &ip, &plen)) {
        in6_addr_set_mapped_ipv4(&ip6, ip);
        plen += 96;
        is_ipv6 = false;
    } else if (scan_ipv6_route(argv[1], &ip6, &plen)) {
        is_ipv6 = true;
    } else {
        unixctl_command_reply_error(conn,
                                    "Invalid 'ip/plen' parameter");
        return;
    }

    if (!strcmp(argv[2], "nhid")) {
        unsigned int nhid;

        if (argc < 4 || !str_to_uint(argv[3], 10, &nhid) || !nhid) {
            unixctl_command_reply_error(conn, "Invalid nexthop group ID");
            return;
        }
        for (int i = 4; i < argc; i++) {
            if (ovs_scan(argv[i], "pkt_mark=%"SCNu32, &mark)) {
                continue;
            }
            if (is_ipv6 &&
                ovs_scan(argv[i], "src="IPV6_SCAN_FMT, src6_s) &&
                ipv6_parse(src6_s, &src6)) {
                continue;
            }
            if (!is_ipv6 &&
                ovs_scan(argv[i], "src="IP_SCAN_FMT, IP_SCAN_ARGS(&src))) {
                continue;
            }
            if (ovs_scan(argv[i], "table=%"SCNu32, &table)) {
                continue;
            }
            unixctl_command_reply_error(conn, "Invalid nhid parameter");
            return;
        }
        if (src) {
            in6_addr_set_mapped_ipv4(&src6, src);
        }
        err = ovs_router_insert_nhid(table, mark, plen + 32, &ip6, plen,
                                     nhid, &src6);
    } else {
        struct in6_addr gw6 = in6addr_any;
        ovs_be32 gw = 0;

        /* Parse the original single-nexthop syntax. */
        for (int i = 3; i < argc; i++) {
            if (ovs_scan(argv[i], "pkt_mark=%"SCNu32, &mark)) {
                continue;
            }

            if (is_ipv6) {
                if (ovs_scan(argv[i], "src="IPV6_SCAN_FMT, src6_s) &&
                    ipv6_parse(src6_s, &src6)) {
                    continue;
                }
                if (ipv6_parse(argv[i], &gw6)) {
                    continue;
                }
            } else {
                if (ovs_scan(argv[i], "src="IP_SCAN_FMT,
                             IP_SCAN_ARGS(&src))) {
                    continue;
                }
                if (ip_parse(argv[i], &gw)) {
                    continue;
                }
            }

            if (ovs_scan(argv[i], "table=%"SCNu32, &table)) {
                continue;
            } else if (ovs_scan(argv[i], "table=")) {
                unixctl_command_reply_error(conn, "Invalid table format");
                return;
            }

            unixctl_command_reply_error(
                conn, "Invalid pkt_mark, IP gateway or src_ip");
            return;
        }

        if (gw) {
            in6_addr_set_mapped_ipv4(&gw6, gw);
        }
        if (src) {
            in6_addr_set_mapped_ipv4(&src6, src);
        }

        struct ovs_router_nexthop nexthop = {
            .gw = gw6,
            .weight = 1,
        };

        ovs_strlcpy(nexthop.output_netdev, argv[2],
                    sizeof nexthop.output_netdev);
        err = ovs_router_insert__(table, mark, plen + 32, true, &ip6, plen,
                                  &nexthop, 1, NULL, 0, 0, &src6);
    }

    if (err) {
        unixctl_command_reply_error(conn, "Error while inserting route.");
    } else {
        unixctl_command_reply(conn, "OK");
    }
}

static void
ovs_router_del(struct unixctl_conn *conn, int argc OVS_UNUSED,
              const char *argv[], void *aux OVS_UNUSED)
{
    struct classifier *cls = cls_find(CLS_MAIN);
    struct in6_addr ip6;
    uint32_t mark = 0;
    unsigned int plen;
    uint32_t table;
    ovs_be32 ip;
    int arg;

    if (scan_ipv4_route(argv[1], &ip, &plen)) {
        in6_addr_set_mapped_ipv4(&ip6, ip);
        plen += 96;
    } else if (!scan_ipv6_route(argv[1], &ip6, &plen)) {
        unixctl_command_reply_error(conn, "Invalid parameters");
        return;
    }

    /* Parse optional parameters. */
    for (arg = 2; arg < argc; arg++) {
        if (ovs_scan(argv[arg], "pkt_mark=%"SCNu32, &mark)) {
            continue;
        }

        if (ovs_scan(argv[arg], "table=%"SCNu32, &table)) {
            cls = cls_find(table);
            if (!cls) {
                struct ds ds = DS_EMPTY_INITIALIZER;

                ds_put_format(&ds, "Table %s not found", argv[arg]);
                unixctl_command_reply_error(conn, ds_cstr_ro(&ds));
                ds_destroy(&ds);
                return;
            }
            continue;
        } else if (ovs_scan(argv[arg], "table=")) {
            unixctl_command_reply_error(conn, "Invalid table format");
            return;
        }

        unixctl_command_reply_error(conn, "Invalid pkt_mark or table");
        return;
    }

    if (!cls) {
        unixctl_command_reply_error(conn, "Table not found");
        return;
    }

    if (rt_entry_delete(cls, mark, plen + 32, &ip6, plen)) {
        unixctl_command_reply(conn, "OK");
        seq_change(tnl_conf_seq);
    } else {
        unixctl_command_reply_error(conn, "Not found");
    }
}

static void
ovs_router_show_json(struct json *json_routes, const struct classifier *cls,
                     uint32_t table)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct ovs_router_entry *rt;

    if (!cls) {
        return;
    }

    CLS_FOR_EACH (rt, cr, cls) {
        const struct ovs_router_group *group = rt->group;
        uint8_t plen = rt->plen;
        struct json *json, *json_nexthops;

        json = json_object_create();
        json_nexthops = json_array_create_empty();

        if (IN6_IS_ADDR_V4MAPPED(&rt->nw_addr)) {
            plen -= 96;
        }

        json_object_put(json, "table", json_integer_create(table));
        json_object_put(json, "user", json_boolean_create(rt->user));
        json_object_put(json, "local",
                        json_boolean_create(table == CLS_LOCAL && !rt->user));
        json_object_put(json, "prefix", json_integer_create(plen));

        ipv6_format_mapped(&rt->nw_addr, &ds);
        json_object_put_string(json, "dst", ds_cstr_ro(&ds));
        ds_clear(&ds);

        ipv6_format_mapped(&group->nexthops[0].src_addr, &ds);
        json_object_put_string(json, "prefsrc", ds_cstr_ro(&ds));
        ds_clear(&ds);

        if (rt->mark) {
            json_object_put(json, "mark", json_integer_create(rt->mark));
        }
        if (group->id) {
            json_object_put(json, "nexthop_id",
                            json_integer_create(group->id));
        }

        for (size_t i = 0; i < group->n_nexthops; i++) {
            const struct ovs_router_entry_nexthop *nexthop =
                &group->nexthops[i];
            struct json *nh = json_object_create();

            json_object_put_string(nh, "dev", nexthop->output_netdev);
            if (ipv6_addr_is_set(&nexthop->gw)) {
                ipv6_format_mapped(&nexthop->gw, &ds);
                json_object_put_string(nh, "gateway", ds_cstr_ro(&ds));
                ds_clear(&ds);
            }
            if (group->n_nexthops > 1) {
                ipv6_format_mapped(&nexthop->src_addr, &ds);
                json_object_put_string(nh, "prefsrc", ds_cstr_ro(&ds));
                ds_clear(&ds);
                json_object_put(nh, "weight",
                                json_integer_create(nexthop->weight));
            }
            if (nexthop->id) {
                json_object_put(nh, "id",
                                json_integer_create(nexthop->id));
            }
            if (nexthop->flags) {
                json_object_put(nh, "flags",
                                json_integer_create(nexthop->flags));
            }
            json_array_add(json_nexthops, nh);
        }

        json_object_put(json, "nexthops", json_nexthops);
        json_array_add(json_routes, json);
    }

    ds_destroy(&ds);
}

static bool
is_standard_table(uint32_t table_id)
{
    return table_id == CLS_DEFAULT
           || table_id == CLS_MAIN
           || table_id == CLS_LOCAL;
}

static void
ovs_router_show_text(struct ds *ds, const struct classifier *cls,
                     uint32_t table, bool show_header)
{
    struct ovs_router_entry *rt;

    if (show_header) {
        if (is_standard_table(table)) {
            ds_put_format(ds, "Route Table:\n");
        } else {
            ds_put_format(ds, "Route Table #%"PRIu32":\n", table);
        }
    }

    if (!cls) {
        return;
    }

    CLS_FOR_EACH (rt, cr, cls) {
        const struct ovs_router_group *group = rt->group;
        uint8_t plen;
        if (rt->user) {
            ds_put_format(ds, "User: ");
        } else {
            ds_put_format(ds, "Cached: ");
        }
        ipv6_format_mapped(&rt->nw_addr, ds);
        plen = rt->plen;
        if (IN6_IS_ADDR_V4MAPPED(&rt->nw_addr)) {
            plen -= 96;
        }
        ds_put_format(ds, "/%"PRIu8, plen);
        if (rt->mark) {
            ds_put_format(ds, " MARK %"PRIu32, rt->mark);
        }
        if (group->id) {
            ds_put_format(ds, " nhid %"PRIu32, group->id);
        }

        for (size_t i = 0; i < group->n_nexthops; i++) {
            const struct ovs_router_entry_nexthop *nexthop =
                &group->nexthops[i];

            if (group->n_nexthops > 1) {
                ds_put_format(ds, " nexthop");
            }
            ds_put_format(ds, " dev %s", nexthop->output_netdev);
            if (ipv6_addr_is_set(&nexthop->gw)) {
                ds_put_format(ds, " GW ");
                ipv6_format_mapped(&nexthop->gw, ds);
            }
            ds_put_format(ds, " SRC ");
            ipv6_format_mapped(&nexthop->src_addr, ds);
            if (group->n_nexthops > 1) {
                ds_put_format(ds, " weight %"PRIu32, nexthop->weight);
            }
            if (nexthop->id) {
                ds_put_format(ds, " id %"PRIu32, nexthop->id);
            }
            if (nexthop->flags) {
                ds_put_format(ds, " flags 0x%"PRIx32, nexthop->flags);
            }
        }
        if (table == CLS_LOCAL && !rt->user) {
            ds_put_format(ds, " local");
        }
        if (!is_standard_table(table) && !show_header) {
            ds_put_format(ds, " table %"PRIu32, table);
        }
        ds_put_format(ds, "\n");
    }
}

static void
ovs_router_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
               const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct classifier *cls = NULL;
    uint32_t table = 0;

    if (argc > 1) {
        if (!strcmp(argv[1], "table=all")) {
            table = CLS_ALL;
        } else if (!ovs_scan(argv[1], "table=%"SCNu32, &table)) {
            unixctl_command_reply_error(conn, "Invalid table format");
            return;
        }
    }

    if (table && table != CLS_ALL) {
        cls = cls_find(table);
        if (!cls) {
            ds_put_format(&ds, "Table '%s' not found", argv[1]);
            unixctl_command_reply_error(conn, ds_cstr_ro(&ds));
            ds_destroy(&ds);
            return;
        }
    }

    if (unixctl_command_get_output_format(conn) == UNIXCTL_OUTPUT_FMT_JSON) {
        struct json *routes = NULL;

        routes = json_array_create_empty();

        if (table == CLS_ALL) {
            struct clsmap_node *node;

            CMAP_FOR_EACH (node, cmap_node, &clsmap) {
                ovs_router_show_json(routes, &node->cls, node->table);
            }
            ovs_router_show_json(routes, cls_find(CLS_MAIN), CLS_MAIN);
        } else if (!table) {
            ovs_router_show_json(routes, cls_find(CLS_LOCAL), CLS_LOCAL);
            ovs_router_show_json(routes, cls_find(CLS_MAIN), CLS_MAIN);
            ovs_router_show_json(routes, cls_find(CLS_DEFAULT), CLS_DEFAULT);
        } else {
            ovs_router_show_json(routes, cls, table);
        }

        unixctl_command_reply_json(conn, routes);
    } else {
        if (table == CLS_ALL) {
            struct clsmap_node *node;

            CMAP_FOR_EACH (node, cmap_node, &clsmap) {
                ovs_router_show_text(&ds, &node->cls, node->table, false);
            }
        } else if (!table) {
            ovs_router_show_text(&ds, cls_find(CLS_LOCAL), CLS_LOCAL, true);
            ovs_router_show_text(&ds, cls_find(CLS_MAIN), CLS_MAIN, false);
            ovs_router_show_text(&ds, cls_find(CLS_DEFAULT), CLS_DEFAULT,
                                 false);
        } else {
            ovs_router_show_text(&ds, cls, table, true);
        }
        unixctl_command_reply(conn, ds_cstr(&ds));
        ds_destroy(&ds);
    }
}

static void
ovs_router_rules_show_json(struct json *rule_entries, bool ipv6)
{
    struct router_rule *rule;
    struct ds ds;

    PVECTOR_FOR_EACH (rule, &rules) {
        struct json *entry;

        if (rule->ipv4 == ipv6) {
            continue;
        }
        entry = json_object_create();

        json_object_put(entry, "priority", json_integer_create(rule->prio));
        json_object_put(entry, "user", json_boolean_create(rule->user));
        json_object_put(entry, "invert", json_boolean_create(rule->invert));
        json_object_put(entry, "ipv4", json_boolean_create(rule->ipv4));
        json_object_put(entry, "src-prefix",
                        json_integer_create(rule->src_prefix));
        json_object_put(entry, "lookup",
                        json_integer_create(rule->lookup_table));

        if (rule->src_prefix) {
            ds_init(&ds);
            ipv6_format_mapped(&rule->from_addr, &ds);
            json_object_put_string(entry, "from", ds_cstr_ro(&ds));
            ds_destroy(&ds);
        } else {
            json_object_put_string(entry, "from", "all");
        }

        json_array_add(rule_entries, entry);
    }
}

static char *
standard_table_name(uint32_t table)
{
    switch (table) {
    case CLS_DEFAULT:
        return "default";
    case CLS_MAIN:
        return "main";
    case CLS_LOCAL:
        return "local";
    }

    return NULL;
}

static void
ovs_router_rules_show_text(struct ds *ds, bool ipv6)
{
    struct router_rule *rule;

    PVECTOR_FOR_EACH (rule, &rules) {
        if (rule->ipv4 == ipv6) {
            continue;
        }
        if (rule->user) {
            ds_put_format(ds, "User: ");
        } else {
            ds_put_format(ds, "Cached: ");
        }
        ds_put_format(ds, "%"PRIu32": ", rule->prio);
        if (rule->invert) {
            ds_put_format(ds, "not ");
        }
        ds_put_format(ds, "from ");
        if (rule->src_prefix) {
            ipv6_format_mapped(&rule->from_addr, ds);
            if (!((IN6_IS_ADDR_V4MAPPED(&rule->from_addr) &&
                   rule->src_prefix == 32) || rule->src_prefix == 128)) {
                ds_put_format(ds, "/%"PRIu8" ", rule->src_prefix);
            }
        } else {
            ds_put_cstr(ds, "all");
        }
        ds_put_format(ds, " ");
        if (is_standard_table(rule->lookup_table)) {
            ds_put_format(ds, "lookup %s\n",
                          standard_table_name(rule->lookup_table));
        } else {
            ds_put_format(ds, "lookup %"PRIu32"\n", rule->lookup_table);
        }
    }
}

static void
ovs_router_rules_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                      const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    bool ipv6 = false;

    if (argc > 1 && ovs_scan(argv[1], "-6")) {
        ipv6 = true;
    }

    if (unixctl_command_get_output_format(conn) == UNIXCTL_OUTPUT_FMT_JSON) {
        struct json *entries = json_array_create_empty();

        ovs_router_rules_show_json(entries, ipv6);
        unixctl_command_reply_json(conn, entries);
    } else {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ovs_router_rules_show_text(&ds, ipv6);
        unixctl_command_reply(conn, ds_cstr(&ds));
        ds_destroy(&ds);
    }
}

static void
ovs_router_rule_add_cmd(struct unixctl_conn *conn, int argc OVS_UNUSED,
                        const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    unsigned int src_len = 0;
    struct in6_addr from;
    bool invert = false;
    bool ipv4 = true;
    uint32_t prio = 0;
    uint32_t table;
    ovs_be32 ip;
    int i = 1;

    if (ovs_scan(argv[i], "-6")) {
        ipv4 = false;
        i++;
    }
    if (ovs_scan(argv[i], "not")) {
        invert = true;
        i++;
    }

    if (ovs_scan(argv[i], "from=all")) {
        from = in6addr_any;
    } else if (ovs_scan(argv[i], "from=")) {
        const char *arg = &argv[i][strlen("from=")];

        if (scan_ipv4_route(arg, &ip, &src_len)) {
            in6_addr_set_mapped_ipv4(&from, ip);
            ipv4 = true;
        } else if (scan_ipv6_route(arg, &from, &src_len)) {
            ipv4 = false;
        } else {
            unixctl_command_reply_error(conn, "Invalid from=ip/plen");
            return;
        }
    } else {
        unixctl_command_reply_error(conn, "Invalid 'from' parameter");
        return;
    }
    if (argc <= ++i) {
        unixctl_command_reply_error(conn, "Not enough arguments");
        return;
    }

    if (ovs_scan(argv[i], "prio=%"SCNu32, &prio)) {
        if (argc <= ++i) {
            unixctl_command_reply_error(conn, "Not enough arguments");
            return;
        }
    }

    if (ovs_scan(argv[i], "table=local")) {
        table = CLS_LOCAL;
    } else if (ovs_scan(argv[i], "table=main")) {
        table = CLS_MAIN;
    } else if (ovs_scan(argv[i], "table=default")) {
        table = CLS_DEFAULT;
    } else if (!ovs_scan(argv[i], "table=%"SCNu32, &table)) {
        unixctl_command_reply_error(conn, "Invalid 'table' format");
        return;
    }

    ovs_mutex_lock(&mutex);
    if (!prio) {
        struct router_rule *rule;
        uint32_t prev_prio = 0;

        PVECTOR_FOR_EACH (rule, &rules) {
            if (rule->prio && (!prio || (rule->prio - prev_prio > 1))) {
                prio = rule->prio - 1;
            }
            prev_prio = rule->prio;
        }
    }
    ovs_router_rule_add__(prio, invert, true, src_len, &from, table, ipv4);
    ovs_mutex_unlock(&mutex);

    unixctl_command_reply(conn, "OK");
}

static void
ovs_router_rule_del_cmd(struct unixctl_conn *conn, int argc OVS_UNUSED,
                        const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    unsigned int src_len = 0;
    struct in6_addr from;
    bool invert = false;
    bool ipv4 = true;
    uint32_t prio = 0;
    uint32_t table;
    ovs_be32 ip;
    int i = 1;
    int err;

    if (ovs_scan(argv[i], "-6")) {
        ipv4 = false;
        i++;
    }
    if (ovs_scan(argv[i], "not")) {
        invert = true;
        i++;
    }

    if (ovs_scan(argv[i], "from=all")) {
        from = in6addr_any;
    } else if (ovs_scan(argv[i], "from=")) {
        const char *arg = &argv[i][strlen("from=")];

        if (scan_ipv4_route(arg, &ip, &src_len)) {
            in6_addr_set_mapped_ipv4(&from, ip);
            ipv4 = true;
        } else if (scan_ipv6_route(arg, &from, &src_len)) {
            ipv4 = false;
        } else {
            unixctl_command_reply_error(conn, "Invalid from=ip/plen");
            return;
        }
    } else {
        unixctl_command_reply_error(conn, "Invalid 'from' parameter");
        return;
    }
    if (argc <= ++i) {
        unixctl_command_reply_error(conn, "Not enough arguments");
        return;
    }

    if (ovs_scan(argv[i], "prio=%"SCNu32, &prio)) {
        if (argc <= ++i) {
            unixctl_command_reply_error(conn, "Not enough arguments");
            return;
        }
    }

    if (ovs_scan(argv[i], "table=local")) {
        table = CLS_LOCAL;
    } else if (ovs_scan(argv[i], "table=main")) {
        table = CLS_MAIN;
    } else if (ovs_scan(argv[i], "table=default")) {
        table = CLS_DEFAULT;
    } else if (!ovs_scan(argv[i], "table=%"SCNu32, &table)) {
        unixctl_command_reply_error(conn, "Invalid 'table' format");
        return;
    }

    ovs_mutex_lock(&mutex);
    err = ovs_router_rule_del(prio, invert, src_len, &from, table, ipv4);
    ovs_mutex_unlock(&mutex);

    if (err) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_format(&ds, "Failed to delete router rule: %d (%s)", err,
                      ovs_strerror(err));
        unixctl_command_reply_error(conn, ds_cstr_ro(&ds));
        ds_destroy(&ds);
    } else {
        unixctl_command_reply(conn, "OK");
    }
}

static void
ovs_router_lookup_cmd(struct unixctl_conn *conn, int argc,
                      const char *argv[], void *aux OVS_UNUSED)
{
    struct in6_addr src6 = in6addr_any;
    char src6_s[IPV6_SCAN_LEN + 1];
    struct in6_addr ip6;
    unsigned int plen;
    uint32_t mark = 0;
    ovs_be32 src4 = 0;
    bool is_ipv6;
    ovs_be32 ip;
    int arg;

    if (scan_ipv4_route(argv[1], &ip, &plen) && plen == 32) {
        in6_addr_set_mapped_ipv4(&ip6, ip);
        is_ipv6 = false;
    } else if (scan_ipv6_route(argv[1], &ip6, &plen) && plen == 128) {
        is_ipv6 = true;
    } else {
        unixctl_command_reply_error(conn, "Invalid 'ip/plen' parameter");
        return;
    }

    /* Parse optional parameters. */
    for (arg = 2; arg < argc; arg++) {
        if (ovs_scan(argv[arg], "pkt_mark=%"SCNu32, &mark)) {
            continue;
        }

        if (is_ipv6) {
            if (ovs_scan(argv[arg], "src="IPV6_SCAN_FMT, src6_s) &&
                ipv6_parse(src6_s, &src6)) {
                continue;
            }
        } else {
            if (ovs_scan(argv[arg], "src="IP_SCAN_FMT,
                         IP_SCAN_ARGS(&src4))) {
                continue;
            }
        }

        unixctl_command_reply_error(conn, "Invalid pkt_mark or src");
        return;
    }

    if (src4) {
        in6_addr_set_mapped_ipv4(&src6, src4);
    }

    const struct ovs_router_entry *entry =
        ovs_router_lookup_entry(mark, &ip6, &src6);

    if (entry) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        const struct ovs_router_group *group = entry->group;

        if (group->id) {
            ds_put_format(&ds, "nhid %"PRIu32"\n", group->id);
        }
        if (group->n_nexthops == 1) {
            const struct ovs_router_entry_nexthop *nexthop =
                &group->nexthops[0];
            const struct in6_addr *selected_src = ipv6_addr_is_set(&src6)
                                                 ? &src6
                                                 : &nexthop->src_addr;

            ds_put_cstr(&ds, "src ");
            ipv6_format_mapped(selected_src, &ds);
            ds_put_cstr(&ds, "\ngateway ");
            ipv6_format_mapped(&nexthop->gw, &ds);
            ds_put_format(&ds, "\ndev %s\n", nexthop->output_netdev);
        } else {
            for (size_t nh = 0; nh < group->n_nexthops; nh++) {
                const struct ovs_router_entry_nexthop *nexthop =
                    &group->nexthops[nh];
                const struct in6_addr *selected_src =
                    ipv6_addr_is_set(&src6) ? &src6 : &nexthop->src_addr;

                ds_put_format(&ds, "nexthop dev %s",
                              nexthop->output_netdev);
                if (ipv6_addr_is_set(&nexthop->gw)) {
                    ds_put_cstr(&ds, " gateway ");
                    ipv6_format_mapped(&nexthop->gw, &ds);
                }
                ds_put_cstr(&ds, " src ");
                ipv6_format_mapped(selected_src, &ds);
                ds_put_format(&ds, " weight %"PRIu32, nexthop->weight);
                if (nexthop->id) {
                    ds_put_format(&ds, " id %"PRIu32, nexthop->id);
                }
                if (nexthop->flags) {
                    ds_put_format(&ds, " flags 0x%"PRIx32,
                                  nexthop->flags);
                }
                ds_put_char(&ds, '\n');
            }
        }
        if (group->has_external_hash_map) {
            ds_put_cstr(&ds, "buckets");
            for (size_t i = 0; i < group->hash_map.n_hash; i++) {
                uint16_t index = group->hash_map.members[i];

                if (index == UINT16_MAX) {
                    ds_put_cstr(&ds, " unassigned");
                } else if (group->nexthops[index].id) {
                    ds_put_format(&ds, " %"PRIu32,
                                  group->nexthops[index].id);
                } else {
                    ds_put_format(&ds, " index:%"PRIu16, index);
                }
            }
            ds_put_char(&ds, '\n');
        }
        unixctl_command_reply(conn, ds_cstr(&ds));
        ds_destroy(&ds);
        return;
    }

    struct ovs_router_result result;

    if (!ovs_router_lookup_with_hash(mark, &ip6, &src6, 0, &result)) {
        unixctl_command_reply_error(conn, "Not found");
        return;
    }

    struct ds ds = DS_EMPTY_INITIALIZER;

    ds_put_cstr(&ds, "src ");
    ipv6_format_mapped(&result.src, &ds);
    ds_put_cstr(&ds, "\ngateway ");
    ipv6_format_mapped(&result.gw, &ds);
    ds_put_format(&ds, "\ndev %s\n", result.output_netdev);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
clsmap_node_destroy_cb(struct clsmap_node *node)
{
    classifier_destroy(&node->cls);
    ovsrcu_postpone(free, node);
}

static void
ovs_router_flush_protected(bool flush_all)
    OVS_REQUIRES(mutex)
{
    struct clsmap_node *node;

    CMAP_FOR_EACH (node, cmap_node, &clsmap) {
        cls_flush(&node->cls, flush_all);
        if (!node->cls.n_rules) {
            cmap_remove(&clsmap, &node->cmap_node, hash_int(node->table, 0));
            ovsrcu_postpone(clsmap_node_destroy_cb, node);
        }
    }
    seq_change(tnl_conf_seq);
}

void
ovs_router_flush(bool flush_all)
{
    ovs_mutex_lock(&mutex);
    ovs_router_flush_protected(flush_all);
    ovs_mutex_unlock(&mutex);
}

static void
init_standard_rules(void)
    OVS_REQUIRES(mutex)
{
    /* Add default rules using same priorities as Linux kernel does. */
    ovs_router_rule_add__(0, false, false, 0,
                          &in6addr_v4mapped_any, CLS_LOCAL, true);
    ovs_router_rule_add__(0x7FFE, false, false, 0,
                          &in6addr_v4mapped_any, CLS_MAIN, true);
    ovs_router_rule_add__(0x7FFF, false, false, 0,
                          &in6addr_v4mapped_any, CLS_DEFAULT, true);

    ovs_router_rule_add__(0, false, false, 0,
                          &in6addr_any, CLS_LOCAL, false);
    ovs_router_rule_add__(0x7FFE, false, false, 0,
                          &in6addr_any, CLS_MAIN, false);
}

static void
rule_destroy_cb(struct router_rule *rule)
{
    ovsrcu_postpone(free, rule);
}

static void
ovs_router_rules_flush_protected(bool flush_all)
{
    struct router_rule *rule;

    PVECTOR_FOR_EACH (rule, &rules) {
        if (flush_all || !rule->user) {
            pvector_remove(&rules, rule);
            ovsrcu_postpone(rule_destroy_cb, rule);
        }
    }
    pvector_publish(&rules);
}

void
ovs_router_rules_flush(bool flush_all)
{
    ovs_mutex_lock(&mutex);
    ovs_router_rules_flush_protected(flush_all);
    if (!flush_all) {
        init_standard_rules();
    }
    ovs_mutex_unlock(&mutex);
}

static void
ovs_router_flush_handler(void *aux OVS_UNUSED)
{
    ovs_mutex_lock(&mutex);
    ovs_router_rules_flush_protected(true);
    ovs_router_flush_protected(true);
    pvector_destroy(&rules);
    ovs_assert(cmap_is_empty(&clsmap));
    cmap_destroy(&clsmap);
    cmap_init(&clsmap);
    ovs_mutex_unlock(&mutex);
}

bool
ovs_router_is_referenced(uint32_t table)
{
    struct router_rule *rule;

    PVECTOR_FOR_EACH (rule, &rules) {
        if (rule->lookup_table == table) {
            return true;
        }
    }
    return false;
}

static int
rule_pvec_prio(uint32_t prio)
{
    /* Invert the priority of a pvector entry to reverse the default sorting
     * order (descending) to maintain the standard rules semantic where 0 is
     * the highest priority and UINT_MAX is the lowest.  The mapping is the
     * following:
     *
     *     0        -> INT_MAX
     *     INT_MAX  -> 0
     *     UINT_MAX -> INT_MIN
     */
    if (prio <= INT_MAX) {
        return -(INT_MIN + (int) prio + 1);
    } else {
        return -((int) (prio - INT_MAX - 1)) - 1;
    }
}

static void
ovs_router_rule_add__(uint32_t prio, bool invert, bool user, uint8_t src_len,
                      const struct in6_addr *from, uint32_t lookup_table,
                      bool ipv4)
    OVS_REQUIRES(mutex)
{
    struct router_rule *rule = xzalloc(sizeof *rule);

    rule->prio = prio;
    rule->invert = invert;
    rule->user = user;
    rule->src_prefix = src_len;
    rule->from_addr = *from;
    rule->lookup_table = lookup_table;
    rule->ipv4 = ipv4;

    pvector_insert(&rules, rule, rule_pvec_prio(prio));
    pvector_publish(&rules);
}

void
ovs_router_rule_add(uint32_t prio, bool invert, bool user, uint8_t src_len,
                    const struct in6_addr *from, uint32_t lookup_table,
                    bool ipv4)
    OVS_EXCLUDED(mutex)
{
    if (use_system_routing_table) {
        ovs_mutex_lock(&mutex);
        ovs_router_rule_add__(prio, invert, user, src_len, from,
                              lookup_table, ipv4);
        ovs_mutex_unlock(&mutex);
    }
}

int
ovs_router_rule_del(uint32_t prio, bool invert, uint8_t src_len,
                    const struct in6_addr *from, uint32_t lookup_table,
                    bool ipv4)
    OVS_REQUIRES(mutex)
{
    struct router_rule *rule;

    PVECTOR_FOR_EACH (rule, &rules) {
        if (prio && rule->prio > prio) {
            break;
        }
        if (rule->user
            && rule->invert == invert
            && (!prio || rule->prio == prio)
            && rule->ipv4 == ipv4
            && rule->src_prefix == src_len
            && ipv6_addr_equals(&rule->from_addr, from)
            && rule->lookup_table == lookup_table) {
            pvector_remove(&rules, rule);
            ovsrcu_postpone(rule_destroy_cb, rule);
            pvector_publish(&rules);
            return 0;
        }
    }

    return -ENOENT;
}

void
ovs_router_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        ovs_mutex_lock(&mutex);
        pvector_init(&rules);
        init_standard_rules();
        ovs_mutex_unlock(&mutex);
        fatal_signal_add_hook(ovs_router_flush_handler, NULL, NULL, true);
        unixctl_command_register("ovs/route/add",
                                 "ip/plen dev [gw] [pkt_mark=mark] "
                                 "[src=src_ip] [table=id] | ip/plen "
                                 "nhid ID [pkt_mark=mark] [src=src_ip] "
                                 "[table=id]",
                                 2, INT_MAX, ovs_router_add, NULL);
        unixctl_command_register("ovs/route/show", "[table=all|id]", 0, 1,
                                 ovs_router_show, NULL);
        unixctl_command_register("ovs/route/del", "ip/plen "
                                 "[pkt_mark=mark] [table=id]", 1, 3,
                                 ovs_router_del, NULL);
        unixctl_command_register("ovs/route/lookup", "ip_addr "
                                 "[pkt_mark=mark] [src=src_ip]",
                                 1, 3,
                                 ovs_router_lookup_cmd, NULL);
        unixctl_command_register("ovs/route/rule/show", "[-6]", 0, 1,
                                 ovs_router_rules_show, NULL);
        unixctl_command_register("ovs/route/rule/add",
                                 "[-6] [not] from=all|ip/plen [prio=num] "
                                 "table=local|main|default|id",
                                 2, 5, ovs_router_rule_add_cmd, NULL);
        unixctl_command_register("ovs/route/rule/del",
                                 "[-6] [not] from=all|ip/plen [prio=num] "
                                 "table=local|main|default|id",
                                 2, 5, ovs_router_rule_del_cmd, NULL);
        ovsthread_once_done(&once);
    }
}
