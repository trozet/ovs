/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "nexthop-table.h"

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <stdlib.h>

#include "compiler.h"
#include "hash.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/hmap.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "route-table.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(nexthop_table);

struct nexthop_group_member {
    uint32_t id;
    uint32_t weight;
};

struct nexthop_entry {
    struct hmap_node hmap_node;
    uint32_t id;
    uint32_t flags;
    int ifindex;
    sa_family_t family;
    struct in6_addr gateway;
    char ifname[IFNAMSIZ];
    bool user;
    bool resilient;
    bool blackhole;
    bool fdb;
    bool unsupported;
    size_t n_members;
    struct nexthop_group_member *members;
    size_t n_buckets;
    uint32_t *buckets;
};

static struct hmap nexthops = HMAP_INITIALIZER(&nexthops);
static nexthop_table_change_cb *change_cb;
static void *change_aux;

static struct nexthop_entry *
nexthop_entry_find__(uint32_t id, bool user)
{
    struct nexthop_entry *entry;
    uint32_t hash = hash_int(id, 0);

    HMAP_FOR_EACH_WITH_HASH (entry, hmap_node, hash, &nexthops) {
        if (entry->id == id && entry->user == user) {
            return entry;
        }
    }
    return NULL;
}

static struct nexthop_entry *
nexthop_entry_find(uint32_t id)
{
    struct nexthop_entry *entry = nexthop_entry_find__(id, true);

    return entry ? entry : nexthop_entry_find__(id, false);
}

static void
nexthop_entry_destroy(struct nexthop_entry *entry)
{
    if (entry) {
        free(entry->buckets);
        free(entry->members);
        free(entry);
    }
}

static void
nexthop_table_insert(struct nexthop_entry *entry)
{
    struct nexthop_entry *old = nexthop_entry_find__(entry->id, entry->user);

    if (old) {
        hmap_remove(&nexthops, &old->hmap_node);
        nexthop_entry_destroy(old);
    }
    hmap_insert(&nexthops, &entry->hmap_node, hash_int(entry->id, 0));
}

static void
nexthop_table_notify(void)
{
    if (change_cb) {
        change_cb(change_aux);
    }
}

#ifdef HAVE_LINUX_NEXTHOP_H

#include <linux/nexthop.h>
#include <linux/rtnetlink.h>
#include "netlink.h"
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "openvswitch/ofpbuf.h"

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

struct nexthop_table_msg {
    uint16_t nlmsg_type;
    struct nexthop_entry *entry;
    uint32_t group_id;
    uint32_t nexthop_id;
    uint32_t flags;
    uint16_t bucket;
    bool is_bucket;
};

static struct nln *nln;
static struct nln_notifier *notifier;
static struct nexthop_table_msg nln_change;

static int nexthop_table_parse(struct ofpbuf *, void *change);

static void
nexthop_table_clear_system(void)
{
    struct nexthop_entry *entry;
    struct nexthop_entry *next;

    HMAP_FOR_EACH_SAFE (entry, next, hmap_node, &nexthops) {
        if (!entry->user) {
            hmap_remove(&nexthops, &entry->hmap_node);
            nexthop_entry_destroy(entry);
        }
    }
}

static uint32_t
nexthop_group_weight(const struct nexthop_grp *member)
{
#ifdef HAVE_STRUCT_NEXTHOP_GRP_WEIGHT_HIGH
    return ((uint32_t) member->weight_high << 8) + member->weight + 1;
#else
    return member->weight + 1;
#endif
}

static int
nexthop_table_parse(struct ofpbuf *buf, void *change_)
{
    struct nexthop_table_msg *change = change_;
    const struct nlmsghdr *nlmsg;
    const struct nhmsg *nhmsg;
    struct nlattr *attrs[NHA_MAX + 1];
    size_t offset;

    static const struct nl_policy policy[] = {
        [NHA_ID] = { .type = NL_A_U32 },
        [NHA_GROUP] = { .type = NL_A_UNSPEC, .optional = true,
                        .min_len = sizeof(struct nexthop_grp) },
        [NHA_GROUP_TYPE] = { .type = NL_A_U16, .optional = true },
        [NHA_BLACKHOLE] = { .type = NL_A_FLAG, .optional = true },
        [NHA_OIF] = { .type = NL_A_U32, .optional = true },
        [NHA_GATEWAY] = { .type = NL_A_UNSPEC, .optional = true,
                          .min_len = sizeof(ovs_be32),
                          .max_len = sizeof(struct in6_addr) },
        [NHA_ENCAP_TYPE] = { .type = NL_A_U16, .optional = true },
        [NHA_ENCAP] = { .type = NL_A_NESTED, .optional = true },
#ifdef HAVE_NHA_FDB
        [NHA_FDB] = { .type = NL_A_FLAG, .optional = true },
#endif
#ifdef HAVE_NEXTHOP_RESILIENT_GROUPS
        [NHA_RES_GROUP] = { .type = NL_A_NESTED, .optional = true },
#endif
    };

    nlmsg = ofpbuf_at(buf, 0, NLMSG_HDRLEN);
    nhmsg = ofpbuf_at(buf, NLMSG_HDRLEN, sizeof *nhmsg);
    if (!nlmsg || !nhmsg) {
        return 0;
    }

    memset(change, 0, sizeof *change);
#ifdef HAVE_NEXTHOP_RESILIENT_GROUPS
    if (nlmsg->nlmsg_type == RTM_NEWNEXTHOPBUCKET ||
        nlmsg->nlmsg_type == RTM_DELNEXTHOPBUCKET) {
        static const struct nl_policy bucket_policy[] = {
            [NHA_ID] = { .type = NL_A_U32 },
            [NHA_RES_BUCKET] = { .type = NL_A_NESTED },
        };
        static const struct nl_policy res_bucket_policy[] = {
            [NHA_RES_BUCKET_INDEX] = { .type = NL_A_U16 },
            [NHA_RES_BUCKET_NH_ID] = { .type = NL_A_U32 },
        };
        struct nlattr *bucket_attrs[ARRAY_SIZE(bucket_policy)];
        struct nlattr *res_attrs[ARRAY_SIZE(res_bucket_policy)];

        offset = NLMSG_HDRLEN + sizeof *nhmsg;
        if (!nl_policy_parse(buf, offset, bucket_policy, bucket_attrs,
                             ARRAY_SIZE(bucket_policy)) ||
            !nl_parse_nested(bucket_attrs[NHA_RES_BUCKET], res_bucket_policy,
                             res_attrs, ARRAY_SIZE(res_bucket_policy))) {
            VLOG_DBG_RL(&rl, "received unparseable nexthop bucket message");
            return 0;
        }

        change->nlmsg_type = nlmsg->nlmsg_type;
        change->group_id = nl_attr_get_u32(bucket_attrs[NHA_ID]);
        change->nexthop_id =
            nl_attr_get_u32(res_attrs[NHA_RES_BUCKET_NH_ID]);
        change->bucket = nl_attr_get_u16(res_attrs[NHA_RES_BUCKET_INDEX]);
        change->flags = nhmsg->nh_flags;
        change->is_bucket = true;
        return RTNLGRP_NEXTHOP;
    }
#endif

    if (nlmsg->nlmsg_type != RTM_NEWNEXTHOP &&
        nlmsg->nlmsg_type != RTM_DELNEXTHOP) {
        return 0;
    }

    offset = NLMSG_HDRLEN + sizeof *nhmsg;
    if (!nl_policy_parse(buf, offset, policy, attrs, ARRAY_SIZE(policy))) {
        VLOG_DBG_RL(&rl, "received unparseable nexthop message");
        return 0;
    }

    size_t n_members = 0;
    const struct nexthop_grp *members = NULL;
    if (attrs[NHA_GROUP]) {
        size_t size = nl_attr_get_size(attrs[NHA_GROUP]);

        if (size % sizeof *members) {
            VLOG_DBG_RL(&rl, "invalid nexthop group size");
            return 0;
        }
        members = nl_attr_get(attrs[NHA_GROUP]);
        n_members = size / sizeof *members;
    }

    struct nexthop_entry *entry = xzalloc(sizeof *entry);
    uint16_t group_type = attrs[NHA_GROUP_TYPE]
                          ? nl_attr_get_u16(attrs[NHA_GROUP_TYPE])
                          : NEXTHOP_GRP_TYPE_MPATH;

    entry->id = nl_attr_get_u32(attrs[NHA_ID]);
    entry->flags = nhmsg->nh_flags;
    entry->family = nhmsg->nh_family;
    entry->blackhole = attrs[NHA_BLACKHOLE] != NULL;
#ifdef HAVE_NHA_FDB
    entry->fdb = attrs[NHA_FDB] != NULL;
#endif
    entry->unsupported = attrs[NHA_ENCAP_TYPE] || attrs[NHA_ENCAP];
    entry->n_members = n_members;
    if (n_members) {
        entry->members = xcalloc(n_members, sizeof *entry->members);
    }

    bool supported_group = group_type == NEXTHOP_GRP_TYPE_MPATH;
#ifdef HAVE_NEXTHOP_RESILIENT_GROUPS
    if (group_type == NEXTHOP_GRP_TYPE_RES &&
        attrs[NHA_RES_GROUP]) {
        static const struct nl_policy res_group_policy[] = {
            [NHA_RES_GROUP_BUCKETS] = { .type = NL_A_U16 },
        };
        struct nlattr *res_attrs[ARRAY_SIZE(res_group_policy)];

        if (!nl_parse_nested(attrs[NHA_RES_GROUP], res_group_policy,
                             res_attrs, ARRAY_SIZE(res_group_policy))) {
            VLOG_DBG_RL(&rl, "invalid resilient nexthop group data");
            nexthop_entry_destroy(entry);
            return 0;
        }
        entry->n_buckets =
            nl_attr_get_u16(res_attrs[NHA_RES_GROUP_BUCKETS]);
        entry->buckets = xcalloc(entry->n_buckets,
                                 sizeof *entry->buckets);
        entry->resilient = true;
        supported_group = true;
    }
#endif
    if (!supported_group) {
        entry->unsupported = true;
    }

    if (attrs[NHA_OIF]) {
        entry->ifindex = nl_attr_get_u32(attrs[NHA_OIF]);
    }
    if (attrs[NHA_GATEWAY]) {
        size_t size = nl_attr_get_size(attrs[NHA_GATEWAY]);

        if (size == sizeof(ovs_be32)) {
            in6_addr_set_mapped_ipv4(
                &entry->gateway, nl_attr_get_be32(attrs[NHA_GATEWAY]));
        } else if (size == sizeof entry->gateway) {
            entry->gateway = nl_attr_get_in6_addr(attrs[NHA_GATEWAY]);
        } else {
            VLOG_DBG_RL(&rl, "invalid nexthop gateway size");
            nexthop_entry_destroy(entry);
            return 0;
        }
    }

    for (size_t i = 0; i < n_members; i++) {
        entry->members[i].id = members[i].id;
        entry->members[i].weight = nexthop_group_weight(&members[i]);
    }

    change->nlmsg_type = nlmsg->nlmsg_type;
    change->entry = entry;
    return RTNLGRP_NEXTHOP;
}

static void
nexthop_table_apply_bucket(const struct nexthop_table_msg *msg OVS_UNUSED)
{
#ifdef HAVE_NEXTHOP_RESILIENT_GROUPS
    struct nexthop_entry *entry =
        nexthop_entry_find__(msg->group_id, false);

    if (!entry || !entry->resilient ||
        msg->bucket >= entry->n_buckets) {
        return;
    }
    entry->buckets[msg->bucket] =
        msg->nlmsg_type == RTM_NEWNEXTHOPBUCKET ? msg->nexthop_id : 0;
#else
    OVS_NOT_REACHED();
#endif
}

static void
nexthop_table_dump__(uint16_t request_type)
{
    uint64_t reply_stub[NL_DUMP_BUFSIZE / 8];
    struct ofpbuf request, reply, buf;
    struct nl_dump dump;

    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, sizeof(struct nhmsg), request_type,
                        NLM_F_REQUEST);
    ofpbuf_put_zeros(&request, sizeof(struct nhmsg));
    nl_dump_start(&dump, NETLINK_ROUTE, &request);
    ofpbuf_uninit(&request);

    ofpbuf_use_stub(&buf, reply_stub, sizeof reply_stub);
    while (nl_dump_next(&dump, &reply, &buf)) {
        struct nexthop_table_msg msg = { 0 };

        if (nexthop_table_parse(&reply, &msg) && msg.is_bucket) {
            nexthop_table_apply_bucket(&msg);
        } else if (msg.entry) {
            nexthop_table_insert(msg.entry);
        }
    }
    ofpbuf_uninit(&buf);
    nl_dump_done(&dump);
}

static void
nexthop_table_dump(void)
{
    nexthop_table_clear_system();
    nexthop_table_dump__(RTM_GETNEXTHOP);
#ifdef HAVE_NEXTHOP_RESILIENT_GROUPS
    struct nexthop_entry *entry;

    HMAP_FOR_EACH (entry, hmap_node, &nexthops) {
        if (!entry->user && entry->resilient) {
            nexthop_table_dump__(RTM_GETNEXTHOPBUCKET);
            break;
        }
    }
#endif
}

static void
nexthop_table_change(const void *change_, void *aux OVS_UNUSED)
{
    struct nexthop_table_msg *change =
        CONST_CAST(struct nexthop_table_msg *, change_);

    if (!change) {
        nexthop_table_dump();
    } else if (change->is_bucket) {
        nexthop_table_apply_bucket(change);
    } else {
        struct nexthop_entry *old =
            nexthop_entry_find__(change->entry->id, false);

        if (old) {
            hmap_remove(&nexthops, &old->hmap_node);
            nexthop_entry_destroy(old);
        }
        if (change->nlmsg_type == RTM_NEWNEXTHOP) {
            nexthop_table_insert(change->entry);
#ifdef HAVE_NEXTHOP_RESILIENT_GROUPS
            if (change->entry->resilient) {
                nexthop_table_dump__(RTM_GETNEXTHOPBUCKET);
            }
#endif
            change->entry = NULL;
        }
        nexthop_entry_destroy(change->entry);
    }

    nexthop_table_notify();
}

static void
nexthop_table_system_init(void)
{
    ovs_assert(!nln);
    ovs_assert(!notifier);

    nln = nln_create(NETLINK_ROUTE, nexthop_table_parse, &nln_change);
    notifier = nln_notifier_create(nln, RTNLGRP_NEXTHOP,
                                   nexthop_table_change, NULL);
    nexthop_table_dump();
}

static void
nexthop_table_system_run(void)
{
    if (nln) {
        nln_run(nln);
    }
}

static void
nexthop_table_system_wait(void)
{
    if (nln) {
        nln_wait(nln);
    }
}

#else  /* !HAVE_LINUX_NEXTHOP_H */

static void
nexthop_table_system_init(void)
{
}

static void
nexthop_table_system_run(void)
{
}

static void
nexthop_table_system_wait(void)
{
}

#endif /* HAVE_LINUX_NEXTHOP_H */

static bool
nexthop_table_resolve__(const struct nexthop_entry *entry,
                        uint32_t weight, uint32_t inherited_flags,
                        struct route_data *rd, unsigned int depth)
{
    if (!entry || depth > 8 || entry->blackhole || entry->fdb ||
        entry->unsupported) {
        return false;
    }

    if (entry->n_members) {
        bool resolved = false;

        for (size_t i = 0; i < entry->n_members; i++) {
            const struct nexthop_group_member *member = &entry->members[i];
            const struct nexthop_entry *child =
                nexthop_entry_find(member->id);
            uint64_t combined = (uint64_t) weight * member->weight;

            resolved |= nexthop_table_resolve__(child,
                                                MIN(combined,
                                                    (uint64_t) UINT32_MAX),
                                                inherited_flags |
                                                entry->flags,
                                                rd, depth + 1);
        }
        return resolved;
    }

    if (!entry->ifindex && !entry->ifname[0]) {
        return false;
    }

    struct route_data_nexthop *rdnh = xzalloc(sizeof *rdnh);
    rdnh->family = entry->family;
    rdnh->addr = entry->gateway;
    rdnh->ifindex = entry->ifindex;
    rdnh->nh_id = entry->id;
    rdnh->weight = weight;
    rdnh->flags = inherited_flags | entry->flags;

    if (entry->ifname[0]) {
        ovs_strlcpy(rdnh->ifname, entry->ifname, sizeof rdnh->ifname);
    } else if (!if_indextoname(rdnh->ifindex, rdnh->ifname)) {
        free(rdnh);
        return false;
    }

    ovs_list_push_back(&rd->nexthops, &rdnh->nexthop_node);
    return true;
}

bool
nexthop_table_resolve(uint32_t id, struct route_data *rd)
{
    const struct nexthop_entry *entry = nexthop_entry_find(id);

    if (!entry || !entry->resilient || !entry->n_members) {
        return nexthop_table_resolve__(entry, 1, 0, rd, 0);
    }

    struct route_data tmp;
    memset(&tmp, 0, sizeof tmp);
    ovs_list_init(&tmp.nexthops);

    for (size_t i = 0; i < entry->n_members; i++) {
        const struct nexthop_group_member *member = &entry->members[i];
        const struct nexthop_entry *child = nexthop_entry_find(member->id);

        if (!nexthop_table_resolve__(child, member->weight, entry->flags,
                                     &tmp, 1)) {
            route_data_destroy(&tmp);
            return false;
        }
    }

    bool complete = entry->n_buckets > 0;
    tmp.nh_hash_map = xmalloc(entry->n_buckets * sizeof *tmp.nh_hash_map);
    tmp.n_nh_hash = entry->n_buckets;
    for (size_t i = 0; i < entry->n_buckets; i++) {
        size_t member;

        if (!entry->buckets[i]) {
            tmp.nh_hash_map[i] = UINT16_MAX;
            continue;
        }
        for (member = 0; member < entry->n_members; member++) {
            if (entry->members[member].id == entry->buckets[i]) {
                break;
            }
        }
        if (member == entry->n_members) {
            complete = false;
            break;
        }
        tmp.nh_hash_map[i] = member;
    }
    if (!complete) {
        free(tmp.nh_hash_map);
        tmp.nh_hash_map = NULL;
        tmp.n_nh_hash = 0;
    }

    ovs_list_push_back_all(&rd->nexthops, &tmp.nexthops);
    rd->nh_hash_map = tmp.nh_hash_map;
    rd->n_nh_hash = tmp.n_nh_hash;
    return true;
}

static void
nexthop_table_add(struct unixctl_conn *conn, int argc,
                  const char *argv[], void *aux OVS_UNUSED)
{
    unsigned int id;

    if (!str_to_uint(argv[1], 10, &id) || !id || strcmp(argv[2], "dev")) {
        unixctl_command_reply_error(conn, "Invalid nexthop ID or device");
        return;
    }

    struct nexthop_entry *entry = xzalloc(sizeof *entry);
    entry->id = id;
    entry->user = true;
    ovs_strlcpy(entry->ifname, argv[3], sizeof entry->ifname);

    for (int i = 4; i < argc;) {
        if (!strcmp(argv[i], "via") && i + 1 < argc) {
            ovs_be32 gateway;

            if (ip_parse(argv[i + 1], &gateway)) {
                in6_addr_set_mapped_ipv4(&entry->gateway, gateway);
                entry->family = AF_INET;
            } else if (ipv6_parse(argv[i + 1], &entry->gateway)) {
                entry->family = AF_INET6;
            } else {
                nexthop_entry_destroy(entry);
                unixctl_command_reply_error(conn, "Invalid gateway");
                return;
            }
            i += 2;
        } else if (!strcmp(argv[i], "flags") && i + 1 < argc) {
            if (!str_to_uint(argv[i + 1], 0, &entry->flags)) {
                nexthop_entry_destroy(entry);
                unixctl_command_reply_error(conn, "Invalid flags");
                return;
            }
            i += 2;
        } else {
            nexthop_entry_destroy(entry);
            unixctl_command_reply_error(conn, "Invalid nexthop parameter");
            return;
        }
    }

    nexthop_table_insert(entry);
    nexthop_table_notify();
    unixctl_command_reply(conn, "OK");
}

static void
nexthop_table_group_add(struct unixctl_conn *conn, int argc,
                        const char *argv[], void *aux OVS_UNUSED)
{
    struct nexthop_group_member *members = NULL;
    uint32_t *buckets = NULL;
    size_t allocated_members = 0;
    size_t allocated_buckets = 0;
    size_t n_members = 0;
    size_t n_buckets = 0;
    unsigned int flags = 0;
    unsigned int id;
    ssize_t current = -1;
    struct ds error = DS_EMPTY_INITIALIZER;

    if (!str_to_uint(argv[1], 10, &id) || !id) {
        unixctl_command_reply_error(conn, "Invalid group ID");
        return;
    }

    for (int i = 2; i < argc;) {
        if (!strcmp(argv[i], "nexthop") && i + 1 < argc) {
            unsigned int member_id;

            if (!str_to_uint(argv[i + 1], 10, &member_id) || !member_id ||
                member_id == id) {
                ds_put_cstr(&error, "Invalid group nexthop ID");
                break;
            }
            if (n_members == allocated_members) {
                members = x2nrealloc(members, &allocated_members,
                                     sizeof *members);
            }
            current = n_members++;
            members[current].id = member_id;
            members[current].weight = 1;
            i += 2;
        } else if (!strcmp(argv[i], "weight") && i + 1 < argc) {
            unsigned int weight;

            if (current < 0 ||
                !str_to_uint(argv[i + 1], 10, &weight) || !weight) {
                ds_put_cstr(&error, "Invalid nexthop weight");
                break;
            }
            members[current].weight = weight;
            i += 2;
        } else if (!strcmp(argv[i], "bucket") && i + 1 < argc) {
            unsigned int bucket = 0;

            if (strcmp(argv[i + 1], "unassigned") &&
                (!str_to_uint(argv[i + 1], 10, &bucket) || !bucket)) {
                ds_put_cstr(&error, "Invalid bucket nexthop ID");
                break;
            }
            if (n_buckets == allocated_buckets) {
                buckets = x2nrealloc(buckets, &allocated_buckets,
                                     sizeof *buckets);
            }
            buckets[n_buckets++] = bucket;
            i += 2;
        } else if (!strcmp(argv[i], "flags") && i + 1 < argc) {
            if (!str_to_uint(argv[i + 1], 0, &flags)) {
                ds_put_cstr(&error, "Invalid group flags");
                break;
            }
            i += 2;
        } else {
            ds_put_format(&error, "Invalid group parameter '%s'", argv[i]);
            break;
        }
    }

    if (!n_members && !error.length) {
        ds_put_cstr(&error, "Group requires at least one nexthop");
    }
    for (size_t i = 0; i < n_members && !error.length; i++) {
        const struct nexthop_entry *member =
            nexthop_entry_find(members[i].id);

        if (!member) {
            ds_put_format(&error, "Nexthop ID %"PRIu32" does not exist",
                          members[i].id);
        } else if (n_buckets && member->n_members) {
            ds_put_format(&error, "Resilient group member %"PRIu32
                          " is a group", members[i].id);
        }
        for (size_t j = 0; j < i && !error.length; j++) {
            if (members[i].id == members[j].id) {
                ds_put_format(&error, "Duplicate nexthop ID %"PRIu32,
                              members[i].id);
            }
        }
    }
    for (size_t i = 0; i < n_buckets && !error.length; i++) {
        if (!buckets[i]) {
            continue;
        }
        size_t j;

        for (j = 0; j < n_members; j++) {
            if (buckets[i] == members[j].id) {
                break;
            }
        }
        if (j == n_members) {
            ds_put_format(&error, "Bucket references unknown nexthop ID %"
                          PRIu32, buckets[i]);
        }
    }

    if (error.length) {
        unixctl_command_reply_error(conn, ds_cstr(&error));
    } else {
        struct nexthop_entry *entry = xzalloc(sizeof *entry);

        entry->id = id;
        entry->flags = flags;
        entry->user = true;
        entry->resilient = n_buckets > 0;
        entry->members = members;
        entry->n_members = n_members;
        entry->buckets = buckets;
        entry->n_buckets = n_buckets;
        members = NULL;
        buckets = NULL;
        nexthop_table_insert(entry);
        nexthop_table_notify();
        unixctl_command_reply(conn, "OK");
    }
    ds_destroy(&error);
    free(members);
    free(buckets);
}

static void
nexthop_table_del(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[], void *aux OVS_UNUSED)
{
    unsigned int id;

    if (!str_to_uint(argv[1], 10, &id) || !id) {
        unixctl_command_reply_error(conn, "Invalid nexthop ID");
        return;
    }

    struct nexthop_entry *entry = nexthop_entry_find__(id, true);
    if (!entry) {
        unixctl_command_reply_error(conn, "Not found");
        return;
    }

    hmap_remove(&nexthops, &entry->hmap_node);
    nexthop_entry_destroy(entry);
    nexthop_table_notify();
    unixctl_command_reply(conn, "OK");
}

static void
nexthop_table_show(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct nexthop_entry *entry;

    HMAP_FOR_EACH (entry, hmap_node, &nexthops) {
        ds_put_format(&ds, "%s %"PRIu32,
                      entry->user ? "User" : "System", entry->id);
        if (entry->n_members) {
            ds_put_cstr(&ds, " group");
            for (size_t i = 0; i < entry->n_members; i++) {
                ds_put_format(&ds, " nexthop %"PRIu32" weight %"PRIu32,
                              entry->members[i].id,
                              entry->members[i].weight);
            }
            for (size_t i = 0; i < entry->n_buckets; i++) {
                if (entry->buckets[i]) {
                    ds_put_format(&ds, " bucket %"PRIu32,
                                  entry->buckets[i]);
                } else {
                    ds_put_cstr(&ds, " bucket unassigned");
                }
            }
        } else {
            char ifname[IFNAMSIZ];
            const char *name = entry->ifname;

            if (!name[0] && entry->ifindex &&
                if_indextoname(entry->ifindex, ifname)) {
                name = ifname;
            }
            ds_put_format(&ds, " dev %s", name);
            if (ipv6_addr_is_set(&entry->gateway)) {
                ds_put_cstr(&ds, " via ");
                ipv6_format_mapped(&entry->gateway, &ds);
            }
        }
        if (entry->flags) {
            ds_put_format(&ds, " flags 0x%"PRIx32, entry->flags);
        }
        ds_put_char(&ds, '\n');
    }
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

void
nexthop_table_init(nexthop_table_change_cb *cb, void *aux)
{
    static bool initialized;

    ovs_assert(!initialized);
    initialized = true;
    change_cb = cb;
    change_aux = aux;

    unixctl_command_register("ovs/nexthop/add",
                             "ID dev DEV [via IP] [flags FLAGS] "
                             "(replaces existing manual ID)",
                             3, 7, nexthop_table_add, NULL);
    unixctl_command_register("ovs/nexthop/group/add",
                             "ID nexthop ID [weight N] ... "
                             "[bucket ID|unassigned] ... [flags FLAGS] "
                             "(replaces existing manual ID)",
                             3, INT_MAX, nexthop_table_group_add, NULL);
    unixctl_command_register("ovs/nexthop/del", "ID", 1, 1,
                             nexthop_table_del, NULL);
    unixctl_command_register("ovs/nexthop/show", "", 0, 0,
                             nexthop_table_show, NULL);
    nexthop_table_system_init();
}

void
nexthop_table_run(void)
{
    nexthop_table_system_run();
}

void
nexthop_table_wait(void)
{
    nexthop_table_system_wait();
}
