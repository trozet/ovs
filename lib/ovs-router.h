/*
 * Copyright (c) 2014 Nicira, Inc.
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

#ifndef OVS_TNL_ROUTER_H
#define OVS_TNL_ROUTER_H 1

#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>

#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

enum {
    CLS_DEFAULT = 253,
    CLS_MAIN = 254,
    CLS_LOCAL = 255,
    CLS_ALL = UINT32_MAX,
};

struct ovs_router_nexthop {
    char output_netdev[IFNAMSIZ];
    struct in6_addr gw;
    uint32_t id;
    uint32_t flags;
    uint32_t weight;
};

struct ovs_router_group;

struct ovs_router_result {
    char output_netdev[IFNAMSIZ];
    struct in6_addr src;
    struct in6_addr gw;
    uint32_t id;
    uint32_t flags;
    uint32_t weight;
    bool multipath;
    /* Bits of flow_hash that influenced nexthop selection.  UINT32_MAX
     * indicates that the full value was used. */
    uint32_t hash_mask;
};

bool ovs_router_lookup(uint32_t mark, const struct in6_addr *ip_dst,
                       char output_netdev[],
                       struct in6_addr *src, struct in6_addr *gw);
bool ovs_router_lookup_with_hash(uint32_t mark,
                                 const struct in6_addr *ip_dst,
                                 const struct in6_addr *src,
                                 uint32_t flow_hash,
                                 struct ovs_router_result *);
/* Returns an immutable referenced group.  The caller must release it with
 * ovs_router_group_unref(). */
struct ovs_router_group *ovs_router_lookup_group(
    uint32_t mark, const struct in6_addr *ip_dst,
    const struct in6_addr *src);
bool ovs_router_group_select(const struct ovs_router_group *,
                             const struct in6_addr *src,
                             uint32_t flow_hash,
                             struct ovs_router_result *);
bool ovs_router_group_is_multipath(const struct ovs_router_group *);
uint32_t ovs_router_group_hash_mask(const struct ovs_router_group *);
void ovs_router_group_unref(struct ovs_router_group *);
void ovs_router_init(void);
bool ovs_router_is_referenced(uint32_t table);
void ovs_router_insert(uint32_t table, uint32_t mark,
                       const struct in6_addr *ip_dst,
                       uint8_t plen, bool user,
                       const char output_netdev[], const struct in6_addr *gw,
                       const struct in6_addr *prefsrc);
void ovs_router_insert_nexthops(uint32_t table, uint32_t mark,
                                const struct in6_addr *ip_dst,
                                uint8_t plen, bool user,
                                const struct ovs_router_nexthop *, size_t,
                                const uint16_t *hash_map, size_t n_hash,
                                uint32_t group_id,
                                const struct in6_addr *prefsrc);
void ovs_router_force_insert(uint32_t table, uint32_t mark,
                             const struct in6_addr *ip_dst,
                             uint8_t plen, const char output_netdev[],
                             const struct in6_addr *gw,
                             const struct in6_addr *prefsrc);
void ovs_router_nexthop_table_change(void);
void ovs_router_rule_add(uint32_t prio, bool invert, bool user,
                         uint8_t src_len, const struct in6_addr *from,
                         uint32_t lookup_table, bool ipv4);
int ovs_router_rule_del(uint32_t prio, bool invert, uint8_t src_len,
                        const struct in6_addr *from, uint32_t lookup_table,
                        bool ipv4);
void ovs_router_flush(bool flush_all);
void ovs_router_rules_flush(bool flush_all);

void ovs_router_disable_system_routing_table(void);

int ovs_router_get_netdev_source_address(const struct in6_addr *ip6_dst,
                                         const char netdev_name[],
                                         struct in6_addr *psrc);

#ifdef  __cplusplus
}
#endif

#endif
