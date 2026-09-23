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

#include "dp-hash-map.h"

#include <limits.h>
#include <stdlib.h>

#include "util.h"

bool
dp_hash_map_init(struct dp_hash_map *map, const uint32_t weights[],
                 size_t n_members, size_t max_hash)
{
    struct webster {
        uint32_t divisor;
        double value;
    } *webster;
    uint64_t total_weight = 0;
    uint32_t min_weight = UINT32_MAX;

    *map = (struct dp_hash_map) { 0 };
    if (!n_members || n_members > UINT16_MAX) {
        return false;
    }

    webster = xcalloc(n_members, sizeof *webster);
    for (size_t i = 0; i < n_members; i++) {
        if (weights[i]) {
            min_weight = MIN(min_weight, weights[i]);
        }
        total_weight += weights[i];
        webster[i].divisor = 1;
        webster[i].value = weights[i];
    }
    if (!total_weight) {
        free(webster);
        return false;
    }

    uint64_t min_slots = DIV_ROUND_UP(total_weight, min_weight);
    min_slots = MAX(min_slots,
                    MIN(n_members * 4, DP_HASH_MAP_MAX_HASH_VALUES));
    uint64_t n_hash = MAX(16, ROUND_UP_POW2(min_slots));

    map->n_hash = n_hash;
    if (n_hash > DP_HASH_MAP_MAX_HASH_VALUES ||
        (max_hash && n_hash > max_hash)) {
        free(webster);
        return false;
    }

    map->hash_mask = n_hash - 1;
    map->members = xcalloc(n_hash, sizeof *map->members);
    for (size_t hash = 0; hash < n_hash; hash++) {
        size_t winner = 0;

        for (size_t i = 1; i < n_members; i++) {
            if (webster[i].value > webster[winner].value) {
                winner = i;
            }
        }
        webster[winner].divisor += 2;
        webster[winner].value =
            (double) weights[winner] / webster[winner].divisor;
        map->members[hash] = winner;
    }
    free(webster);
    return true;
}

bool
dp_hash_map_init_explicit(struct dp_hash_map *map,
                          const uint16_t members[], size_t n_hash)
{
    *map = (struct dp_hash_map) { 0 };
    if (!n_hash) {
        return false;
    }

    map->members = xmemdup(members, n_hash * sizeof *members);
    map->n_hash = n_hash;
    map->hash_mask = is_pow2(n_hash) ? n_hash - 1 : UINT32_MAX;
    return true;
}

void
dp_hash_map_destroy(struct dp_hash_map *map)
{
    free(map->members);
    *map = (struct dp_hash_map) { 0 };
}

bool
dp_hash_map_select(const struct dp_hash_map *map, uint32_t hash,
                   dp_hash_map_member_is_alive *is_alive, void *aux,
                   uint16_t *member)
{
    if (!map->members || !map->n_hash) {
        return false;
    }

    size_t start = map->hash_mask != UINT32_MAX
                   ? hash & map->hash_mask : hash % map->n_hash;

    for (size_t i = 0; i < map->n_hash; i++) {
        uint16_t candidate = map->members[(start + i) % map->n_hash];

        if (candidate != DP_HASH_MAP_INVALID_MEMBER &&
            (!is_alive || is_alive(candidate, aux))) {
            *member = candidate;
            return true;
        }
    }
    return false;
}
