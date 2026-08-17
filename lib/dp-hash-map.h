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

#ifndef DP_HASH_MAP_H
#define DP_HASH_MAP_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DP_HASH_MAP_MAX_HASH_VALUES 256
#define DP_HASH_MAP_INVALID_MEMBER UINT16_MAX

struct dp_hash_map {
    uint16_t *members;
    size_t n_hash;
    uint32_t hash_mask;
};

typedef bool dp_hash_map_member_is_alive(uint16_t member, void *aux);

bool dp_hash_map_init(struct dp_hash_map *, const uint32_t weights[],
                      size_t n_members, size_t max_hash);
bool dp_hash_map_init_explicit(struct dp_hash_map *,
                               const uint16_t members[], size_t n_hash);
void dp_hash_map_destroy(struct dp_hash_map *);
bool dp_hash_map_select(const struct dp_hash_map *, uint32_t hash,
                        dp_hash_map_member_is_alive *, void *aux,
                        uint16_t *member);

#endif /* dp-hash-map.h */
