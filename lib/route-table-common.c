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

#include "route-table.h"

#include <stdlib.h>

void
route_data_destroy(struct route_data *rd)
{
    struct route_data_nexthop *rdnh;

    LIST_FOR_EACH_POP (rdnh, nexthop_node, &rd->nexthops) {
        if (rdnh && rdnh != &rd->primary_next_hop__) {
            free(rdnh);
        }
    }
    free(rd->nh_hash_map);
    rd->nh_hash_map = NULL;
    rd->n_nh_hash = 0;
}
