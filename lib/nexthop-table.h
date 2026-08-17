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

#ifndef NEXTHOP_TABLE_H
#define NEXTHOP_TABLE_H 1

#include <stdbool.h>
#include <stdint.h>

struct route_data;

typedef void nexthop_table_change_cb(void *aux);

void nexthop_table_init(nexthop_table_change_cb *, void *aux);
void nexthop_table_run(void);
void nexthop_table_wait(void);

bool nexthop_table_resolve(uint32_t id, struct route_data *);

#endif /* nexthop-table.h */
