/*
 *  Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

/*
 * Returns 0 if the vrf names are the same, 1 if not.
 * Checks for corner cases around defaults.
 */
int
vrf_compare(const char *vrf1, const char *vrf2);

/*
 * Check if a vrf id and a name refer to the same vrf.
 * Returns 0 if yes, 1 if no.
 */
int
match_vrf_to_id(const char *vrf, const uint32_t vrf_table_id);
