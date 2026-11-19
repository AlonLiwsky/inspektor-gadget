/* SPDX-License-Identifier: GPL-2.0 */
#ifndef RESOURCE_SHAPE_OPERATIONS_H
#define RESOURCE_SHAPE_OPERATIONS_H
/* Capacity/UNKNOWN preservation only; not semantic role certification. */
static __attribute__((always_inline)) inline int
rs_append(struct rs_bank *b, const struct rs_role *r)
{
	if (!r->uid || !r->root_epoch || r->knowledge > 1)
		return -22;
	for (int i = 0; i < 16; i++)
		if (b->rows[i].uid == r->uid)
			return -17;
	for (int i = 0; i < 16; i++)
		if (!b->rows[i].uid) {
			b->rows[i] = *r;
			return 0;
		}
	return -28;
}
static __attribute__((always_inline)) inline void
rs_copy(struct rs_bank *dst, const struct rs_bank *src)
{
	dst->stamp = src->stamp;
	dst->task_cookie = src->task_cookie;
	dst->version = src->version;
	for (int i = 0; i < 16; i++)
		dst->rows[i] = src->rows[i];
}
#endif
