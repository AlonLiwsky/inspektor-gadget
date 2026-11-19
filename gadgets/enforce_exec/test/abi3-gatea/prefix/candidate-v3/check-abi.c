// SPDX-License-Identifier: GPL-2.0
// BTF parsing only. No loading, attachment or BPF execution.
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>
#include <stdio.h>
#include <string.h>
static const struct btf_type *resolve(const struct btf *b, __u32 id)
{
	const struct btf_type *t = btf__type_by_id(b, id);
	while (t && (btf_is_mod(t) || btf_is_typedef(t) || btf_is_type_tag(t)))
		t = btf__type_by_id(b, t->type);
	return t;
}
static int ptr(const struct btf *b, __u32 id, const char *name)
{
	const struct btf_type *t = resolve(b, id);
	if (!t || !btf_is_ptr(t))
		return 0;
	if (!name)
		return t->type == 0;
	t = resolve(b, t->type);
	return t && btf_is_struct(t) &&
	       !strcmp(btf__name_by_offset(b, t->name_off), name);
}
int px_check_abi(const char *path)
{
	struct btf *b = btf__parse(path, NULL);
	if (libbpf_get_error(b))
		return 1;
	int rc = 1;
	const char *names[] = { "copy_thread", "ret_from_fork" };
	for (unsigned i = 0; i < 2; i++) {
		int id = btf__find_by_name_kind(b, names[i], BTF_KIND_FUNC);
		if (id < 0)
			goto done;
		const struct btf_type *f = btf__type_by_id(b, id),
				      *p = resolve(b, f->type);
		if (!p || !btf_is_func_proto(p) || btf_vlen(p) != (i ? 4 : 2))
			goto done;
		const struct btf_param *a = btf_params(p);
		if (!ptr(b, a[0].type, "task_struct"))
			goto done;
		if (!i) {
			const struct btf_type *r = resolve(b, p->type);
			if (!r || !btf_is_int(r) || r->size != 4 ||
			    btf_int_encoding(r) != BTF_INT_SIGNED ||
			    !ptr(b, a[1].type, "kernel_clone_args"))
				goto done;
		} else {
			if (p->type || !ptr(b, a[1].type, "pt_regs") ||
			    !ptr(b, a[3].type, NULL))
				goto done;
			const struct btf_type *fn = resolve(b, a[2].type);
			if (!fn || !btf_is_ptr(fn))
				goto done;
			fn = resolve(b, fn->type);
			if (!fn || !btf_is_func_proto(fn) || btf_vlen(fn) != 1)
				goto done;
			const struct btf_type *ret = resolve(b, fn->type);
			if (!ret || !btf_is_int(ret) || ret->size != 4 ||
			    btf_int_encoding(ret) != BTF_INT_SIGNED ||
			    !ptr(b, btf_params(fn)[0].type, NULL))
				goto done;
		}
		printf("PASS BTF %s typed prototype %s\n", path, names[i]);
	}
	rc = 0;
done:
	btf__free(b);
	return rc;
}
#ifdef PX_ABI_MAIN
int main(int argc, char **argv)
{
	return argc == 2 ? px_check_abi(argv[1]) : 2;
}
#endif
