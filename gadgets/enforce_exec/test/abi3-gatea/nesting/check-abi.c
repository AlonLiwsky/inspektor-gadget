// SPDX-License-Identifier: GPL-2.0
// BTF inspection only: does not load a BPF program or create a map.
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
static int integer(const struct btf *b, __u32 id)
{
	const struct btf_type *t = resolve(b, id);
	return t && btf_is_int(t) && t->size == 4 &&
	       btf_int_encoding(t) == BTF_INT_SIGNED;
}
static int pointer(const struct btf *b, __u32 id, const char *name,
		   int character)
{
	const struct btf_type *t = resolve(b, id);
	if (!t || !btf_is_ptr(t))
		return 0;
	t = resolve(b, t->type);
	if (!t)
		return 0;
	const char *n = btf__name_by_offset(b, t->name_off);
	return n && !strcmp(n, name) &&
	       (character ? (btf_is_int(t) && t->size == 1) : btf_is_struct(t));
}
int nest_check_abi(const char *path)
{
	struct btf *b = btf__parse(path, NULL);
	if (libbpf_get_error(b))
		return 1;
	const char *names[] = { "bpf_lsm_file_open", "bpf_lsm_inode_permission",
				"bpf_get_file_xattr" };
	const char *args[][3] = { { "file", NULL, NULL },
				  { "idmap", "inode", "mask" },
				  { "file", "name__str", "value_p" } };
	const char *pointees[][3] = { { "file", NULL, NULL },
				      { "mnt_idmap", "inode", NULL },
				      { "file", "char", "bpf_dynptr" } };
	int rc = 1;
	for (unsigned i = 0; i < 3; i++) {
		int id = btf__find_by_name_kind(b, names[i], BTF_KIND_FUNC);
		if (id < 0)
			goto done;
		const struct btf_type *fn = btf__type_by_id(b, id),
				      *p = btf__type_by_id(b, fn->type);
		unsigned count = i ? 3 : 1;
		if (!p || !btf_is_func_proto(p) || btf_vlen(p) != count ||
		    !integer(b, p->type))
			goto done;
		const struct btf_param *a = btf_params(p);
		for (unsigned j = 0; j < count; j++) {
			const char *name =
				btf__name_by_offset(b, a[j].name_off);
			if (!name || strcmp(name, args[i][j]))
				goto done;
			if (pointees[i][j]) {
				if (!pointer(b, a[j].type, pointees[i][j],
					     i == 2 && j == 1))
					goto done;
			} else if (!integer(b, a[j].type))
				goto done;
		}
		printf("PASS BTF %s exact argument slots/types and signed int return\n",
		       names[i]);
	}
	rc = 0;
done:
	btf__free(b);
	return rc;
}
#ifdef NEST_ABI_MAIN
int main(int argc, char **argv)
{
	return argc == 2 ? nest_check_abi(argv[1]) : 2;
}
#endif
