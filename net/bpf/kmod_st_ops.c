#include <linux/kernel.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>

static struct btf *bpf_test_ops_btf;

struct bpf_test_ops_state {
	int val;
};

struct bpf_test_st_ops {
	int (*test_st_1) (struct bpf_test_ops_state *cb);
	int (*test_st_2) (struct bpf_test_ops_state *cb, int arg1, 
						unsigned long arg2);
	int (*test_st_sleepable) (struct bpf_test_ops_state *cb);
	char 			name[100];
};

static int bpf_test_st_sleepable(struct bpf_test_ops_state *cb)
{
	pr_info("bpf_test_st_sleepable: default behaviour\n");
	return 0;
}


static int bpf_test_st_2(struct bpf_test_ops_state *cb, int arg1, unsigned long arg2)
{
	pr_info("bpf_test_st_2: default behaviour\n");
	return 0;
}


static int bpf_test_st_1(struct bpf_test_ops_state *cb__nullable)
{
	pr_info("bpf_test_st_1: default behaviour\n");
	return 0;
}

static bool bpf_test_ops_is_valid_access(int off, int size,
					enum bpf_access_type type,
					const struct bpf_prog *prog,
					struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static int bpf_test_ops_btf_struct_access(struct bpf_verifier_log *log,
					const struct bpf_reg_state *reg,
					int off, int size)
{
	const struct btf_type *state;
	const struct btf_type *t;
	s32 type_id;

	type_id = btf_find_by_name_kind(reg->btf, "bpf_test_ops_state",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;

	t = btf_type_by_id(reg->btf, reg->btf_id);
	state = btf_type_by_id(reg->btf, type_id);
	if (t != state) {
		bpf_log(log, "only access to bpf_test_ops_state is supported\n");
		return -EACCES;
	}

	if (off + size > sizeof(struct bpf_test_ops_state)) {
		bpf_log(log, "write access at off %d with size %d\n", off, size);
		return -EACCES;
	}

	return 0;
}

// If bpf_verifier_ops is not created then verifier c:
static const struct bpf_verifier_ops bpf_test_verifier_ops = {
	.is_valid_access = bpf_test_ops_is_valid_access,
	.btf_struct_access = bpf_test_ops_btf_struct_access,
};

// Kernel crashes without an init function during the boot
static int bpf_test_init(struct btf *btf)
{
	bpf_test_ops_btf = btf;
	return 0;
}

static int bpf_test_ops_check_member(const struct btf_type *t,
				      const struct btf_member *member,
				      const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct bpf_test_st_ops, test_st_sleepable):
		break;
	default:
		if (prog->sleepable)
			return -EINVAL;
	}

	return 0;
}

static int bpf_test_init_member(const struct btf_type *t,
				 const struct btf_member *member,
				 void *kdata, const void *udata)
{
	return -EOPNOTSUPP;
}

static int bpf_test_reg(void *kdata, struct bpf_link *link)
{
	return -EOPNOTSUPP;
}

static void bpf_test_unreg(void *kdata, struct bpf_link *link)
{
}

static struct bpf_test_st_ops __bpf_bpf_test_st_ops = {
	.test_st_1 = bpf_test_st_1,
	.test_st_2 = bpf_test_st_2,
	.test_st_sleepable = bpf_test_st_sleepable,
};

static struct bpf_struct_ops bpf_bpf_test_st_ops = {
	.verifier_ops = &bpf_test_verifier_ops,
	.init = bpf_test_init,
	.check_member = bpf_test_ops_check_member,
	.init_member = bpf_test_init_member,
	.reg = bpf_test_reg,
	.unreg = bpf_test_unreg,
	.name = "bpf_test_st_ops",
	.cfi_stubs = &__bpf_bpf_test_st_ops,
	.owner = THIS_MODULE,
};

static int __init kmod_st_ops_init(void)
{
	return register_bpf_struct_ops(&bpf_bpf_test_st_ops, bpf_test_st_ops);
}
late_initcall(kmod_st_ops_init);
