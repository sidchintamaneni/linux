


#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>


noinline int sid_bpf_attach_prog(unsigned int sid_id, int prog_fd, __u32 flags){
    
}

////should implement dummy context
//__weak noinline int sid_bpf_event(){
//    return 0;
//}
//
//
//
//BTF_SET8_START(sid_bpf_fmodret_ids);
//BTF_ID_FLAGS(func, sid_bpf_event);
//BTF_SET8_END(sid_bpf_fmodret_ids);
//
//
//static const struct btf_kfunc_id_set sid_bpf_fmodret_set = {
//    .owner = THIS_MODULE,
//    .set = &sid_bpf_fmodret_ids,
//};


BTF_SET8_START(sid_bpf_syscall_kfunc_ids)
BTF_ID_FLAGS(func, sid_bpf_attach_prog)
BTF_SET8_END(sid_bpf_syscall_kfunc_ids)

static const struct btf_kfunc_id_set sid_bpf_syscall_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &sid_bpf_syscall_kfunc_ids,
};


static int __init sid_bpf_init(void){
    pr_info("sid_bpf_init: module initialized\n"); 

//    err =  register_btf_fmodret_id_set(&sid_bpf_fmodret_set);
//    if (err) {
//		pr_warn("error while registering fmodret entrypoints: %d", err);
//		return 0;
//	}
    
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &sid_bpf_syscall_kfunc_set);
	if (err) {
		pr_warn("error while setting Sid BPF syscall kfuncs: %d", err);
		return 0;
	}

    return 0;
}

static void __exit sid_bpf_exit(void){
    pr_info("sid_bpf_exit: module unloaded\n");
}

late_initcall(sid_bpf_init);
module_exit(sid_bpf_exit);

MODULE_AUTHOR("Siddharth Chintamaneni");
MODULE_LICENSE("GPL");

