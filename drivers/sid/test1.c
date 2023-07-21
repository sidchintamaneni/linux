#include<linux/module.h>
#include<linux/init.h>
#include<linux/kernel.h>

static int hello_init(void){
   printk(KERN_ALERT "Kernel module entry");
   return 0;
}

static void hello_exit(void){
   printk(KERN_INFO "Kernel module exit");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_AUTHOR("Siddharth");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Siddharth's first driver with GPL licence.");
