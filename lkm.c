#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>

#define MAX_SYMBOL_LEN  64
static char symbol[MAX_SYMBOL_LEN];

static void trace(void *arg0, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5);

static struct jprobe jp = {
  .entry = JPROBE_ENTRY(trace),
};

static void trace(void *arg0, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5)
{
  dump_stack();
  jprobe_return();
}

ssize_t handler_proc_write(struct file *filep, const char __user *buf, size_t len, loff_t *offp)
{
  int ret;

  jp.kp.symbol_name = NULL;
  memset(symbol, 0, sizeof(symbol));
  memcpy(symbol, (void *)buf, len);
  jp.kp.symbol_name = symbol; 
  if (!memcmp(symbol, "none", 4)){
    jp.kp.symbol_name = NULL;
    unregister_jprobe(&jp);
    return len;
  }
  else if ((ret = register_jprobe(&jp)) < 0) {
    printk("trace: register_jprobe failed, returned %d\n", ret);
    jp.kp.symbol_name = NULL;
    return -ENOSYS;
  }
  printk("trace: %s traced\n", jp.kp.symbol_name);
  return len;
}

ssize_t handler_proc_read(struct file *filep, char __user *buf, size_t count, loff_t *offp)
{
  int ret;
  if((int)*offp > 0){
    return 0;
  }

  if (!jp.kp.symbol_name){
    sprintf(buf, "Function traced : none\n");
    ret = 23;
    *offp += 23;
  }
  else {
    sprintf(buf, "Function traceed : %s\n", jp.kp.symbol_name);
    ret = strlen(jp.kp.symbol_name) + 20;
    *offp += ret;
  }
  return ret;
}

static const struct file_operations hello_proc_fops = {
  .owner = THIS_MODULE,
  .read = handler_proc_read,
  .write = handler_proc_write,
};

static int __init mod_init(void)
{
  struct proc_dir_entry *proc_entry;

  proc_entry = proc_create("trace", 666, NULL, &hello_proc_fops);
  if (!proc_entry){
    printk(KERN_ALERT "Error : could not initialize trace entry\n");
    return -ENOMEM;
  }

  return 0;
}

static void __exit mod_exit(void)
{
  unregister_jprobe(&jp);
  remove_proc_entry("trace", NULL);
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
