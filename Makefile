CONFIG_MODULE_SIG=n
obj-m := lkm.o
KERNEL_DIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default: 
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules 
clean: 
	rm -rf *.o *.ko *.symvers *.mod.* *.order

