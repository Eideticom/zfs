ZFS = $(realpath $(PWD)/../..)
KBUILD_EXTRA_SYMBOLS = $(ZFS)/module/Module.symvers
TARGET = zoff_noload

KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m += $(TARGET).o

ccflags-y = -std=gnu99 -Wno-declaration-after-statement -g3 -I$(PWD) -I$(ZFS) \
	    -I$(ZFS)/include -I$(ZFS)/include/os/linux/spl \
	    -I$(ZFS)/include/os/linux/kernel -I$(ZFS)/include/os/linux/zfs \
	    -DZOFF=1 -D_KERNEL

default: modules
.PHONY: default

%::
	make -C $(KDIR) M=$(PWD) $@
