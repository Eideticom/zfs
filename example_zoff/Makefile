ZFS = $(realpath $(PWD)/..)
KBUILD_EXTRA_SYMBOLS = $(ZFS)/module/Module.symvers
TARGET = example_zoff

obj-m += $(TARGET).o
$(TARGET)-objs := example_zoff_provider.o kernel_offloader.o raidz.o disk.o

ccflags-y=-std=gnu99 -Wno-declaration-after-statement -g3 -I$(PWD) -I$(ZFS) -I$(ZFS)/include -I$(ZFS)/include/os/linux/spl -I$(ZFS)/include/os/linux/kernel -I$(ZFS)/include/os/linux/zfs -DZOFF=1 -D_KERNEL

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
