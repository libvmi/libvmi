obj-m +=findoffsets.o

# Use "make KERNEL=</path/to/target/kernel/src>" to override this
KERNEL=/lib/modules/$(shell uname -r)/build

all:
	make -C $(KERNEL) M=$(PWD) modules -lcsys

clean:
	make -C $(KERNEL) M=$(PWD) clean
