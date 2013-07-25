CC       = gcc

CFLAGS   += -Wall
CFLAGS   += -Werror
CFLAGS   += -O3
#CFLAGS   += $(INCLUDES) -I.
CFLAGS   += -Wp,-MD,.$(@F).d
#LDFLAGS  += -L. -L../libxa/
DEPS     = .*.d
LIBS     = -lxenctrl -lvmi -lm

#all: kern_sym virt_addr user_virt_addr-linux user_virt_addr-windows read_mem
all: kern_sym virt_addr read_mem

clean:
	rm -rf *.a *.o *~ $(DEPS) kern_sym virt_addr user_virt_addr-linux user_virt_addr-windows read_mem

kern_sym: kern_sym.c common.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^  $(LIBS)

virt_addr: virt_addr.c common.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

user_virt_addr-linux: user_virt_addr-linux.c common.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

user_virt_addr-windows: user_virt_addr-windows.c common.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

read_mem: read_mem.c common.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

-include $(DEPS)
