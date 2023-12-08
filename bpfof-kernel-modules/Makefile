obj-m += xrp_metadata_host.o
obj-m += xrp_metadata_target.o

ccflags-y += -Wno-declaration-after-statement

xrp_metadata_host-y += xrp_metadata_host_main.o serialization.o sync_proto.o kern_tcp.o generic.o
xrp_metadata_target-y += xrp_metadata_target_main.o serialization.o sync_proto.o kern_tcp.o generic.o

# Needed to work with sudo.
PWD := $(CURDIR)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean