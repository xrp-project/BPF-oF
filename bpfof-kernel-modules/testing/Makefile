LLC ?= llc
CLANG ?= clang
CC ?= gcc

# BPF_CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/
BPF_CFLAGS ?= -I/usr/include/ -I/usr/local/include/bpf

all: simple_xrp_hugepage.o simple_xrp.o simple_xrp.out xrp_loader.out

random_reader.out: random_reader.c
	$(CLANG) \
	-Wall \
	-O2 \
	-o random_reader.out random_reader.c -lpthread


xrp_loader.out: xrp_loader.c
	$(CLANG) \
	$(BPF_CFLAGS) \
	-Wall \
	-O2 \
	-Wl,-rpath,/usr/local/lib64 \
	-o xrp_loader.out xrp_loader.c -lbpf


simple_xrp.out: simple_xrp.c
	$(CLANG) \
	$(BPF_CFLAGS) \
	-Wall \
	-O2 \
	-Wl,-rpath,/usr/local/lib64 \
	-o simple_xrp.out simple_xrp.c

simple_read_bpfof.out: simple_read_bpfof.c
	$(CLANG) \
	$(BPF_CFLAGS) \
	-Wall \
	-O2 \
	-Wl,-rpath,/usr/local/lib64 \
	-o simple_read_bpfof.out simple_read_bpfof.c

simple_xrp.o: simple_xrp.bpf.c

simple_xrp_hugepage.o: simple_xrp_hugepage.bpf.c

%.o: %.bpf.c
	$(CLANG) -S \
		-target bpf \
		-D __BPF_TRACING__ \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}


.PHONY: clean
clean:
	rm -rf *.o *.out
