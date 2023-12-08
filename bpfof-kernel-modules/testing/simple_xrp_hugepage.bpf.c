/*
 * BPF program for simple-kv
 *
 * Author: etm2131@columbia.edu
 */
#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>

#define BLK_SIZE 512
#define HUGE_PAGE_SIZE 2 * 1024 * 1024

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

SEC("xrp_prog")
unsigned int simple_xrp_func(struct bpf_xrp *context) {
    __u8 iteration;
    iteration = context->scratch[0];
    context->fd_arr[0] = context->cur_fd;
    bpf_printk("Iteration '%hu', printing first bytes: %x %x ...\n", iteration,
               context->data[0], context->data[1]);
    bpf_printk("first scratch buffer bytes: %x %x %x\n", context->scratch[0], context->scratch[1], context->scratch[2]);
    if (iteration == 0) {
        context->next_addr[0] = BLK_SIZE;
        context->size[0] = BLK_SIZE *3;
        bpf_printk("Iteration=0\n");
        bpf_printk("0: first bytes from context->data: %x %x %x\n", context->data[0], context->data[1], context->data[2]);
        context->scratch[0]++;
        return 0;
    } else if (iteration == 1) {
        // Read and resubmit
        context->next_addr[0] = BLK_SIZE + HUGE_PAGE_SIZE;
        context->size[0] = HUGE_PAGE_SIZE; // 2mb
        context->scratch[0]++;
        bpf_printk("Iteration=1\n");
        bpf_printk("1: first bytes from context->data: %x %x %x\n", context->data[0], context->data[1], context->data[2]);
        return 0;
    } else if (iteration >= 2) {
        // Read and stop
        bpf_printk("Iteration=2\n");
        bpf_printk("2: first bytes from context->data: %x %x %x\n", context->data[0], context->data[1], context->data[2]);
        bpf_printk("2: last bytes from context->data: %x %x %x\n", context->data[1024], context->data[1025], context->data[1026]);
        memcpy(context->scratch+1, context->data, BLK_SIZE);
        context->done = 1;
        context->next_addr[0] = 0;
        context->size[0] = 0;
        return 0;
    } else {
        bpf_printk("ERROR: We should never enter this!\n");
        return -1;
    }
}

char LICENSE[] SEC("license") = "GPL";
