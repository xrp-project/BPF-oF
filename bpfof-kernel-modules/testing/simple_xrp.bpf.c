/*
 * BPF program for simple-kv
 *
 * Author: etm2131@columbia.edu
 */
#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>

#define BLK_SIZE 512
#define SCRATCH_SIZE 4096
#define XRP_MULTI_FILE 1

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

SEC("xrp_prog")
unsigned int simple_xrp_func(struct bpf_xrp *context) {
    #ifdef XRP_MULTI_FILE
    bpf_printk("XRP_MULTI_FILE is defined\n");
    context->fd_arr[0] = context->cur_fd;
    #endif
    __u8 iteration;
    iteration = context->scratch[0];
    bpf_printk("Iteration '%hu', printing first bytes: %x %x ...\n", iteration,
               context->data[0], context->data[1]);
    if (iteration == 0) {
        context->next_addr[0] = BLK_SIZE;
        context->size[0] = BLK_SIZE;
        context->scratch[0]++;
        return 0;
    } else if (iteration == 1) {
        // Read and resubmit
        context->next_addr[0] = BLK_SIZE * 2;
        context->size[0] = BLK_SIZE;
        context->scratch[0]++;
        return 0;
    } else if (iteration >= 2) {
        // Read and stop
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
