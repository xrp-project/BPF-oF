#define _GNU_SOURCE // Needed for O_DIRECT

#include <time.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/file.h>
#include <sys/types.h>

#define SYS_READ_BPFOF 447
#define XRP_READ_IGNORE_BPF_FD   -1234
#define SCRATCH_SIZE 4096


int main(int argc, char **argv) {
    int ret;
    int file_offset;

    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    // Open the given filename
    int file_fd = open(argv[1], O_RDONLY | O_DIRECT);

    file_offset = 0;

    // Allocate a 4k-aligned scratch buffer
    char *scratch = aligned_alloc(4096, 4096);

    // Allocate a 4k-aligned data buffer
    char *data_buf = aligned_alloc(4096, 4096);

    // sleep(2);

    scratch[0] = 1;
    printf("First scratch bytes: %x %x %x %x\n", scratch[0], scratch[1], scratch[2], scratch[3]);
    printf("Last scratch bytes: %x %x %x %x\n", scratch[509], scratch[510], scratch[511], scratch[512]);

    // bpf_fd is invalid. The request will be sent over the network, so it's
    // not needed.
    // TODO: We don't really need the data buffer either!
    bool printed_success = false;
    struct timespec start_time, end_time;
    sleep(2);
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    for (int i = 0; i < 1; i++) {
        // memset(scratch, 0x0, 512);
        unsigned int fds[10];
        fds[0] = file_fd;
        size_t data_buffer_count = 512;
        ret = syscall(SYS_READ_BPFOF, fds, 1, data_buffer_count,
                      file_offset, scratch, SCRATCH_SIZE);
        if (ret >= 0 && !printed_success){
            printf("Success at i=%d!\n", i);
            printed_success = true;
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            long elapsed_ns = (end_time.tv_sec - start_time.tv_sec) * 1000000000 + (end_time.tv_nsec - start_time.tv_nsec);
            printf("Elapsed time: %ld ns\n", elapsed_ns);
        }
    }
    if (ret < 0) {
        perror("read_xrp");
        return 1;
    }

    // Print first and last 4 bytes of the scratch buffer
    printf("First scratch bytes: %x %x %x %x\n", scratch[0], scratch[1], scratch[2], scratch[3]);
    printf("Last scratch bytes: %x %x %x %x\n", scratch[509], scratch[510], scratch[511], scratch[512]);

    printf("First data bytes: %x %x %x %x\n", data_buf[0], data_buf[1], data_buf[2], data_buf[3]);
    printf("Last data bytes: %x %x %x %x\n", data_buf[509], data_buf[510], data_buf[511], data_buf[512]);

    close(file_fd);
    return 0;
}
