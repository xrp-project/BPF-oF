#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define BLOCK_SIZE 4096

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <filename> <offset> <length>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *filename = argv[1];
    off_t offset = strtoll(argv[2], NULL, 10);
    size_t length = strtoul(argv[3], NULL, 10);

    // Open the file with O_DIRECT flag
    int fd = open(filename, O_RDONLY | O_DIRECT);
    if (fd < 0) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    // Allocate aligned buffer
    void *buffer;
    length = length / BLOCK_SIZE * BLOCK_SIZE + BLOCK_SIZE;
    if (posix_memalign(&buffer, BLOCK_SIZE, length) != 0) {
        perror("Error allocating aligned buffer");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Perform direct I/O read
    ssize_t read_bytes = pread(fd, buffer, length, offset);
    if (read_bytes < 0) {
        perror("Error reading file");
        free(buffer);
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Clean up
    free(buffer);
    close(fd);

    return 0;
}
