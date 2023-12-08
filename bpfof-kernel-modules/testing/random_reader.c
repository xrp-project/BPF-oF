#define _GNU_SOURCE  // Needed for O_DIRECT

#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <pthread.h>

#define aligned_alloca(align, size)                          \
    (((uintptr_t)alloca((size) + (align)-1) + ((align)-1)) & \
     ~(uintptr_t)((align)-1));

#define LEVELS 7

// struct to hold the arguments to each thread
struct WorkerArgs {
    int file_fd;
    int file_size;
    int thread_id;
    int *offsets;
};

int do_pread(int file_fd, size_t count, off_t file_offset) {
    char *data = (char *)aligned_alloca(512, 512);
    return pread(file_fd, data, 512, file_offset);
}

void *worker(void *args) {
    int ret;
    int file_offset;
    struct WorkerArgs *worker_args = (struct WorkerArgs *)args;
    int file_fd = worker_args->file_fd;
    int file_size = worker_args->file_size;
    int thread_id = worker_args->thread_id;
    int *offsets = worker_args->offsets;

    while (true) {
        for (int i = 0; i < LEVELS; i++) {
            // Read 512 bytes from the file
            // ret = pread(file_fd, data, 512, file_offset);
            ret = do_pread(file_fd, 512, offsets[i]);

            if (ret != 512) {
                perror("Error reading file");
                exit(1);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    int ret;
    int file_size;
    int num_threads;
    struct stat file_stat;
    char *USAGE = "random_reader.out FILE NUM_THREADS\n";

    // Check that we got exactly 2 arguments
    if (argc != 3) {
        printf("%s", USAGE);
        exit(1);
    }

    // Open the given filename with O_DIRECT
    int file_fd = open(argv[1], O_RDONLY | O_DIRECT);

    // Get the size of the file
    ret = fstat(file_fd, &file_stat);
    if (ret) {
        perror("Error getting file size");
        exit(1);
    }
    file_size = file_stat.st_size;

    // Start threads
    num_threads = atoi(argv[2]);
    pthread_t tids[num_threads];
    struct WorkerArgs worker_args_arr[num_threads];
    printf("Starting %d threads\n", num_threads);

    int offsets[LEVELS];
    unsigned int seed = 1;
    for (int i = 0; i < LEVELS; i++) {
        offsets[i] = rand_r(&seed) % file_size;
        offsets[i] = offsets[i] & ~(512 - 1);
    }

    for (int i = 0; i < num_threads; i++) {
        worker_args_arr[i].file_fd = file_fd;
        worker_args_arr[i].file_size = file_size;
        worker_args_arr[i].thread_id = i;
        worker_args_arr[i].offsets = offsets;
        pthread_create(&tids[i], NULL, worker, (void *)&worker_args_arr[i]);
    }

    // Wait for threads to finish
    for (int i = 0; i < num_threads; i++) {
        pthread_join(tids[i], NULL);
    }
}