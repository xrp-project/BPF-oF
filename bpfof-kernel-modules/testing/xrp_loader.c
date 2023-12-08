#include <stdio.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

int main(int argc, char *argv[]) {
    int ret;
    int progfd;
    char *prog_path, *bpf_fs_path;
    struct bpf_object *obj;
    // struct bpf_program *xrp_prog;

    if (argc != 3) {
        printf("USAGE: xrp_loader [BPF_PROGRAM.o] [BPF_FS_PATH]\n");
        return -1;
    }
    prog_path = argv[1];
    bpf_fs_path = argv[2];
    printf("Loading program: %s\n", prog_path);
    ret = bpf_prog_load(prog_path, BPF_PROG_TYPE_XRP, &obj, &progfd);
    if (ret) {
        printf("Error loading XRP BPF program. Error code: %d\n", ret);
        return -1;
    }
    // xrp_prog = bpf_object__find_program_by_name(obj, "xrp_prog");
    // if (xrp_prog == NULL) {
    //     printf("ERROR: Didn't find program section named 'xrp_prog' in %s\n",
    //            prog_path);
    //     return -1;
    // }
    printf("Pinning program to '%s'\n", bpf_fs_path);
    ret = bpf_object__pin(obj, bpf_fs_path);
    if (ret) {
        printf("ERROR: Failed to pin BPF program '%s' to '%s'", prog_path,
               bpf_fs_path);
        return ret;
    }
    return 0;
}