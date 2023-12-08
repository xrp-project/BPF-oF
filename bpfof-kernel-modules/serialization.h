#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/nvme.h>

struct bpfof_fdtable_serialization {
    char *buf;
    int buf_size;
};

// struct bpfof_fd_info {
//     uint32_t fd;
//     uint32_t inode_identifier;
// } __attribute__((__packed__));

void print_xrp_es_tree(struct rb_root *root);
void print_xrp_es_tree(struct rb_root *root);
void nvmeof_xrp_rcu_free(struct rcu_head *head);
int xrp_es_serialize(struct xrp_root *root, char **es_bytes);
int xrp_es_deserialize(char *es_bytes, int len, struct xrp_root *root);
// int bpfof_deserialize_fdtable(
//     struct bpfof_fdtable_serialization *fdtable_serialization,
//     struct fdtable **fdt);
// int bpfof_serialize_fdtable(struct files_struct *files,
//     struct bpfof_fdtable_serialization **fdtable_serialization, int lock_file_inode);
// void bpfof_free_fdtable_serialization(
//     struct bpfof_fdtable_serialization *fdtable_serialization);
void print_fdtable(struct files_struct *files);