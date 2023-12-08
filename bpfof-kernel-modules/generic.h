#ifndef _GENERIC_H
#define _GENERIC_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/fdtable.h>

extern char *MODULE_NAME;

void set_module_name(char *module_name);

struct filename_node {
    char *filename;
    struct list_head list;
};

int kern_readdir(char *pathname, bool *more_files_remaining,
                 struct list_head *filename_list);
void free_filename_list(struct list_head *filename_list);
int path_join(char *dir, char *file, char *res);

static inline struct inode *lookup_inode_from_fd_rcu(struct files_struct *files,
                                        unsigned int fd) {
    struct inode *inode = NULL;
    struct file *file;
    struct fdtable *fdt = rcu_dereference(files->fdt);
    if (fdt == NULL) {
        pr_warn("%s: No fdtable found.\n", MODULE_NAME);
        goto unlock;
    }
    if (fd < fdt->max_fds) {
        fd = array_index_nospec(fd, fdt->max_fds);
        file = rcu_dereference(fdt->fd[fd]);
    }
    if (file == NULL) {
        pr_warn("%s: No file found for fd: %u\n", MODULE_NAME, fd);
        goto unlock;
    }
    inode = file->f_inode;
unlock:
    return inode;
}

#endif /* _GENERIC_H */
