#include "generic.h"
#include <linux/namei.h>
#include <linux/slab.h>

char *MODULE_NAME;

void set_module_name(char *module_name) { MODULE_NAME = module_name; }

#define MAX_FILENAME_LEN 256
#define MAX_FILES 10000

struct kern_list_dir_callback {
    struct dir_context ctx;
    struct list_head *filename_list;
    char *root_dir;
    int max_files;
    bool more_files_remaining;
};

static int kern_filldir(struct dir_context *ctx, const char *name, int namlen,
                        loff_t offset, u64 ino, unsigned int d_type) {
    struct kern_list_dir_callback *cb = container_of(
        ctx, struct kern_list_dir_callback, ctx);
    if (cb->max_files <= 0) {
        pr_err("%s: too many files in directory: %s\n", MODULE_NAME,
               cb->root_dir);
        cb->more_files_remaining = true;
        return -1;
    }
    cb->max_files--;
    if (namlen > MAX_FILENAME_LEN) {
        pr_err("%s: filename too long: '%.*s'\n", MODULE_NAME, namlen, name);
        return -1;
    }
    if (d_type != DT_REG) {
        pr_info("%s: '%.*s' is not a regular file\n", MODULE_NAME, namlen,
                name);
        return 0;
    }
    pr_info("%s: found file: '%.*s'\n", MODULE_NAME, namlen, name);
    struct filename_node *node = kmalloc(sizeof(struct filename_node),
                                         GFP_KERNEL);
    if (unlikely(!node)) return ENOMEM;
    node->filename = kmalloc(namlen + 1, GFP_KERNEL);
    if (unlikely(!node->filename)) return ENOMEM;
    memcpy(node->filename, name, namlen);
    node->filename[namlen] = '\0';
    list_add(&node->list, cb->filename_list);
    return 0;
}

/**
 * kern_readdir - Read the files of a directory into a list.
 *
 * @pathname:              The path of the directory to read
 * @more_files_remaining:  Set to true if the directory contains more files.
 *                         User-provided.
 * @filename_list:         The list to populate with filenames. User-provided.
 */
int kern_readdir(char *pathname, bool *more_files_remaining,
                 struct list_head *filename_list) {
    int ret;
    struct path path;

    ret = kern_path(pathname, LOOKUP_FOLLOW, &path);
    if (ret) {
        pr_err("%s: kern_path() failed: %d\n", MODULE_NAME, ret);
        return -1;
    }
    // Confirm that the path is a directory
    if (!d_is_dir(path.dentry)) {
        pr_err("%s: %s is not a directory\n", MODULE_NAME, pathname);
        ret = -1;
        goto path_release;
    }

    // Iterate over the directory's children
    struct file *file;
    struct kern_list_dir_callback cb = {
        .ctx.actor = kern_filldir,
        .root_dir = pathname,
        .max_files = MAX_FILES,
        .more_files_remaining = false,
        .filename_list = filename_list,
    };
    file = filp_open(pathname, O_DIRECTORY, 0);
    if (IS_ERR(file)) {
        pr_err("%s: filp_open() failed: %ld\n", MODULE_NAME, PTR_ERR(file));
        ret = -1;
        goto path_release;
    }
    ret = iterate_dir(file, &cb.ctx);
    if (ret) {
        pr_err("%s: iterate_dir() failed: %d\n", MODULE_NAME, ret);
        ret = -1;
        free_filename_list(filename_list);
        goto file_release;
    }
    *more_files_remaining = cb.more_files_remaining;

file_release:
    filp_close(file, NULL);
path_release:
    path_put(&path);
    return ret;
}

void free_filename_list(struct list_head *filename_list) {
    struct filename_node *node;
    while (!list_empty(filename_list)) {
        node = list_first_entry(filename_list, struct filename_node, list);
        list_del(&node->list);
        kfree(node->filename);
        kfree(node);
    }
}

// This is a naive implementation of path_join.
// It assumes that res is large enough to hold the result.
int path_join(char *dir, char *file, char *res) {
    BUG_ON(strlen(dir) + strlen(file) + 1 > PATH_MAX);
    if (dir[strlen(dir) - 1] == '/') {
        sprintf(res, "%s%s", dir, file);
    } else {
        sprintf(res, "%s/%s", dir, file);
    }
    return 0;
}