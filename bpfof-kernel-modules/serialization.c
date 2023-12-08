#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/rbtree_augmented.h>
#include <linux/rcupdate.h>

#include "generic.h"
#include "serialization.h"
#include "xrp_metadata_target_main.h"

/////////////////
// Helper Code //
/////////////////

// print_xrp_es_tree MUST be called with the rcu lock held!
void print_xrp_es_tree(struct rb_root *root) {
    struct rb_node *node;
    unsigned long num_extents = 0;
    pr_debug("xrp extent tree: (sizeof(struct xrp_extent)=%ld)\n",
           sizeof(struct xrp_extent));
    if (!root) goto out;
    node = rb_first(root);
    while (node) {
        struct xrp_extent *i_extent;
        i_extent = rb_entry(node, struct xrp_extent, rb_node);
        pr_debug("  [%u, %u): %llu\n", i_extent->lblk,
               i_extent->lblk + i_extent->len, i_extent->pblk);
        ++num_extents;
        node = rb_next(node);
    }
out:
    pr_debug("  total number of extents: %lu\n", num_extents);
}

struct stack_node {
    struct list_head list;
    struct xrp_extent *data;
};

static struct stack_node *stack_init(void) {
    struct stack_node *stack = kmalloc(sizeof(struct stack_node), GFP_NOIO);
    INIT_LIST_HEAD(&stack->list);
    return stack;
}

static bool stack_empty(struct stack_node *stack) {
    return list_empty(&stack->list);
}

static void stack_insert(struct stack_node *stack, struct xrp_extent *data) {
    struct stack_node *new_node = kmalloc(sizeof(struct stack_node), GFP_NOIO);
    new_node->data = data;
    list_add(&new_node->list, &stack->list);
}

static struct xrp_extent *stack_pop(struct stack_node *stack) {
    struct xrp_extent *data;
    if (list_empty(&stack->list)) {
        return NULL;
    }
    struct stack_node *elem = list_first_entry(&stack->list, struct stack_node,
                                               list);
    list_del(&elem->list);
    data = elem->data;
    kfree(elem);
    return data;
}

static void stack_free(struct stack_node *stack, bool free_data) {
    while (!stack_empty(stack)) {
        struct xrp_extent *data = stack_pop(stack);
        if (free_data) kfree(data);
    }
    kfree(stack);
}

//////////////////////////////////////////
// Serialization - Deserialization code //
//////////////////////////////////////////

void nvmeof_xrp_rcu_free(struct rcu_head *head) {
    // All we need to do is free the large buffer containing all nodes.
    // We do this by getting the root node and then freeing it.
    struct xrp_root *xrp_root = container_of(head, struct xrp_root, rcu_head);
    struct xrp_extent *es_root = container_of(xrp_root->rb_root.rb_node,
                                              struct xrp_extent, rb_node);
    kfree(es_root);
}

static int xrp_es_serialize_node(struct xrp_extent *es_node, char *buf,
                                 int max) {
    int len;

    len = sizeof(struct xrp_extent);
    if (max < len) {
        pr_warn("%s: Not enough space to serialize es_node\n", MODULE_NAME);
        return -1;
    }
    memcpy(buf, es_node, len);
    return len;
}

static struct xrp_extent *new_null_es_node(void) {
    struct xrp_extent *es_null;
    es_null = kmalloc(sizeof(struct xrp_extent), GFP_NOIO);
    es_null->lblk = -1;
    es_null->len = -1;
    es_null->pblk = -1;
    return es_null;
}

static bool is_null_es_node(struct xrp_extent *es_node) {
    if (es_node->lblk == -1 && es_node->pblk == -1 && es_node->len == -1) {
        return true;
    }
    return false;
}

int xrp_es_serialize(struct xrp_root *root, char **es_bytes) {
    int ret;
    int count;
    int buf_size;
    int bytes_written;

    struct xrp_extent *es_node, *tmp;

    // Count the number of nodes in the tree
    count = 0;
    rbtree_postorder_for_each_entry_safe(es_node, tmp, &root->rb_root,
                                         rb_node) {
        count++;
        if (es_node->rb_node.rb_right == NULL) count++;
        if (es_node->rb_node.rb_left == NULL) count++;
    }
    pr_debug("%s: es_tree count %d\n", MODULE_NAME, count);
    pr_debug("%s: size of single node %ld\n", MODULE_NAME,
            sizeof(struct xrp_extent));
    buf_size = count * sizeof(struct xrp_extent);
    // TODO: Do I need GFP_NOIO here?
    *es_bytes = kmalloc(buf_size, GFP_NOIO);

    // Traverse the binary tree using pre-order DFS.
    // Algorithm:
    // 1. Initialize stack with root node
    // 2. While stack is not empty:
    //   i.   Pop and process node.
    //   ii.  If null_node, continue to next iteration.
    //   iii. Insert right child or null_node.
    //   iv.  Insert left child or null_node.
    bytes_written = 0;
    struct stack_node *stack = stack_init();
    es_node = container_of(root->rb_root.rb_node, struct xrp_extent, rb_node);
    stack_insert(stack, es_node);
    while (!stack_empty(stack)) {
        es_node = stack_pop(stack);
        ret = xrp_es_serialize_node(es_node, *es_bytes + bytes_written,
                                    buf_size - bytes_written);
        if (ret < 0) {
            pr_err("%s: Failed to serialize tree\n", MODULE_NAME);
            stack_free(stack, false);
            kfree(*es_bytes);
            return -1;
        }
        bytes_written += ret;

        // Check if it's a null-node
        if (is_null_es_node(es_node)) {
            kfree(es_node);
            continue;
        }

        if (es_node->rb_node.rb_right != NULL) {
            tmp = container_of(es_node->rb_node.rb_right, struct xrp_extent,
                               rb_node);
            stack_insert(stack, tmp);
        } else {
            stack_insert(stack, new_null_es_node());
        }
        if (es_node->rb_node.rb_left != NULL) {
            tmp = container_of(es_node->rb_node.rb_left, struct xrp_extent,
                               rb_node);
            stack_insert(stack, tmp);
        } else {
            stack_insert(stack, new_null_es_node());
        }
    }
    return bytes_written;
}

static int xrp_es_deserialize_node(char *es_bytes, int *pos, int max,
                                   struct xrp_extent **es_node) {
    if (*pos + sizeof(struct xrp_extent) > max) {
        pr_err("%s: Not enough room in buffer to parse es_node! Pos: %d\n",
               MODULE_NAME, *pos);
        return -1;
    }
    *es_node = (struct xrp_extent *)(es_bytes + *pos);
    *pos += sizeof(struct xrp_extent);
    return 0;
}

int xrp_es_deserialize(char *es_bytes, int len, struct xrp_root *root) {
    // Given the list of nodes in pre-order, construct the extent-status
    // tree.
    // Algorithm:
    // 1. Initialize stack of items that need a right child.
    // 2. Initialize parent to first item of list.
    // 3. While list is not empty:
    //   i.  Read new node.
    //   ii.  If parent is not null_node:
    //        - Connect new node as left child of parent. If new node is
    //          null_node, replace with NULL.
    //        - Add parent to stack of nodes that need a right child.
    //   iii. Else, if parent is null_node:
    // 		  - Pop an item from the stack and assign it to parent.
    //        - Connect new node as right child of parent. If new node is
    //			null_node, replace with NULL.
    //   iv.  parent <- new node
    int pos;
    int ret;
    struct xrp_extent *parent;
    struct xrp_extent *new_node;
    struct stack_node *needs_right_child;

    if (len % sizeof(struct xrp_extent) != 0) {
        pr_err("%s: Given bytes are not a multiple of es_node struct size!\n",
               MODULE_NAME);
        return -1;
    }
    needs_right_child = stack_init();

    ret = xrp_es_deserialize_node(es_bytes, &pos, len, &parent);
    if (ret) {
        goto err;
    }
    rb_set_parent(&parent->rb_node, NULL);

    root->rb_root.rb_node = &parent->rb_node;
    while (pos != len) {
        ret = xrp_es_deserialize_node(es_bytes, &pos, len, &new_node);
        if (ret) {
            goto err;
        }
        if (!is_null_es_node(parent)) {
            if (is_null_es_node(new_node)) {
                parent->rb_node.rb_left = NULL;
            } else {
                parent->rb_node.rb_left = &new_node->rb_node;
                rb_set_parent(&new_node->rb_node, &parent->rb_node);
            }
            stack_insert(needs_right_child, parent);
        } else {
            BUG_ON(stack_empty(needs_right_child));
            parent = stack_pop(needs_right_child);
            if (is_null_es_node(new_node)) {
                parent->rb_node.rb_right = NULL;
            } else {
                parent->rb_node.rb_right = &new_node->rb_node;
                rb_set_parent(&new_node->rb_node, &parent->rb_node);
            }
        }
        parent = new_node;
    }
    BUG_ON(!stack_empty(needs_right_child));
    stack_free(needs_right_child, false);
    return 0;
err:
    stack_free(needs_right_child, false);
    return -1;
}

/////////////////////////////////////////////////////
// File descriptor <-> inode mapping serialization //
/////////////////////////////////////////////////////

static int empty_inode = -1234;


void bpfof_free_fdtable_serialization(
    struct bpfof_fdtable_serialization *fdtable_serialization) {
    kfree(fdtable_serialization->buf);
    kfree(fdtable_serialization);
}

// int bpfof_deserialize_fdtable(
//     struct bpfof_fdtable_serialization *fdtable_serialization,
//     struct fdtable **fdt) {
//     int ret;
//     if (!(fdtable_serialization->buf_size % sizeof(u32) == 0)) {
//         pr_err("%s: Given bytes are not a multiple of u32 size!\n",
//                MODULE_NAME);
//         return -1;
//     }
//     int fdt_size = fdtable_serialization->buf_size / sizeof(u32);
//     *fdt = alloc_fdtable(fdt_size);
//     if (!*fdt) {
//         pr_err("%s: Failed to allocate fdtable!\n", MODULE_NAME);
//         return ENOMEM;
//     }
//     int idx;
//     struct mapping *mapping;
//     for (idx = 0; idx < fdt_size; idx++) {
//         u32 inode_num = le32_to_cpu(((u32 *)fdtable_serialization->buf)[idx]);
//         if (inode_num == empty_inode) {
//             (*fdt)->fd[idx] = NULL;
//         } else {
//             struct file *file = kmalloc(sizeof(struct file), GFP_KERNEL);
//             if (!file) {
//                 pr_err("%s: Failed to allocate file struct!\n", MODULE_NAME);
//                 return ENOMEM;
//             }
//             // TODO: Lookup the inode in the inode map we keep
//             BUG_ON(inode_num < 0);
//             mapping = get_mapping_locked(inode_num);
//             if (!mapping) {
//                 pr_err("%s: Failed to find inode %d in inode map!\n",
//                        MODULE_NAME, inode_num);
//                 ret = -1;
//                 goto err;
//             }

//             file->f_inode = mapping->xrp_inode;
//             (*fdt)->fd[idx] = file;
//         }
//     }
//     return 0;
// err:
//     __free_fdtable(*fdt);
//     return ret;
// }

static void sprintf_pos(char *buf, int *pos, int len, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int ret = vsnprintf(buf + *pos, len - *pos, fmt, args);
    BUG_ON(ret < 0);
    *pos += ret;
    va_end(args);
}


void print_fdtable(struct files_struct *files) {
    struct fdtable *fdt;
    if (!files) {
        pr_err("%s: No files struct for current process!\n", MODULE_NAME);
        return;
    }
    spin_lock(&files->file_lock);
    fdt = files_fdtable(files);
    int idx;
    pr_debug("%s: Start printing fdtable...\n", MODULE_NAME);
    int msg_idx = 0;
    int msg_size = fdt->max_fds * 40;
    char *msg = kmalloc(msg_size, GFP_KERNEL);
    sprintf_pos(msg, &msg_idx, msg_size, "[");
    for (idx = 0; idx < fdt->max_fds; idx++) {
        struct file *file;
        sprintf_pos(msg, &msg_idx, msg_size, "%d: ", idx);
        file = rcu_dereference_check_fdtable(files, fdt->fd[idx]);
        if (file == NULL) {
            sprintf_pos(msg, &msg_idx, msg_size, "NULL,");
        } else if (file->f_inode == NULL) {
            sprintf_pos(msg, &msg_idx, msg_size, "NULL_INODE,");
        } else {
            sprintf_pos(msg, &msg_idx, msg_size, "%lu,", file->f_inode->i_ino);
        }
    }
    spin_unlock(&files->file_lock);
    sprintf_pos(msg, &msg_idx, msg_size, "]\n");
    pr_debug("%s", msg);
    kfree(msg);
    pr_debug("%s: End printing fdtable...\n", MODULE_NAME);
}

static int max_nonnull_fd(struct fdtable *fdt) {
    int idx;
    for (idx = fdt->max_fds - 1; idx >= 0; idx--) {
        if (fdt->fd[idx] != NULL) {
            return idx+1;
        }
    }
    return 1;
}

int bpfof_serialize_fdtable(struct files_struct *files,
    struct bpfof_fdtable_serialization **fdtable_serialization,
    int lock_file_inode) {

    int ret;
    int old_max_fds, max_fds;
    struct fdtable *fdt;
    if (!files) {
        pr_err("%s: No files struct for current process!\n", MODULE_NAME);
        return -1;
    }
    spin_lock(&files->file_lock);
    old_max_fds = max_nonnull_fd(files_fdtable(files));
    spin_unlock(&files->file_lock);

    *fdtable_serialization = kmalloc(sizeof(struct bpfof_fdtable_serialization),
                                     GFP_KERNEL);
    if (!*fdtable_serialization) {
        pr_err("%s: Failed to allocate memory for fdtable serialization!\n",
               MODULE_NAME);
        BUG();
        return ENOMEM;
    }
    (*fdtable_serialization)->buf_size = old_max_fds * sizeof(u32);
    (*fdtable_serialization)->buf = kmalloc((*fdtable_serialization)->buf_size,
                                            GFP_KERNEL);
    if (!(*fdtable_serialization)->buf) {
        pr_err("%s: Failed to allocate memory for fdtable serialization!\n",
               MODULE_NAME);
        ret = ENOMEM;
        goto err;
    }
    // Iterate through all file descriptors and serialize them.
    // The serialized format is:
    // <inode: 4 bytes><inode: 4 bytes><inode: 4 bytes>...
    // The file descriptor is implied by the positioning in the string.
    spin_lock(&files->file_lock);
    fdt = files_fdtable(files);
    max_fds = max_nonnull_fd(fdt);
    if (old_max_fds < max_fds) {
        pr_warn("%s: max_fds changed! Need to try again!\n", MODULE_NAME);
        ret = EAGAIN;
        goto err_unlock;
    }
    int idx;
    u32 value_to_serialize;
    for (idx = 0; idx < max_fds; idx++) {
        struct file *file;
        file = rcu_dereference_check_fdtable(files, fdt->fd[idx]);
        if (!file || !file->f_inode || !S_ISREG(file->f_inode->i_mode) || file->f_inode->i_ino == lock_file_inode) {
            value_to_serialize = cpu_to_le32(empty_inode);
        } else {
            struct rb_root *xrp_rb_root = rcu_dereference(file->f_inode->xrp_extent_root);
            if (!xrp_rb_root || RB_EMPTY_ROOT(xrp_rb_root)) {
                pr_debug("%s: Inode %lu at fd %d has no extents, not including in synced fdtable\n", MODULE_NAME, file->f_inode->i_ino, idx);
                value_to_serialize = cpu_to_le32(empty_inode);
            } else {
                value_to_serialize = cpu_to_le32(file->f_inode->i_ino);
            }
        }
        memcpy((*fdtable_serialization)->buf + idx * sizeof(u32),
               &value_to_serialize, sizeof(u32));
    }
    spin_unlock(&files->file_lock);
    return 0;
err_unlock:
    spin_unlock(&files->file_lock);
err:
    bpfof_free_fdtable_serialization(*fdtable_serialization);
    return ret;
}
