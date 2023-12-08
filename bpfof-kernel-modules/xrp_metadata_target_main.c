#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/namei.h>
#include <linux/nospec.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/wait.h>
#include <linux/blk_types.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <net/inet_connection_sock.h>
#include <net/request_sock.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <linux/bpf.h>

#include "generic.h"
#include "kern_tcp.h"
#include "serialization.h"
#include "sync_proto.h"
#include "xrp_metadata_target_main.h"

static int port = 31000;
module_param(port, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(port, "TCP port that the XRP metadata target listens on.");

static bool testing_mode;
module_param(testing_mode, bool, false);
MODULE_PARM_DESC(testing_mode,
                 "Testing mode enables the ping-pong server to test the code.");

static char *bpf_pathname = "/sys/fs/bpf/simple_xrp/xrp_prog";
module_param(bpf_pathname, charp, 0000);
MODULE_PARM_DESC(bpf_pathname, "Pathname to pinned XRP program to use.");

static bool use_hugepages;
module_param(use_hugepages, bool, false);
MODULE_PARM_DESC(use_hugepages,
                 "Use hugepages (2MB) for the XRP data buffer.");

struct xrp_metadata_server {
    struct socket *listen_socket;
    struct task_struct *listen_thread;
    DECLARE_HASHTABLE(mappings, 8);  // 256 buckets
    rwlock_t mappings_lock;
    struct bpf_prog *xrp_prog;
    struct files_struct *files;
    bool listener_stopped;
};

struct xrp_metadata_server *server;

////////////////////////////////////
// Helpers to manipulate mappings //
////////////////////////////////////

void free_mapping_list(void) {
    int i;
    struct hlist_node *tmp;
    struct mapping *mapping;
    struct xrp_root *xrp_root;

    // Delete all hashtable entries
    hash_for_each_safe(server->mappings, i, tmp, mapping, hash_list) {
        hash_del(&mapping->hash_list);
        xrp_root = container_of(mapping->xrp_inode->xrp_extent_root,
                                struct xrp_root, rb_root);
        kfree(xrp_root);
        kfree(mapping->xrp_inode);
        kfree(mapping);
    }
}

// insert_mapping must be called with the mappings_lock held.
static void insert_mapping(struct mapping *mapping) {
    hash_add(server->mappings, &mapping->hash_list, mapping->id);
}

// get_mapping must be called with the mappings_lock held.
// TODO: Search in list. Now get the first element.
struct mapping *get_mapping(uint32_t inode_identifier) {
    struct mapping *mapping;
    if (hash_empty(server->mappings)) {
        return NULL;
    }
    // Search for mapping with id inode_identifier
    hash_for_each_possible(server->mappings, mapping, hash_list,
                           inode_identifier) {
        if (mapping->id == inode_identifier) {
            return mapping;
        }
    }
    return NULL;
}

struct mapping *get_mapping_locked(uint32_t inode_identifier) {
    struct mapping *mapping;
    read_lock(&server->mappings_lock);
    mapping = get_mapping(inode_identifier);
    read_unlock(&server->mappings_lock);
    return mapping;
}

static int empty_inode = -1234;


int bpfof_deserialize_fdtable(
    struct bpfof_fdtable_serialization *fdtable_serialization,
    struct fdtable **fdt) {
    int ret;
    if (!(fdtable_serialization->buf_size % sizeof(u32) == 0)) {
        pr_err("%s: Given bytes are not a multiple of u32 size!\n",
               MODULE_NAME);
        return -1;
    }
    int fdt_size = fdtable_serialization->buf_size / sizeof(u32);
    *fdt = alloc_fdtable(fdt_size);
    if (!*fdt) {
        pr_err("%s: Failed to allocate fdtable!\n", MODULE_NAME);
        return ENOMEM;
    }
    int idx;
    struct mapping *mapping;
    for (idx = 0; idx < fdt_size; idx++) {
        u32 inode_num = le32_to_cpu(((u32 *)fdtable_serialization->buf)[idx]);
        // The first 3 fds are stdin, stdout, stderr
        if (idx <= 2){
            (*fdt)->fd[idx] = NULL;
            continue;
        }
        if (inode_num == empty_inode) {
            (*fdt)->fd[idx] = NULL;
        } else {
            struct file *file = kmalloc(sizeof(struct file), GFP_KERNEL);
            if (!file) {
                pr_err("%s: Failed to allocate file struct!\n", MODULE_NAME);
                return ENOMEM;
            }
            // TODO: Lookup the inode in the inode map we keep
            BUG_ON(inode_num < 0);
            mapping = get_mapping_locked(inode_num);
            if (!mapping) {
                pr_warn("%s: Failed to find inode %d in inode map!\n",
                       MODULE_NAME, inode_num);
                kfree(file);
                (*fdt)->fd[idx] = NULL;
                continue;
                // ret = -1;
                // goto err;
            }

            file->f_inode = mapping->xrp_inode;
            (*fdt)->fd[idx] = file;
            set_open_fd(idx, *fdt);
            get_file(file);
        }
    }
    return 0;
    __free_fdtable(*fdt);
    return ret;
}

//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////
// Functions exposed to NVME Driver //
//////////////////////////////////////

// The NVMEoF target calls into these functions to get the mappings.
extern int (*driver_get_nvmeof_xrp_info)(bool *xrp_enabled,
                                         struct bpf_prog **xrp_prog,
                                         struct bpfof_fd_info *bpfof_fd_info_arr,
                                         struct xrp_fd_info *xrp_fd_info_arr,
                                         size_t *xrp_fd_count);

// The NVMEoF target driver checks this variable to decide if it should use
// hugepages for the data buffer.
extern bool nvmeof_xrp_use_hugepages;

// We use this just for compatibility with XRP's existing interface.
extern const struct inode_operations ext4_file_inode_operations;

// TODO: Check if the block device has XRP enabled
// TODO: Add code to the NVMEoF target to set an inode_identifier field
// for each request, passed by the NVMEoF host.
int get_nvmeof_xrp_info(bool *xrp_enabled,
                        struct bpf_prog **xrp_prog,
                        struct bpfof_fd_info *bpfof_fd_info_arr,
                        struct xrp_fd_info *xrp_fd_info_arr,
                        size_t *xrp_fd_count) {
    int i;
    struct mapping *mapping;
    size_t fd_count = 0;
    read_lock(&server->mappings_lock);
    // For each fd, get the inode identifier and the XRP inode.
    for (i = 0; i < 10; i++) {
        if (bpfof_fd_info_arr[i].inode_identifier == 0) {
            break;
        }
        fd_count++;
        mapping = get_mapping(bpfof_fd_info_arr[i].inode_identifier);
        if (mapping == NULL) {
            read_unlock(&server->mappings_lock);
            pr_warn("%s: No mapping found for inode identifier: %u\n", MODULE_NAME,
                    bpfof_fd_info_arr[i].inode_identifier);
            *xrp_enabled = false;
            return 0;
        }
        xrp_fd_info_arr[i].fd = bpfof_fd_info_arr[i].fd;
        xrp_fd_info_arr[i].inode = mapping->xrp_inode;
    }
    read_unlock(&server->mappings_lock);
    pr_debug("%s: Got %lu fds\n", MODULE_NAME, fd_count);
    for (i = 0; i < fd_count; i++) {
        pr_debug("%s: fd: %d, inode: %lu\n", MODULE_NAME, bpfof_fd_info_arr[i].fd,
                xrp_fd_info_arr[i].inode->i_ino);
    }
    *xrp_prog = server->xrp_prog;
    *xrp_enabled = true;
    *xrp_fd_count = fd_count;
    return 0;
}

//////////////////////////////////////////////////////////////////////////////

int handle_setversion_request(struct socket *conn_socket,
                              struct setversion_request_header *hdr,
                              char *payload, int len) {
    int ret;
    struct mapping *mapping;
    struct rb_root *old_root;
    struct xrp_root *xrp_root, *old_xrp_root;

    pr_debug("%s: Received extent-status tree! Deserializing...\n", MODULE_NAME);
    xrp_root = kmalloc(sizeof(struct xrp_root), GFP_KERNEL);
    ret = xrp_es_deserialize(payload, len, xrp_root);
    print_xrp_es_tree(&xrp_root->rb_root);
    if (ret < 0) {
        pr_err("%s: Error deserializing extent status tree. Error code: %d",
               MODULE_NAME, ret);
        return ret;
    }

    // Get current mapping if it exists
    write_lock(&server->mappings_lock);
    mapping = get_mapping(hdr->inode_identifier);
    if (mapping == NULL) {
        // Mapping does not exist, create it.
        pr_debug("%s: Creating new mapping for id '%u'...\n", MODULE_NAME,
                hdr->inode_identifier);
        // TODO: Where do we free it?
        mapping = kmalloc(sizeof(struct mapping), GFP_KERNEL);
        mapping->id = hdr->inode_identifier;
        mapping->version = hdr->version;
        mapping->xrp_inode = kmalloc(sizeof(struct inode), GFP_KERNEL);
        spin_lock_init(&mapping->xrp_inode->xrp_extent_lock);
        mapping->xrp_inode->xrp_extent_root = &xrp_root->rb_root;
        mapping->xrp_inode->i_op = &ext4_file_inode_operations;
        mapping->xrp_inode->i_ino = hdr->inode_identifier;
        insert_mapping(mapping);
    } else {
        // Mapping exists, update it.
        // The structure we're updating uses RCU. Be extra careful!
        pr_debug("%s: Updating existing mapping for id '%u'...\n", MODULE_NAME,
                hdr->inode_identifier);
        spin_lock(&mapping->xrp_inode->xrp_extent_lock);
        old_root = mapping->xrp_inode->xrp_extent_root;
        old_xrp_root = container_of(old_root, struct xrp_root, rb_root);
        rcu_assign_pointer(mapping->xrp_inode->xrp_extent_root, xrp_root);
        call_rcu(&old_xrp_root->rcu_head, nvmeof_xrp_rcu_free);
        spin_unlock(&mapping->xrp_inode->xrp_extent_lock);
    }
    write_unlock(&server->mappings_lock);
    return 0;
}

int handle_setfdtable_request(struct socket *conn_socket,
                              struct setfdtable_request_header *hdr,
                              char *payload, int len) {
    int ret;
    struct fdtable *new_fdt, *old_fdt;
    struct bpfof_fdtable_serialization fdt_ser =
        {
            .buf = payload,
            .buf_size = len,
        };
    pr_debug("%s: Received fdtable! Deserializing...\n", MODULE_NAME);
    ret = bpfof_deserialize_fdtable(&fdt_ser, &new_fdt);
    if (ret < 0) {
        pr_err("%s: Error deserializing fdtable. Error code: %d", MODULE_NAME,
               ret);
        return ret;
    }
    pr_debug("%s: Replacing fdtable for current task!\n", MODULE_NAME);
    spin_lock(&server->files->file_lock);
    old_fdt = server->files->fdt;
    rcu_assign_pointer(server->files->fdt, new_fdt);
    if (old_fdt != NULL) {
        call_rcu(&old_fdt->rcu, free_fdtable_rcu);
    }
    spin_unlock(&server->files->file_lock);
    print_fdtable(server->files);
    return 0;
}

static int tcp_server_accept(struct socket **conn_socket) {
    int ret;

    // TODO: Check for signals!
    pr_info("%s: Accepting connection!", MODULE_NAME);
    // Blocking IO
    ret = kernel_accept(server->listen_socket, conn_socket, 0);
    if (ret) {
        pr_err("%s: Error %d while accepting connection", MODULE_NAME, ret);
        return -1;
    }

    // Get client info
    struct sockaddr_in sock_addr;
    ret = kernel_getpeername(*conn_socket, (struct sockaddr *)&sock_addr);
    if (ret < 0) {
        pr_err("%s: Error %d trying to get peer info", MODULE_NAME, ret);
        sock_release(*conn_socket);
        return -1;
    }
    char client_ip[16];
    inet_ntoa(&sock_addr.sin_addr, client_ip);
    pr_info("%s: Connected with client (%s, %d)", MODULE_NAME, client_ip,
            ntohs(sock_addr.sin_port));
    return 0;
}

static int tcp_server_listen(void) {
    int ret;
    struct socket *conn_socket;
    struct bpf_prog *xrp_prog;
    struct server_ops server_ops = {
        .handle_setversion_request = handle_setversion_request,
        .handle_setfdtable_request = handle_setfdtable_request,
    };

    // Create a TCP socket
    pr_info("%s: Starting TCP server!", MODULE_NAME);
    ret = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
                           &server->listen_socket);
    if (ret) {
        pr_err("%s: Error: %d while creating listen socket\n", MODULE_NAME,
               ret);
        goto err;
    }
    // Not needed right now, but let's set this anyway
    server->listen_socket->sk->sk_reuse = 1;
    // Disable Nagle's algorithm
    tcp_sock_set_nodelay(server->listen_socket->sk);

    // Bind socket
    struct sockaddr_in addr = {.sin_addr =
                                   {
                                       .s_addr = INADDR_ANY,
                                   },
                               .sin_family = AF_INET,
                               .sin_port = htons(port)};
    ret = kernel_bind(server->listen_socket, (struct sockaddr *)&addr,
                      sizeof(addr));
    if (ret) {
        pr_err("%s: Error: %d while binding socket to address", MODULE_NAME,
               ret);
        goto release;
    }

    // Start listening for connections
    ret = kernel_listen(server->listen_socket, 16);
    if (ret) {
        pr_err("%s: Error: %d while attempting to listen", MODULE_NAME, ret);
        goto release;
    }

    // Load BPF program
    pr_info("%s: Using BPF prog at pathname %s\n", MODULE_NAME, bpf_pathname);
    xrp_prog = bpf_prog_get_type_path(bpf_pathname, BPF_PROG_TYPE_XRP);
    if (IS_ERR(xrp_prog)) {
        pr_err("%s: Failed to get BPF prog at pathname: %s. Error code: %ld\n",
               MODULE_NAME, bpf_pathname, PTR_ERR(xrp_prog));
        goto release;
    }
    server->xrp_prog = xrp_prog;

    /////////////////
    // Server loop //
    /////////////////

    // We allow these signals
    allow_kernel_signal(SIGKILL | SIGTERM);

    pr_info("%s: Starting server loop...\n", MODULE_NAME);
    while (true) {
        if (signal_pending(current)) {
            goto release;
        }

        if (kthread_should_stop()) {
            goto release;
        }
        // Accept new connection
        ret = tcp_server_accept(&conn_socket);
        if (signal_pending(current)) {
            goto release;
        }
        if (ret) {
            pr_info("%s: Error %d occurred while accepting new connection",
                    MODULE_NAME, ret);
            continue;
        }

        // Connection established. Starting processing messages.
        pr_info("%s: Connection established, processing messages...\n",
                MODULE_NAME);
        while (true) {
            if (signal_pending(current)) break;
            // Process single message
            ret = process_single_message(conn_socket, &server_ops);
            if (ret < 0) {
                pr_err("%s: Error processing message. Error code: %d.",
                       MODULE_NAME, ret);
            }
        }

        // End connection and destroy socket
        kernel_sock_shutdown(conn_socket, SHUT_RD);
        sock_release(conn_socket);
    }

release:
    sock_release(server->listen_socket);
err:
    server->listener_stopped = true;
    do_exit(0);
}

static int __init xrp_metadata_target_init(void) {
    set_module_name("xrp_metadata_target");
    // Start metadata server
    pr_info("%s: Using TCP port %d\n", MODULE_NAME, port);
    server = kzalloc(sizeof(struct xrp_metadata_server), GFP_KERNEL);
    rwlock_init(&server->mappings_lock);
    server->files = kmalloc(sizeof(struct file), GFP_KERNEL);
    spin_lock_init(&server->files->file_lock);
    hash_init(server->mappings);
    driver_get_nvmeof_xrp_info = get_nvmeof_xrp_info;
    server->listen_thread = kthread_run((void *)tcp_server_listen, NULL,
                                        MODULE_NAME);
    nvmeof_xrp_use_hugepages = use_hugepages;
    if (use_hugepages)
        pr_info("%s: Using hugepages for NVMe-oF XRP data buffer\n",
                MODULE_NAME);

    pr_info("%s: Module loaded!\n", MODULE_NAME);
    return 0;
}

static void __exit xrp_metadata_target_exit(void) {
    if (!server->listener_stopped) {
        pr_info("%s: Cleaning up listening thread", MODULE_NAME);
        send_sig(SIGTERM, server->listen_thread, 1);
        kthread_stop(server->listen_thread);
    }
    driver_get_nvmeof_xrp_info = NULL;
    free_mapping_list();
    if (server->xrp_prog) bpf_prog_put(server->xrp_prog);
    kfree(server->files);
    kfree(server);
}

module_init(xrp_metadata_target_init);
module_exit(xrp_metadata_target_exit);
MODULE_LICENSE("GPL");
