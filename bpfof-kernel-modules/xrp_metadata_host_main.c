#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/fsnotify_backend.h>
#include <linux/hashtable.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/namei.h>
#include <linux/pid.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/debugfs.h>
#include <linux/rwsem.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <net/inet_connection_sock.h>
#include <net/request_sock.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "generic.h"
#include "kern_tcp.h"
#include "serialization.h"
#include "sync_proto.h"

#define PARAM_PERM S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP
#define EVENTS_OF_INTEREST                                            \
    (FS_CREATE | FS_OPEN | FS_DELETE | FS_MOVED_TO | FS_CLOSE_WRITE | \
     FS_CLOSE_NOWRITE | FS_EVENT_ON_CHILD)

static int port = 31000;
module_param(port, int, PARAM_PERM);
MODULE_PARM_DESC(port,
                 "TCP port that the remote XRP metadata host listens on.");

static char *ip = "192.168.53.3";
module_param(ip, charp, PARAM_PERM);
MODULE_PARM_DESC(port,
                 "TCP port that the remote XRP metadata host listens on.");

static char *sync_dir = "/mydata/rocksdb";
module_param(sync_dir, charp, PARAM_PERM);
MODULE_PARM_DESC(sync_dir,
                 "All files in this directory will have their extents synced.");

static int scratch_buffer_size = 4096;
module_param(scratch_buffer_size, int, PARAM_PERM);
MODULE_PARM_DESC(scratch_buffer_size, "Size of the XRP scratch buffer.");

////////////////////////////////////
// Statistics exposed via debugfs //
////////////////////////////////////

static struct dentry *stats_dir;
static atomic_t stats_counter_version_mismatches_fdtable = ATOMIC_INIT(0);
static atomic_t stats_counter_version_mismatches_inodes = ATOMIC_INIT(0);


int setup_stats(void) {
    stats_dir = debugfs_create_dir("bpfof_host_stats", NULL);
    if (!stats_dir) {
        pr_err("Failed to create debugfs directory\n");
        return -ENODEV;
    }

    debugfs_create_atomic_t("version_mismatches_fdtable", 0444, stats_dir,
                            &stats_counter_version_mismatches_fdtable);

    debugfs_create_atomic_t("version_mismatches_inodes", 0444, stats_dir,
                            &stats_counter_version_mismatches_inodes);
    return 0;
}

void teardown_stats(void) {
    debugfs_remove(stats_dir);
}

void stats_version_mismatches_fdtable_increment(void) {
    atomic_inc(&stats_counter_version_mismatches_fdtable);
}

void stats_version_mismatches_inodes_increment(void) {
    atomic_inc(&stats_counter_version_mismatches_inodes);
}

///////////////////////////////////////////////////////////////////////////////

/////////////////////////
// External interfaces //
/////////////////////////

extern volatile int nvmeof_xrp_scratch_buffer_size;
extern int ext4_ext_precache(struct inode *inode);

///////////////////////////////////////////////////////////////////////////////

///////////////////
// Global state  //
///////////////////

struct xrp_metadata_client {
    struct socket *send_socket;
    int port;
    char *ip;
    char *sync_dir;
    bool sender_stopped;
    DECLARE_HASHTABLE(inode_to_send_state, 8);  // Maps inode to send state.
    struct rw_semaphore inode_to_send_state_lock;          // Protects inode_to_send_state.
    int lock_file_inode;
};

static struct xrp_metadata_client *client;

///////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////
// Code for tracking the send state of each inode. //
/////////////////////////////////////////////////////

struct send_state {
    int inode_identifier;
    atomic_long_t version;
    atomic_long_t is_in_sync_queue;
    struct hlist_node hash;
    atomic_long_t ignore_next_create;
    char *pathname;
};

struct send_state *alloc_send_state(int inode_identifier, int version,
                                    char *pathname) {
    struct send_state *state = kmalloc(sizeof(struct send_state), GFP_ATOMIC);
    if (state == NULL) {
        pr_err("%s: Failed to allocate send state for inode %d.\n", MODULE_NAME,
               inode_identifier);
    }
    state->inode_identifier = inode_identifier;
    int pathname_len = strlen(pathname) + 1;
    state->pathname = kmalloc(pathname_len, GFP_ATOMIC);
    if (state->pathname == NULL) {
        pr_err("%s: Failed to allocate pathname for inode %d.\n", MODULE_NAME,
               inode_identifier);
    }
    memcpy(state->pathname, pathname, pathname_len);
    atomic_long_set(&state->version, version);
    atomic_long_set(&state->is_in_sync_queue, 0);
    atomic_long_set(&state->ignore_next_create, 0);
    pr_debug("%s: Allocated send state for inode %d with pathname %s.\n",
            MODULE_NAME, inode_identifier, pathname);
    return state;
}

static void destroy_send_state(struct send_state *state) {
    kfree(state->pathname);
    kfree(state);
}

static struct send_state *get_send_state(int inode_identifier) {
    struct send_state *state;
    hash_for_each_possible(client->inode_to_send_state, state, hash,
                           inode_identifier) {
        if (state->inode_identifier == inode_identifier) {
            return state;
        }
    }
    return NULL;
}

static void insert_send_state(struct send_state *state) {
    hash_add(client->inode_to_send_state, &state->hash,
             state->inode_identifier);
}

static void remove_send_state(struct send_state *state) {
    hash_del(&state->hash);
    destroy_send_state(state);
}
// TODO: Delete the send state when the inode is deleted.

///////////////////////////////////////////////////////////////////////////////

////////////////////////////
// Workqueue-related code //
////////////////////////////

static struct workqueue_struct *nvmeof_xrp_send_wq;
static DEFINE_MUTEX(nvmeof_xrp_send_wq_mutex);

enum nvmeof_xrp_work_type {
    NVMEOF_XRP_SYNC_WORK,
    NVMEOF_XRP_FDTABLE_SYNC_WORK,
    NVMEOF_XRP_DELETE_WORK,
};

struct nvmeof_xrp_work_struct {
    enum nvmeof_xrp_work_type type;
    // Sync
    char *pathname;
    // Fdtable sync
    struct delayed_work work;
    bool force_sync;
};


static void nvmeof_xrp_wq_handler(struct work_struct *w);

static struct nvmeof_xrp_work_struct *alloc_work(enum nvmeof_xrp_work_type type,
                                                 char *pathname) {
    struct nvmeof_xrp_work_struct *work =
        (struct nvmeof_xrp_work_struct *)kmalloc(
            sizeof(struct nvmeof_xrp_work_struct), GFP_ATOMIC);
    INIT_DELAYED_WORK(&work->work, nvmeof_xrp_wq_handler);
    work->type = type;
    int pathlen = strlen(pathname) + 1;
    work->pathname = (char *)kmalloc(pathlen, GFP_ATOMIC);
    memcpy(work->pathname, pathname, pathlen);
    pr_debug("%s: Allocating work for '%s'\n", MODULE_NAME, pathname);
    return work;
}


static void destroy_work(struct nvmeof_xrp_work_struct *work) {
    if (work->type == NVMEOF_XRP_SYNC_WORK) {
        kfree(work->pathname);
    }
    kfree(work);
}

static int setup_workqueues(void) {
    nvmeof_xrp_send_wq = alloc_workqueue("nvmeof_xrp_send_wq", WQ_HIGHPRI, 1);
    if (!nvmeof_xrp_send_wq) {
        pr_err("%s: Error allocating workqueue!\n", MODULE_NAME);
        return -1;
    }
    return 0;
}

static void destroy_workqueues(void) {
    if (nvmeof_xrp_send_wq) {
        destroy_workqueue(nvmeof_xrp_send_wq);
    }
}

static int sync_existing_files(char *root_dir) {
    int ret;
    bool more_files_remaining;
    LIST_HEAD(filenames);
    ret = kern_readdir(root_dir, &more_files_remaining, &filenames);
    if (ret) {
        pr_err("%s: Error reading directory '%s'!\n", MODULE_NAME, root_dir);
        return -1;
    }
    BUG_ON(more_files_remaining);

    // For each item in the list, create a work item and add it to the queue
    struct list_head *pos;
    struct nvmeof_xrp_work_struct *work;
    char pathname[2000];
    struct path path;

    list_for_each(pos, &filenames) {
        struct filename_node *f_node = list_entry(pos, struct filename_node,
                                                  list);
        path_join(root_dir, f_node->filename, pathname);
        ret = kern_path(pathname, LOOKUP_FOLLOW, &path);
        if (ret) {
            pr_err("%s: Error getting path for '%s'!\n", MODULE_NAME, pathname);
            return -1;
        }
        down_write(&client->inode_to_send_state_lock);
        insert_send_state(
            alloc_send_state(path.dentry->d_inode->i_ino, -1, pathname));
        up_write(&client->inode_to_send_state_lock);
        path_put(&path);
        work = alloc_work(NVMEOF_XRP_SYNC_WORK, pathname);
        queue_work(nvmeof_xrp_send_wq, &work->work.work);
    }
    free_filename_list(&filenames);
    return 0;
}

static int cache_extents(struct inode *inode) {
    // Fiemap with 0 extent count simply iterates over the file extents.
    int ret;
    struct fiemap_extent_info fieinfo = {
        .fi_extents_start = 0,
        .fi_extents_max = 0,
        .fi_extents_start = NULL,
        .fi_flags = FIEMAP_FLAG_SYNC | FIEMAP_FLAG_CACHE,
    };
    ret = inode->i_op->fiemap(inode, &fieinfo, 0, FIEMAP_MAX_OFFSET);
    return ret;
}

static int send_file_extents(char *pathname, struct inode *inode,
                             struct send_state *send_state) {
    int ret;
    int version, old_version;
    struct rb_root *xrp_rb_root;
    struct xrp_root *xrp_root;
    char *es_bytes;

    // Load the extent status tree in-memory.
    // We *know* that this is an ext4 file, so we can use the ext4-specific
    // function to load the tree.
    rcu_read_lock();
    // Check if extent version is newer than what we've sent so far.
    xrp_rb_root = rcu_dereference(inode->xrp_extent_root);
    xrp_root = container_of(xrp_rb_root, struct xrp_root, rb_root);
    if (!xrp_rb_root || RB_EMPTY_ROOT(xrp_rb_root)) {
        rcu_read_unlock();
        pr_info("%s: File '%s' has no extent status tree :(\n", MODULE_NAME,
                pathname);
        return -1;
    }
    version = xrp_root->version;
    old_version = atomic_long_read(&send_state->version);
    if (version == old_version) {
        rcu_read_unlock();
        pr_warn(
            "%s: File '%s' has no new version! Old version: %d. New Version: "
            "%d\n",
            MODULE_NAME, pathname, old_version, version);
        return -1;
    }
    pr_debug("%s: Printing XRP tree\n", MODULE_NAME);
    print_xrp_es_tree(xrp_rb_root);
    ret = xrp_es_serialize(xrp_root, &es_bytes);
    rcu_read_unlock();
    if (ret < 0) {
        pr_err(
            "test_serialization: Error serializing extent-status tree: "
            "%d!\n",
            ret);
        return ret;
    }
    // Don't sleep while holding the lock!
    up_read(&client->inode_to_send_state_lock);
    // Send extent status tree for file
    pr_debug("%s: Sending new version!\n", MODULE_NAME);
    ret = send_new_version(version, inode->i_ino, es_bytes, ret,
                           client->send_socket);
    kfree(es_bytes);
    down_read(&client->inode_to_send_state_lock);
    if (ret) {
        pr_err("%s: Error while sending new es_tree version. Error code: %d",
               MODULE_NAME, ret);
        return ret;
        // BUG();
    }
    send_state = get_send_state(inode->i_ino);
    if (send_state == NULL) {
        pr_err("%s: Error getting send state for inode %lu!\n", MODULE_NAME,
               inode->i_ino);
        return -1;
    }
    atomic_long_cmpxchg(&send_state->version, old_version, version);
    return 0;
}

static int nvmeof_xrp_handle_xrp_sync(
    struct nvmeof_xrp_work_struct *nvmeof_xrp_work) {
    int ret = 0;
    struct path path;
    pr_debug("%s: Queue item pathname: '%s'\n", MODULE_NAME,
            nvmeof_xrp_work->pathname);
    ret = kern_path(nvmeof_xrp_work->pathname, LOOKUP_FOLLOW, &path);
    if (ret) {
        pr_err("%s: Error getting kernel path: %d!\n", MODULE_NAME, ret);
        return ret;
    }
    pr_debug("%s: Path '%s', inode '%ld'\n", MODULE_NAME,
            nvmeof_xrp_work->pathname, path.dentry->d_inode->i_ino);

    // Check for the LOCK file
    if (strstr(nvmeof_xrp_work->pathname, "MANIFEST") != NULL) {
        pr_debug("%s: Got manifest file! Not syncing!\n", MODULE_NAME);
        client->lock_file_inode = path.dentry->d_inode->i_ino;
        path_put(&path);
        return 0;
    }

    // Call fiemap here without holding the lock. Otherwise, we'll deadlock,
    // as fiemap will cause an fs event which calls the handler.
    pr_debug("%s: Caching extent status tree for '%s'...\n", MODULE_NAME,
            nvmeof_xrp_work->pathname);
    ret = cache_extents(path.dentry->d_inode);
    if (ret) {
        pr_err("%s: Error loading extent status tree for '%s'!\n", MODULE_NAME,
               nvmeof_xrp_work->pathname);
        goto release_path;
    }
    // Load existing send state for this file
    down_read(&client->inode_to_send_state_lock);
    struct send_state *send_state = get_send_state(path.dentry->d_inode->i_ino);
    if (send_state == NULL) {
        pr_err("%s: Error: send_state is NULL!\n", MODULE_NAME);
        up_read(&client->inode_to_send_state_lock);
        ret = -1;
        goto release_path;
    }
    atomic_long_set(&send_state->is_in_sync_queue, 0);
    // At this point, we have a send state and hold the read lock.
    send_file_extents(nvmeof_xrp_work->pathname, path.dentry->d_inode,
                      send_state);
    up_read(&client->inode_to_send_state_lock);
release_path:
    path_put(&path);
    return ret;
}

static void nvmeof_xrp_wq_handler(struct work_struct *w) {
    int ret;
    mutex_lock(&nvmeof_xrp_send_wq_mutex);
    struct delayed_work *delayed_work = container_of(w, struct delayed_work,
                                                     work);
    struct nvmeof_xrp_work_struct *nvmeof_xrp_work = container_of(
        delayed_work, struct nvmeof_xrp_work_struct, work);
    if (nvmeof_xrp_work->type == NVMEOF_XRP_SYNC_WORK) {
        ret = nvmeof_xrp_handle_xrp_sync(nvmeof_xrp_work);
        if (ret) {
            pr_err("%s: Error while handling NVMEOF_XRP_SYNC_WORK!\n",
                   MODULE_NAME);
            goto release_work;
        }
    } else if (nvmeof_xrp_work->type == NVMEOF_XRP_DELETE_WORK) {
        // Unimplemented
        pr_debug("%s: NVMEOF_XRP_DELETE_WORK is unimplemented!\n", MODULE_NAME);
    } else {
        pr_err("%s: Unknown work type: %d!\n", MODULE_NAME,
               nvmeof_xrp_work->type);
    }
release_work:
    destroy_work(nvmeof_xrp_work);
    mutex_unlock(&nvmeof_xrp_send_wq_mutex);
}

///////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////
// Functions exposed to NVME Driver //
//////////////////////////////////////

extern bool (*driver_nvmeof_xrp_mapping_synced)(
    struct xrp_fd_info *xrp_fd_info_arr, size_t xrp_fd_count);
bool __nvmeof_xrp_single_mapping_synced(struct inode *inode);

// driver_xrp_mapping_synced checks if the latest version of the extent mapping
// for the given inode is synced.
bool nvmeof_xrp_mapping_synced(struct xrp_fd_info *xrp_fd_info_arr,
                               size_t xrp_fd_count) {
    // Check if all mappings are synced
    int i;
    bool ret = true;
    for (i = 0; i < xrp_fd_count; i++) {
        if (!__nvmeof_xrp_single_mapping_synced(xrp_fd_info_arr[i].inode)) {
            ret = false;
        }
    }
    return ret;
}


bool __nvmeof_xrp_single_mapping_synced(struct inode *inode) {
    int version, remote_version;
    struct rb_root *xrp_rb_root;
    struct xrp_root *xrp_root;
    pr_debug("%s: Checking if mapping for inode %ld is synced...\n",
             MODULE_NAME, inode->i_ino);
    // Get local version
    rcu_read_lock();
    xrp_rb_root = rcu_dereference(inode->xrp_extent_root);
    xrp_root = container_of(xrp_rb_root, struct xrp_root, rb_root);

    version = xrp_root->version;
    rcu_read_unlock();
    down_read(&client->inode_to_send_state_lock);
    struct send_state *state = get_send_state(inode->i_ino);
    if (state == NULL) {
        up_read(&client->inode_to_send_state_lock);
        pr_warn("%s: No send state for inode %ld!\n", MODULE_NAME,
                inode->i_ino);
        stats_version_mismatches_inodes_increment();
        return false;
    }
    remote_version = atomic_long_read(&state->version);
    if (likely(version == remote_version)) {
        up_read(&client->inode_to_send_state_lock);
        return true;
    }
    int prev_is_in_sync_queue;
    prev_is_in_sync_queue = atomic_long_cmpxchg(&state->is_in_sync_queue, 0, 1);
    if (prev_is_in_sync_queue == 0) {
        pr_debug(
            "%s: Queueing sync work for inode %ld because version check "
            "failed\n",
            MODULE_NAME, inode->i_ino);
        up_read(&client->inode_to_send_state_lock);
        struct nvmeof_xrp_work_struct *work = alloc_work(NVMEOF_XRP_SYNC_WORK,
                                                         state->pathname);
        queue_delayed_work(nvmeof_xrp_send_wq, &work->work, 0);
    } else {
        pr_debug("%s: Sync work for inode %ld is already in the queue!\n",
                MODULE_NAME, inode->i_ino);
        up_read(&client->inode_to_send_state_lock);
    }
    stats_version_mismatches_inodes_increment();
    return false;
}

///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////
// Code related to file-watching //
///////////////////////////////////

static struct fsnotify_group *nvmeof_xrp_watch_group;
static struct fsnotify_mark nvmeof_xrp_watch_mark;

static void mask_str(u32 mask, char *mstr) {
    // Convert mask to string
    int i;
    mstr[32] = '\0';
    for (i = 0; i < 32; i++) {
        mstr[i] = (mask & (1 << (32 - i))) ? '1' : '0';
    }
}

static char *event_str(u32 mask) {
    if (mask & FS_OPEN) return "FS_OPEN";
    if (mask & FS_CREATE) return "FS_CREATE";
    if (mask & FS_CLOSE_WRITE) return "FS_CLOSE_WRITE";
    if (mask & FS_CLOSE_NOWRITE) return "FS_CLOSE_NOWRITE";
    if (mask & FS_MOVED_TO) return "FS_MOVED_TO";
    if (mask & FS_MOVED_FROM) return "FS_MOVED_FROM";
    if (mask & FS_DELETE) return "FS_DELETE";
    if (!(mask & FS_EVENT_ON_CHILD)) return "NON_CHILD_EVENT";
    return "UNKNOWN";
}

static int nvmeof_xrp_handle_event(struct fsnotify_group *group, u32 mask,
                                   const void *data, int data_type,
                                   struct inode *dir,
                                   const struct qstr *file_name, u32 cookie,
                                   struct fsnotify_iter_info *iter_info) {
    // See: https://access.redhat.com/solutions/762903
    if (!current) {
        pr_err("%s: current is NULL! Unexpected!\n", MODULE_NAME);
        return 0;
    }
    if (current->fs == NULL) {
        pr_debug("%s: current->fs is NULL! Process is probably finishing up..\n",
                MODULE_NAME);
        return 0;
    }
    if (WARN_ON_ONCE(group != nvmeof_xrp_watch_group)) return 0;
    char mstr[33];
    mask_str(mask, mstr);
    if (file_name == NULL) {
        pr_debug("%s: Got event '%s'(%s), no filename!\n", MODULE_NAME,
                event_str(mask), mstr);
        return 0;
    }

    pr_debug("%s: Got event '%s'(%s) for file '%.*s'!\n", MODULE_NAME,
            event_str(mask), mstr, file_name->len, file_name->name);
    if (!(mask & (EVENTS_OF_INTEREST))) return 0;
    int ret;
    struct path path;
    char *filename = kmalloc(512, GFP_ATOMIC);
    char *pathname = kmalloc(PATH_MAX, GFP_ATOMIC);
    WARN_ON(file_name->len > 512);
    memcpy(filename, file_name->name, file_name->len);
    filename[file_name->len] = '\0';
    WARN_ON(strlen(client->sync_dir) + strlen(filename) + 1 > PATH_MAX);
    path_join(client->sync_dir, filename, pathname);
    pr_debug("%s: Pathname: '%s'", MODULE_NAME, pathname);
    if (!(mask & FS_DELETE)) {
        pr_debug("%s: Getting the path %s\n", MODULE_NAME, pathname);
        ret = kern_path(pathname, LOOKUP_FOLLOW, &path);
        pr_debug("%s: Got the path %s and inode %ld\n", MODULE_NAME, pathname,
                path.dentry->d_inode->i_ino);
        if (ret) {
            pr_warn("%s: Could not get path for file '%.*s'!\n", MODULE_NAME,
                    file_name->len, file_name->name);
            return 0;
        }
    }

    if (mask & FS_CREATE) {
        down_write(&client->inode_to_send_state_lock);
        struct send_state *state = get_send_state(path.dentry->d_inode->i_ino);
        if (state != NULL) {
            int should_allow_existing = atomic_long_xchg(
                &state->ignore_next_create, 0);
            pr_debug(
                "%s: File '%s' already has send state! Pathname: %s. "
                "State pathname: %s\n",
                MODULE_NAME, pathname, pathname, state->pathname);
            if (should_allow_existing == 0 ||
                strcmp(state->pathname, pathname) != 0) {
                pr_warn(
                    "%s: WARNING: File '%s' has send state even though it was "
                    "just created! Pathname: %s. State pathname: %s\n",
                    MODULE_NAME, pathname, pathname, state->pathname);
                up_write(&client->inode_to_send_state_lock);
                BUG();
                goto release;
            } else {
                pr_debug(
                    "%s: File '%s' has send state even though it was just "
                    "created, but we are ignoring it!\n",
                    MODULE_NAME, pathname);
                up_write(&client->inode_to_send_state_lock);
                goto release;
            }
        }
        pr_debug("%s: Inserting send state for file '%s' with inode '%ld'!\n",
                MODULE_NAME, pathname, path.dentry->d_inode->i_ino);
        insert_send_state(
            alloc_send_state(path.dentry->d_inode->i_ino, -1, pathname));
        up_write(&client->inode_to_send_state_lock);
        struct nvmeof_xrp_work_struct *work;
        work = alloc_work(NVMEOF_XRP_SYNC_WORK, pathname);
        queue_work(nvmeof_xrp_send_wq, &work->work.work);
    } else if (mask & (FS_CLOSE_WRITE | FS_CLOSE_NOWRITE)) {
        struct nvmeof_xrp_work_struct *work;

        // First, check if the file has the same inode as a file we have a send
        // state for. This should never happen as we handle deletes and
        // renames, but it's better to be safe than sorry.
        down_read(&client->inode_to_send_state_lock);
        struct send_state *state = get_send_state(path.dentry->d_inode->i_ino);
        if (state == NULL) {
            pr_warn(
                "%s: WARNING: File '%s' has no send state even though it"
                " already existed!\n",
                MODULE_NAME, pathname);
            up_read(&client->inode_to_send_state_lock);
            BUG();
            goto release;
        }
        ret = strcmp(state->pathname, pathname);
        if (ret != 0) {
            pr_warn("%s: File '%s' has the same inode as file '%s'!\n",
                    MODULE_NAME, pathname, state->pathname);
            up_read(&client->inode_to_send_state_lock);
            BUG();
            goto release;
        }
        work = alloc_work(NVMEOF_XRP_SYNC_WORK, pathname);
        queue_work(nvmeof_xrp_send_wq, &work->work.work);
        up_read(&client->inode_to_send_state_lock);
    } else if (mask & FS_DELETE) {
        // TODO: How to find the deleted file's inode?
        down_write(&client->inode_to_send_state_lock);
        // Iterate hash table
        struct send_state *state;
        int bkt;
        bool found = false;
        hash_for_each(client->inode_to_send_state, bkt, state, hash) {
            if (strcmp(state->pathname, pathname) == 0) {
                pr_debug(
                    "%s: Received delete event for file '%s', removing "
                    "send state!\n",
                    MODULE_NAME, pathname);
                remove_send_state(state);
                found = true;
                break;
            }
        }
        if (!found) {
            pr_warn(
                "%s: WARNING: Received delete event for file '%s', but no "
                "send state exists! Printing all entries...\n",
                MODULE_NAME, pathname);
            hash_for_each(client->inode_to_send_state, bkt, state, hash) {
                pr_warn("%s: Entry: '%s'\n", MODULE_NAME, state->pathname);
            }
        }
        up_write(&client->inode_to_send_state_lock);
    } else if (mask & FS_MOVED_TO) {
        int bkt;
        struct send_state *state;
        down_write(&client->inode_to_send_state_lock);
        // Did we already have a send state for this pathname?
        // If yes, we need to remove it and add a new one.
        hash_for_each(client->inode_to_send_state, bkt, state, hash) {
            if (strcmp(state->pathname, pathname) == 0) {
                pr_debug(
                    "%s: Received moved_to event for file '%s', removing "
                    "old send state!\n",
                    MODULE_NAME, pathname);
                remove_send_state(state);
                break;
            }
        }
        state = get_send_state(path.dentry->d_inode->i_ino);
        if (state == NULL) {
            pr_warn(
                "%s: WARNING: Received moved_to event for file '%s', but no "
                "send state exists!\n",
                MODULE_NAME, pathname);
            up_write(&client->inode_to_send_state_lock);
            BUG();
            goto release;
        }
        pr_debug(
            "%s: Received moved_to event for file '%s', updating "
            "pathname! Old pathname: %s. New pathname: %s\n",
            MODULE_NAME, pathname, state->pathname, pathname);
        kfree(state->pathname);
        int pathname_len = strlen(pathname) + 1;
        state->pathname = kmalloc(pathname_len, GFP_ATOMIC);
        memcpy(state->pathname, pathname, pathname_len);
        atomic_long_set(&state->ignore_next_create, 1);
        up_write(&client->inode_to_send_state_lock);
    }

release:
    if (file_name != NULL) {
        if (!(mask & FS_DELETE)) path_put(&path);
        kfree(filename);
        kfree(pathname);
    }
    return 0;
}

static void nvmeof_xrp_free_mark(struct fsnotify_mark *mark) {
    // Mark is a global variable, so we don't need to do anything here.
    return;
}

static const struct fsnotify_ops nvmeof_xrp_fsnotify_ops = {
    .handle_event = nvmeof_xrp_handle_event,
    .free_mark = nvmeof_xrp_free_mark,
};

static int setup_sync_dir_watch(char *sync_dir) {
    // Watch the the given directory:
    // 1. Allocate a new fsnotify group. The group is the entity that will
    //    receive notifications from the kernel.
    // 2. Create a new fsnotify mark. The mark is an object that will be
    //    attached to the inode of the directory we want to watch. It contains
    //    information about the group that will receive notifications and the
    //    mask of events that we want to receive.
    int ret;
    struct path sync_dir_path;

    pr_info("%s: Syncing extents for files under '%s'\n", MODULE_NAME,
            sync_dir);
    nvmeof_xrp_watch_group = fsnotify_alloc_group(&nvmeof_xrp_fsnotify_ops);
    if (IS_ERR(nvmeof_xrp_watch_group)) {
        pr_err("%s: Error allocating fsnotify group!\n", MODULE_NAME);
        return -1;
    }
    fsnotify_init_mark(&nvmeof_xrp_watch_mark, nvmeof_xrp_watch_group);
    nvmeof_xrp_watch_mark.mask = EVENTS_OF_INTEREST;
    ret = kern_path(sync_dir, LOOKUP_FOLLOW, &sync_dir_path);
    if (ret) {
        pr_err("%s: Error getting kernel path: %d!\n", MODULE_NAME, ret);
        goto release_group;
    }
    ret = fsnotify_add_inode_mark(&nvmeof_xrp_watch_mark,
                                  sync_dir_path.dentry->d_inode, 0);
    path_put(&sync_dir_path);
    if (ret) {
        pr_err("%s: Error adding fsnotify mark! Error code: %d\n", MODULE_NAME,
               ret);
        goto release_mark;
    }
    return 0;
release_mark:
    // fsnotify_destroy_mark(&nvmeof_xrp_watch_mark, nvmeof_xrp_watch_group);
    // fsnotify_put_mark(&nvmeof_xrp_watch_mark);
release_group:
    // fsnotify_put_group(nvmeof_xrp_watch_group);
    fsnotify_destroy_group(nvmeof_xrp_watch_group);
    fsnotify_wait_marks_destroyed();
    return ret;
}

///////////////////////////////////////////////////////////////////////////////

static int setup_tcp_connection(void) {
    int ret;
    ret = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
                           &client->send_socket);
    if (ret) {
        pr_err("%s: Error: %d while creating send socket\n", MODULE_NAME, ret);
        return -1;
    }
    // Disable Nagle's algorithm
    tcp_sock_set_nodelay(client->send_socket->sk);

    struct sockaddr_in server_addr = {.sin_family = AF_INET,
                                      .sin_port = htons(client->port),
                                      .sin_addr = {
                                          .s_addr = in_aton(client->ip),
                                      }};
    ret = kernel_connect(client->send_socket, (struct sockaddr *)&server_addr,
                         sizeof(server_addr), O_RDWR);
    if (ret) {
        pr_err("%s: Error: %d while connecting\n", MODULE_NAME, ret);
        kfree(client->send_socket);
        return -1;
    }

    pr_info("%s: Successfully connected with target!\n", MODULE_NAME);
    return 0;
}

static int __init xrp_metadata_host_init(void) {
    int ret;

    set_module_name("xrp_metadata_host");
    driver_nvmeof_xrp_mapping_synced = nvmeof_xrp_mapping_synced;
    client = kzalloc(sizeof(struct xrp_metadata_client), GFP_KERNEL);
    client->ip = ip;
    client->port = port;
    client->sync_dir = sync_dir;
    hash_init(client->inode_to_send_state);
    init_rwsem(&client->inode_to_send_state_lock);
    nvmeof_xrp_scratch_buffer_size = scratch_buffer_size;

    pr_info("%s: Using IP address %s\n", MODULE_NAME, client->ip);
    pr_info("%s: Using TCP port %d\n", MODULE_NAME, client->port);
    ret = setup_tcp_connection();
    if (ret) {
        pr_err("%s: Error setting up TCP connection: %d!\n", MODULE_NAME, ret);
        return ret;
    }
    ret = setup_workqueues();
    if (ret) {
        pr_err("%s: Error setting up workqueues: %d!\n", MODULE_NAME, ret);
        return ret;
    }
    ret = sync_existing_files(client->sync_dir);
    if (ret) {
        pr_err("%s: Error syncing existing files: %d!\n", MODULE_NAME, ret);
        return ret;
    }
    ret = setup_sync_dir_watch(client->sync_dir);
    if (ret) {
        pr_err("%s: Error setting up sync dir watch: %d!\n", MODULE_NAME, ret);
        return ret;
    }
    ret = setup_stats();
    if (ret) {
        pr_err("%s: Error setting up stats: %d!\n", MODULE_NAME, ret);
        return ret;
    }
    msleep(2000);

    pr_info("%s: Module loaded!\n", MODULE_NAME);
    return 0;
}

static void __exit xrp_metadata_host_exit(void) {
    // fsnotify_destroy_mark(&nvmeof_xrp_watch_mark, nvmeof_xrp_watch_group);
    // fsnotify_put_mark(&nvmeof_xrp_watch_mark);
    // fsnotify_put_group(nvmeof_xrp_watch_group);
    fsnotify_destroy_group(nvmeof_xrp_watch_group);
    fsnotify_wait_marks_destroyed();
    destroy_workqueues();
    kfree(client);
    teardown_stats();
    driver_nvmeof_xrp_mapping_synced = NULL;
}

module_init(xrp_metadata_host_init);
module_exit(xrp_metadata_host_exit);
MODULE_LICENSE("GPL");
