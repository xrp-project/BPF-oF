#ifndef _XRP_METADATA_TARGET_H
#define _XRP_METADATA_TARGET_H

#include <linux/hashtable.h>

struct mapping {
    // id identifies the file this mapping belongs to
    uint32_t id;
    int version;
    // xrp_inode is a fake inode to easily plug into XRP's existing interface
    struct inode *xrp_inode;
    struct hlist_node hash_list;
};

struct mapping *get_mapping_locked(uint32_t inode_identifier);

#endif /* _XRP_METADATA_TARGET_H */
