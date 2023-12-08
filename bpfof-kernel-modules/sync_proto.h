
#ifndef _SYNC_PROTO_H
#define _SYNC_PROTO_H

#include <linux/types.h>

#define MAGIC_SIZE 8
extern char MAGIC[MAGIC_SIZE];

enum msg_type {
    MSG_SETVERSION_REQUEST,
    MSG_SETVERSION_RESPONSE,
    MSG_SETFDTABLE_REQUEST,
    MSG_SETFDTABLE_RESPONSE,
};

enum status { OK, ERROR };

// Common Header:
// - 8 Bytes: Magic Number
// - 2 Bytes: Message Type
// - 8 Bytes: Message header length
// - 8 Bytes: Message length
//
// Total: 26 Bytes
struct common_header {
    enum msg_type msg_type;
    // hdr_size is the size of the message-specific header.
    uint64_t hdr_size;
    // msg_size is the total message size ending, starting at the first byte of
    // the message-specific header (after the common header) and ending at the
    // last byte of the message.
    uint64_t msg_size;
} __attribute__((__packed__));

struct setversion_request_header {
    uint64_t version;
    uint32_t inode_identifier;
} __attribute__((__packed__));

struct setversion_response_header {
    enum status status;
} __attribute__((__packed__));

struct setfdtable_request_header {
    uint64_t version;
} __attribute__((__packed__));

struct setfdtable_response_header {
    enum status status;
} __attribute__((__packed__));

struct server_ops {
    int (*handle_setversion_request)(struct socket *conn_socket,
                                     struct setversion_request_header *hdr,
                                     char *payload, int len);
    int (*handle_setfdtable_request)(struct socket *conn_socket,
                                     struct setfdtable_request_header *hdr,
                                     char *payload, int len);
};

int process_single_message(struct socket *conn_socket,
                           struct server_ops *server_ops);

int send_new_version(int version, int inode_identifier, char *payload, int len,
                     struct socket *conn_socket);

int send_new_fdtable(int version, char *payload, int len,
                     struct socket *conn_socket);

#endif /* _SYNC_PROTO_H */