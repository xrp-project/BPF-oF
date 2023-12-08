#include <linux/types.h>

#include "generic.h"
#include "kern_tcp.h"
#include "sync_proto.h"

char MAGIC[MAGIC_SIZE] = {0x34, 0xb6, 0xcb, 0xa0, 0x12, 0x42, 0x49, 0xdd};

// Code that implements the sync protocol

int parse_common_header(char *buf, int len,
                        struct common_header *common_header) {
    if (len < MAGIC_SIZE + sizeof(struct common_header)) {
        pr_err("%s: Failed to parse common header, buffer too small!\n",
               MODULE_NAME);
        return -1;
    }
    if (memcmp(buf, MAGIC, MAGIC_SIZE) != 0) {
        pr_err("%s: Failed to parse common header, magic not matching!\n",
               MODULE_NAME);
        return -1;
    }
    memcpy(common_header, buf + MAGIC_SIZE, sizeof(struct common_header));
    return 0;
}

int recv_common_header(struct socket *conn_socket,
                       struct common_header *common_header) {
    int ret;
    char buf[MAGIC_SIZE + sizeof(struct common_header)];

    ret = ksock_recv_all(conn_socket, buf,
                         MAGIC_SIZE + sizeof(struct common_header),
                         MSG_WAITALL);
    if (ret < 0) {
        pr_err("%s: Failed to receive new message. Error code: %d\n",
               MODULE_NAME, ret);
        return ret;
    }
    return parse_common_header(buf, MAGIC_SIZE + sizeof(struct common_header),
                               common_header);
}

int process_single_message(struct socket *conn_socket,
                           struct server_ops *server_ops) {
    int ret;
    struct common_header common_header;

    pr_debug("%s: Receiving common header...\n", MODULE_NAME);
    ret = recv_common_header(conn_socket, &common_header);
    if (ret < 0) {
        return ret;
    }
    pr_debug(
        "%s: Received common header with: 'msg_type': %d, 'hdr_size': %lld, "
        "'msg_size': %lld \n",
        MODULE_NAME, common_header.msg_type, common_header.hdr_size,
        common_header.msg_size);

    if (common_header.msg_type == MSG_SETVERSION_REQUEST) {
        pr_debug("%s: Received a MSG_SETVERSION_REQUEST, receiving header...\n",
                MODULE_NAME);
        // Parse setversion_request_header
        struct setversion_request_header *hdr;
        BUG_ON(common_header.hdr_size !=
               sizeof(struct setversion_request_header));
        char buf[sizeof(struct setversion_request_header)];
        ret = ksock_recv_all(conn_socket, buf, common_header.hdr_size, 0);
        if (ret < 0) {
            pr_err("%s: Failed to parse setversion_request_header\n",
                   MODULE_NAME);
            return ret;
        }
        hdr = (struct setversion_request_header *)buf;
        pr_debug(
            "%s: Received a MSG_SETVERSION_REQUEST, received header with: "
            "'version': %lld\n",
            MODULE_NAME, hdr->version);

        // Parse payload
        char *payload;
        uint64_t payload_size = common_header.msg_size - common_header.hdr_size;
        pr_debug(
            "%s: Received a MSG_SETVERSION_REQUEST, receiving payload with "
            "size %llu\n",
            MODULE_NAME, payload_size);
        payload = kmalloc(payload_size, GFP_KERNEL);
        ret = ksock_recv_all(conn_socket, payload, payload_size, 0);
        if (ret < 0) {
            pr_err(
                "%s: Failed to receive payload for MSG_SETVERSION_REQUEST. "
                "Error code: %d\n",
                MODULE_NAME, ret);
            kfree(payload);
            return ret;
        }
        pr_debug("%s: Received a MSG_SETVERSION_REQUEST, received payload...\n",
                MODULE_NAME);

        server_ops->handle_setversion_request(conn_socket, hdr, payload,
                                              payload_size);
        // Don't free payload buffer. We re-use the memory for the deserialized
        // extent-status tree.
    } else if (common_header.msg_type == MSG_SETFDTABLE_REQUEST) {
        pr_debug("%s: Received a MSG_SETFDTABLE_REQUEST, receiving header...\n",
                MODULE_NAME);
        // Parse setversion_request_header
        struct setfdtable_request_header *hdr;
        BUG_ON(common_header.hdr_size != sizeof(struct setfdtable_request_header));
        char buf[sizeof(struct setfdtable_request_header)];
        ret = ksock_recv_all(conn_socket, buf, common_header.hdr_size, 0);
        if (ret < 0) {
            pr_err("%s: Failed to parse setfdtable_request_header\n", MODULE_NAME);
            return ret;
        }
        hdr = (struct setfdtable_request_header *)buf;
        pr_debug(
            "%s: Received a MSG_SETFDTABLE_REQUEST, received header with: "
            "'version': %lld\n",
            MODULE_NAME, hdr->version);

        // Parse payload
        char *payload;
        uint64_t payload_size = common_header.msg_size - common_header.hdr_size;
        pr_debug(
            "%s: Received a MSG_SETFDTABLE_REQUEST, receiving payload with "
            "size %llu\n",
            MODULE_NAME, payload_size);
        payload = kmalloc(payload_size, GFP_KERNEL);
        if (payload == NULL) {
            pr_err("%s: Failed to allocate memory for payload\n", MODULE_NAME);
            BUG();
        }
        ret = ksock_recv_all(conn_socket, payload, payload_size, 0);
        if (ret < 0) {
            pr_err(
                "%s: Failed to receive payload for MSG_SETFDTABLE_REQUEST. "
                "Error code: %d\n",
                MODULE_NAME, ret);
            kfree(payload);
            return ret;
        }
        pr_debug("%s: Received a MSG_SETFDTABLE_REQUEST, received payload...\n",
                MODULE_NAME);

        server_ops->handle_setfdtable_request(conn_socket, hdr, payload,
                                              payload_size);

    } else {
        pr_err("%s: Unknown message type\n", MODULE_NAME);
        BUG();
    }
    return 0;
}

int send_new_version(int version, int inode_identifier, char *payload, int len,
                     struct socket *conn_socket) {
    int ret;
    struct common_header common_header;
    struct setversion_request_header setversion_request_header;

    // 1. Write Magic Number
    ret = ksock_send_all(conn_socket, (void *)MAGIC, MAGIC_SIZE, 0);
    if (ret < 0) {
        pr_err("%s: Failed to send magic. Error code: %d!\n", MODULE_NAME, ret);
        return ret;
    }

    // 2. Write Common Header
    common_header.msg_type = MSG_SETVERSION_REQUEST;
    common_header.hdr_size = sizeof(struct setversion_request_header);
    common_header.msg_size = common_header.hdr_size + len;
    ret = ksock_send_all(conn_socket, (void *)&common_header,
                         sizeof(struct common_header), 0);
    if (ret < 0) {
        pr_err("%s: Failed to send common header. Error code: %d\n",
               MODULE_NAME, ret);
        return ret;
    }

    // 3. Write Request Header
    // TODO: Fill version.
    setversion_request_header.version = version;
    setversion_request_header.inode_identifier = inode_identifier;
    ret = ksock_send_all(conn_socket, (void *)&setversion_request_header,
                         sizeof(struct setversion_request_header), 0);
    if (ret < 0) {
        pr_err(
            "%s: Failed to send setversion_request_header header. Error code: "
            "%d\n",
            MODULE_NAME, ret);
        return ret;
    }

    // 4. Write Payload
    ret = ksock_send_all(conn_socket, (void *)payload, len, 0);
    if (ret < 0) {
        pr_err("%s: Failed to send new version payload. Error code: %d\n",
               MODULE_NAME, ret);
        return ret;
    }
    return 0;
}

int send_new_fdtable(int version, char *payload, int len,
                     struct socket *conn_socket) {
    int ret;
    struct common_header common_header;
    struct setfdtable_request_header setfdtable_request_header;

    // 1. Write Magic Number
    ret = ksock_send_all(conn_socket, (void *)MAGIC, MAGIC_SIZE, 0);
    if (ret < 0) {
        pr_err("%s: Failed to send magic. Error code: %d!\n", MODULE_NAME, ret);
        return ret;
    }

    // 2. Write Common Header
    common_header.msg_type = MSG_SETFDTABLE_REQUEST;
    common_header.hdr_size = sizeof(struct setfdtable_request_header);
    common_header.msg_size = common_header.hdr_size + len;
    ret = ksock_send_all(conn_socket, (void *)&common_header,
                         sizeof(struct common_header), 0);
    if (ret < 0) {
        pr_err("%s: Failed to send common header. Error code: %d\n",
               MODULE_NAME, ret);
        return ret;
    }

    // 3. Write Request Header
    // TODO: Fill version.
    setfdtable_request_header.version = version;
    ret = ksock_send_all(conn_socket, (void *)&setfdtable_request_header,
                         sizeof(struct setfdtable_request_header), 0);
    if (ret < 0) {
        pr_err(
            "%s: Failed to send setfdtable_request_header header. Error code: "
            "%d\n",
            MODULE_NAME, ret);
        return ret;
    }

    // 4. Write Payload
    ret = ksock_send_all(conn_socket, (void *)payload, len, 0);
    if (ret < 0) {
        pr_err("%s: Failed to send new version payload. Error code: %d\n",
               MODULE_NAME, ret);
        return ret;
    }
    return 0;
}