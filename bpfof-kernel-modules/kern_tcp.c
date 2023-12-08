#include <linux/inet.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/wait.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <net/inet_connection_sock.h>
#include <net/request_sock.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "generic.h"

// Helpers for in-kernel TCP

// inet_ntoa translates the given address to an IP address string stored in
// the given char array. The char array MUST have size 16.
void inet_ntoa(struct in_addr *in, char *str_ip) {
    u_int32_t int_ip = 0;
    memset(str_ip, 0, 16);
    int_ip = in->s_addr;
    sprintf(str_ip, "%d.%d.%d.%d", (int_ip)&0xFF, (int_ip >> 8) & 0xFF,
            (int_ip >> 16) & 0xFF, (int_ip >> 16) & 0xFF);
}

int ksock_recv(struct socket *conn_socket, char *buf, size_t size, int flags) {
    struct kvec iov = {.iov_base = buf, .iov_len = size};
    struct msghdr msg = {.msg_flags = flags};
    return kernel_recvmsg(conn_socket, &msg, &iov, 1, iov.iov_len,
                          msg.msg_flags);
}

int ksock_recv_all(struct socket *conn_socket, char *buf, size_t size,
                   int flags) {
    int ret;
    int remaining = size;
    while (remaining) {
        ret = ksock_recv(conn_socket, buf, remaining, flags);
        if (signal_pending(current)) {
            pr_info("%s: Received signal!\n", MODULE_NAME);
            return -1;
        }
        if (ret >= 0) {
            remaining -= ret;
            buf += ret;
        } else if (ret < 0) {
            return ret;
        }
    }
    return size;
}

int ksock_send(struct socket *conn_socket, char *buf, size_t size, int flags) {
    struct kvec iov = {.iov_base = buf, .iov_len = size};
    struct msghdr msg = {.msg_flags = flags};
    return kernel_sendmsg(conn_socket, &msg, &iov, 1, iov.iov_len);
}

int ksock_send_all(struct socket *conn_socket, char *buf, size_t size,
                   int flags) {
    int ret;
    int remaining = size;
    while (remaining) {
        ret = ksock_send(conn_socket, buf, remaining, flags);
        if (signal_pending(current)) return -1;
        if (ret >= 0) {
            remaining -= ret;
            buf += ret;
        } else if (ret < 0) {
            return ret;
        }
    }
    return size;
}
