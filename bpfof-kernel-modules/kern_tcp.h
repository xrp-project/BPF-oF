#ifndef _KERN_TCP_H
#define _KERN_TCP_H

#include <linux/net.h>
#include <linux/types.h>
#include <uapi/linux/in.h>

void inet_ntoa(struct in_addr *in, char *str_ip);
int ksock_recv(struct socket *conn_socket, char *buf, size_t size, int flags);
int ksock_recv_all(struct socket *conn_socket, char *buf, size_t size,
                   int flags);
int ksock_send(struct socket *conn_socket, char *buf, size_t size, int flags);
int ksock_send_all(struct socket *conn_socket, char *buf, size_t size,
                   int flags);
#endif /* _KERN_TCP_H */
