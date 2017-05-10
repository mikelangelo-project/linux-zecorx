
#ifndef __METH_UTILS_H
#define __METH_UTILS_H

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/uio.h>


void skb_print(struct sk_buff *skb);
void my_netdev_printk(struct net_device *dev);
int map_iovec_to_skb(struct sk_buff *skb, struct iov_iter *from);
void iov_iter_print (struct iov_iter *iter);
void addr_print (unsigned char *addr);
void buf_print(void *buf, int len);




#endif /* __METH_UTILS_H */
