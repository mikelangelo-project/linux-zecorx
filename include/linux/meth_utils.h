
#ifndef __METH_UTILS_H
#define __METH_UTILS_H

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/uio.h>


void skb_print(struct sk_buff *skb);
void my_netdev_printk(const struct net_device *dev);
int map_iovec_to_skb(struct sk_buff *skb, struct iov_iter *from);




#endif /* __METH_UTILS_H */
