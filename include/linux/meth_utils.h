
#ifndef __METH_UTILS_H
#define __METH_UTILS_H

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/uio.h>
#include <linux/scatterlist.h>
#include <linux/mm_types.h>
#include <linux/wait.h>
#include <linux/list.h>

/* used to hold information about pages used for zero-copy receive */
struct vhost_page_info {
	struct hlist_node h_link;
	int desc;
	int offset;
	struct page *page;
	int len;
	void (*callback)(struct vhost_page_info *);
	void *vnet_hdr;
	void *virt_page_addr;
	int virt_page_len;
	struct vhost_virtqueue *vq;
};

typedef unsigned long long timestamp_t;

void skb_print(struct sk_buff *skb);
void skb_print_short(struct sk_buff *skb);
void skb_frag_print(struct sk_buff *skb, int frag_num);
void my_netdev_printk(struct net_device *dev);
int map_iovec_to_skb(struct sk_buff *skb, struct iov_iter *from);
void iov_iter_print (struct iov_iter *iter);
void addr_print (unsigned char *addr);
void buf_print(void *buf, int len);
void unmap_skb_frags(struct sk_buff *skb);
void scatterlist_print(struct scatterlist *sg, int n_segs);
void wait_queue_entry_print(wait_queue_t *w);
void wait_queue_print(wait_queue_head_t *wqh);

#define MSG_ZCOPY_RX		0x400000
#define MSG_ZCOPY_RX_POST	0x800000

#endif /* __METH_UTILS_H */
