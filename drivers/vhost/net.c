/* Copyright (C) 2009 Red Hat, Inc.
 * Author: Michael S. Tsirkin <mst@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 * virtio-net server in host kernel.
 */

#include <linux/compat.h>
#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include <linux/net.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <linux/if_macvlan.h>
#include <linux/if_vlan.h>
#include <linux/meth_utils.h>

#include <net/sock.h>

#include "vhost.h"

static int experimental_zcopytx = 1;
static int experimental_zcopyrx = 1;
module_param(experimental_zcopytx, int, 0444);
MODULE_PARM_DESC(experimental_zcopytx, "Enable Zero Copy TX;"
		                       " 1 -Enable; 0 - Disable");
module_param(experimental_zcopyrx, int, 0444);
MODULE_PARM_DESC(experimental_zcopyrx, "Enable Zero Copy RX;"
		                       " 1 -Enable; 0 - Disable");

/* Max number of bytes transferred before requeueing the job.
 * Using this limit prevents one virtqueue from starving others. */
#define VHOST_NET_WEIGHT 0x80000

/* MAX number of TX used buffers for outstanding zerocopy */
#define VHOST_MAX_PEND 128
#define VHOST_GOODCOPY_LEN 256

/*
 * For transmit, used buffer len is unused; we override it to track buffer
 * status internally; used for zerocopy tx only.
 * xxx Not any more!!! added separate field to be able to track zero copy rx buffer, plus its length
 */
/* Lower device DMA failed */
#define VHOST_DMA_FAILED_LEN	((__force __virtio32)3)
/* Lower device DMA done */
#define VHOST_DMA_DONE_LEN	((__force __virtio32)2)
/* Lower device DMA in progress */
#define VHOST_DMA_IN_PROGRESS	((__force __virtio32)1)
/* Buffer unused */
#define VHOST_DMA_CLEAR_LEN	((__force __virtio32)0)

#define VHOST_DMA_IS_DONE(len) ((__force u32)(len) >= (__force u32)VHOST_DMA_DONE_LEN)

enum {
	VHOST_NET_FEATURES = VHOST_FEATURES |
			 (1ULL << VHOST_NET_F_VIRTIO_NET_HDR) |
			 (1ULL << VIRTIO_NET_F_MRG_RXBUF) |
			 (1ULL << VIRTIO_F_IOMMU_PLATFORM)
};

unsigned long long vhost_net_features;

enum {
	VHOST_NET_VQ_RX = 0,
	VHOST_NET_VQ_TX = 1,
	VHOST_NET_VQ_MAX = 2,
};

struct vhost_net_ubuf_ref {
	/* refcount follows semantics similar to kref:
	 *  0: object is released
	 *  1: no outstanding ubufs
	 * >1: outstanding ubufs
	 */
	atomic_t refcount;
	wait_queue_head_t wait;
	struct vhost_virtqueue *vq;
};

struct vhost_net_virtqueue {
	struct vhost_virtqueue vq;
	size_t vhost_hlen;
	size_t sock_hlen;
	/* vhost zerocopy support fields below: */
	/* last used idx for outstanding DMA zerocopy buffers */
	int upend_idx;
	/* first used idx for DMA done zerocopy buffers */
	int done_idx;
	/* an array of userspace buffers info */
	struct ubuf_info *ubuf_info;
	/* Reference counting for outstanding ubufs.
	 * Protected by vq mutex. Writers must also take device mutex. */
	struct vhost_net_ubuf_ref *ubufs;
};

struct vhost_net {
	struct vhost_dev dev;
	struct vhost_net_virtqueue vqs[VHOST_NET_VQ_MAX];
	struct vhost_poll poll[VHOST_NET_VQ_MAX];
	/* Number of TX recently submitted.
	 * Protected by tx vq lock. */
	unsigned tx_packets;
	/* Number of times zerocopy TX recently failed.
	 * Protected by tx vq lock. */
	unsigned tx_zcopy_err;
	/* Flush in progress. Protected by tx vq lock. */
	bool tx_flush;
};

static struct kmem_cache *vhost_desc_slab = NULL;

static unsigned vhost_net_zcopy_mask __read_mostly;

static void vhost_net_enable_zcopy(int vq)
{
	vhost_net_zcopy_mask |= 0x1 << vq;
}

static struct vhost_net_ubuf_ref *
vhost_net_ubuf_alloc(struct vhost_virtqueue *vq, bool zcopy)
{
	struct vhost_net_ubuf_ref *ubufs;
	/* No zero copy backend? Nothing to count. */
	if (!zcopy)
		return NULL;
	ubufs = kmalloc(sizeof(*ubufs), GFP_KERNEL);
	if (!ubufs)
		return ERR_PTR(-ENOMEM);
	atomic_set(&ubufs->refcount, 1);
	init_waitqueue_head(&ubufs->wait);
	ubufs->vq = vq;
	return ubufs;
}

static int vhost_net_ubuf_put(struct vhost_net_ubuf_ref *ubufs)
{
	int r = atomic_sub_return(1, &ubufs->refcount);
	if (unlikely(!r))
		wake_up(&ubufs->wait);
	return r;
}

static void vhost_net_ubuf_put_and_wait(struct vhost_net_ubuf_ref *ubufs)
{
	vhost_net_ubuf_put(ubufs);
	wait_event(ubufs->wait, !atomic_read(&ubufs->refcount));
}

static void vhost_net_ubuf_put_wait_and_free(struct vhost_net_ubuf_ref *ubufs)
{
	vhost_net_ubuf_put_and_wait(ubufs);
	kfree(ubufs);
}

static void vhost_net_clear_ubuf_info(struct vhost_net *n)
{
	int i;

	for (i = 0; i < VHOST_NET_VQ_MAX; ++i) {
		kfree(n->vqs[i].ubuf_info);
		n->vqs[i].ubuf_info = NULL;
	}
}

static int vhost_net_set_ubuf_info(struct vhost_net *n)
{
	bool zcopy;
	int i;

	//printk(KERN_ERR "entering vhost_net_set_ubuf_info, vhost_net = %p \n", n);
	for (i = 0; i < VHOST_NET_VQ_MAX; ++i) {
		zcopy = vhost_net_zcopy_mask & (0x1 << i);
		//printk(KERN_ERR "vhost_net_set_ubuf_info, vhost_net_zcopy_mask = %x, i = %d, zcopy = %d \n", vhost_net_zcopy_mask, i, zcopy);
		if (!zcopy)
			continue;
		n->vqs[i].ubuf_info = kmalloc(sizeof(*n->vqs[i].ubuf_info) *
					      UIO_MAXIOV, GFP_KERNEL);
		if  (!n->vqs[i].ubuf_info)
			goto err;
	}
	return 0;

err:
	vhost_net_clear_ubuf_info(n);
	return -ENOMEM;
}

static void vhost_net_vq_reset(struct vhost_net *n)
{
	int i;

	vhost_net_clear_ubuf_info(n);

	for (i = 0; i < VHOST_NET_VQ_MAX; i++) {
		n->vqs[i].done_idx = 0;
		n->vqs[i].upend_idx = 0;
		n->vqs[i].ubufs = NULL;
		n->vqs[i].vhost_hlen = 0;
		n->vqs[i].sock_hlen = 0;
	}

}

static void vhost_net_tx_packet(struct vhost_net *net)
{
	++net->tx_packets;
	if (net->tx_packets < 1024)
		return;
	net->tx_packets = 0;
	net->tx_zcopy_err = 0;
}

static void vhost_net_tx_err(struct vhost_net *net)
{
	++net->tx_zcopy_err;
}

static bool vhost_net_tx_select_zcopy(struct vhost_net *net)
{
	/* TX flush waits for outstanding DMAs to be done.
	 * Don't start new DMAs.
	 */
	return !net->tx_flush &&
		net->tx_packets / 64 >= net->tx_zcopy_err;
}

static bool vhost_sock_zcopy_tx(struct socket *sock)
{
	return unlikely(experimental_zcopytx) &&
		sock_flag(sock->sk, SOCK_ZEROCOPY);
}

/* In case of DMA done not in order in lower device driver for some reason.
 * upend_idx is used to track end of used idx, done_idx is used to track head
 * of used idx. Once lower device DMA done contiguously, we will signal KVM
 * guest used idx.
 */
static void vhost_zerocopy_signal_used(struct vhost_net *net,
				       struct vhost_virtqueue *vq)
{
	struct vhost_net_virtqueue *nvq =
		container_of(vq, struct vhost_net_virtqueue, vq);
	int i, add;
	int j = 0;

	//printk(KERN_ERR "entering vhost_zerocopy_signal_used, net = %p, vq = %p, nvq = %p \n",net, vq, nvq);
	//printk(KERN_ERR "vhost_zerocopy_signal_used, done_idx = %d, upend_idx = %d \n", nvq->done_idx, nvq->upend_idx);
	//printk(KERN_ERR "vhost_zerocopy_signal_used, avail_idx = %d, last_avail_idx = %d, last_used_idx = %d \n", vq->avail_idx, vq->last_avail_idx, vq->last_used_idx);
	for (i = nvq->done_idx; i != nvq->upend_idx; i = (i + 1) % UIO_MAXIOV) {
		//printk(KERN_ERR "vhost_zerocopy_signal_used, i = %d, len = %d \n", i, vq->heads[i].len);
		if (vq->heads[i].len == VHOST_DMA_FAILED_LEN)
			vhost_net_tx_err(net);
		if (VHOST_DMA_IS_DONE(vq->heads[i].len)) {
			vq->heads[i].len = VHOST_DMA_CLEAR_LEN;
			++j;
		} else
			break;
	}
	while (j) {
		add = min(UIO_MAXIOV - nvq->done_idx, j);
		//printk(KERN_ERR "vhost_zerocopy_signal_used, j = %d, add = %d \n", j, add);
		{
		int i;
		for (i = 0; i < add; i++) {
			vq->heads[i+nvq->done_idx].offset = 0;
			vq->heads[i+nvq->done_idx].pad = 0;
		}
		}
		vhost_add_used_and_signal_n(vq->dev, vq,
					    &vq->heads[nvq->done_idx], add);
		nvq->done_idx = (nvq->done_idx + add) % UIO_MAXIOV;
		j -= add;
	}
	//printk(KERN_ERR "exiting vhost_zerocopy_signal_used, net = %p, vq = %p, nvq = %p \n",net, vq, nvq);
}

static void vhost_rx_zc_callback(struct vhost_page_info *v_page_info)
{
	struct vhost_virtqueue *vq = v_page_info->vq;
	int desc = v_page_info->desc;

	//printk(KERN_ERR "entering vhost_rx_zc_callback, v_page_info = %p \n", v_page_info);
	// KM - xxx - perhaps just recycle the buffer
	//len += sizeof(struct virtio_net_hdr_mrg_rxbuf);
	rcu_read_lock_bh();
	vhost_add_used(vq, desc, 0);
	vq->live_bufs--;
	kmem_cache_free(vhost_desc_slab, v_page_info);
	vhost_poll_queue(&vq->poll);
	rcu_read_unlock_bh();
}

static void vhost_zerocopy_callback(struct ubuf_info *ubuf, bool success)
{
	struct vhost_net_ubuf_ref *ubufs = ubuf->ctx;
	struct vhost_virtqueue *vq = ubufs->vq;
	int cnt;

	//printk(KERN_ERR "entering vhost_zerocopy_callback, ubuf = %p, success = %d \n", ubuf, success);
	//printk(KERN_ERR "vhost_zerocopy_callback, ubuf = %p, desc = %d \n", ubuf, ubuf->desc);
	rcu_read_lock_bh();

	/* set len to mark this desc buffers done DMA */
	vq->heads[ubuf->desc].len = success ?
		VHOST_DMA_DONE_LEN : VHOST_DMA_FAILED_LEN;
	cnt = vhost_net_ubuf_put(ubufs);

	/*
	 * Trigger polling thread if guest stopped submitting new buffers:
	 * in this case, the refcount after decrement will eventually reach 1.
	 * We also trigger polling periodically after each 16 packets
	 * (the value 16 here is more or less arbitrary, it's tuned to trigger
	 * less than 10% of times).
	 */
	if (cnt <= 1 || !(cnt % 16))
		vhost_poll_queue(&vq->poll);

	rcu_read_unlock_bh();
}

static inline unsigned long busy_clock(void)
{
	return local_clock() >> 10;
}

static bool vhost_can_busy_poll(struct vhost_dev *dev,
				unsigned long endtime)
{
	return likely(!need_resched()) &&
	       likely(!time_after(busy_clock(), endtime)) &&
	       likely(!signal_pending(current)) &&
	       !vhost_has_work(dev);
}

static void vhost_net_disable_vq(struct vhost_net *n,
				 struct vhost_virtqueue *vq)
{
	struct vhost_net_virtqueue *nvq =
		container_of(vq, struct vhost_net_virtqueue, vq);
	struct vhost_poll *poll = n->poll + (nvq - n->vqs);
	//printk(KERN_ERR "entering vhost_net_disable_vq, current = %p \n", current);
	if (!vq->private_data)
		return;
	//printk(KERN_ERR "vhost_net_disable_vq: before vhost_poll_stop \n");
	vhost_poll_stop(poll);
	//printk(KERN_ERR "exiting vhost_net_disable_vq, current = %p \n", current);
}

static int vhost_net_enable_vq(struct vhost_net *n,
				struct vhost_virtqueue *vq)
{
	struct vhost_net_virtqueue *nvq =
		container_of(vq, struct vhost_net_virtqueue, vq);
	struct vhost_poll *poll = n->poll + (nvq - n->vqs);
	struct socket *sock;

	sock = vq->private_data;
	if (!sock)
		return 0;

	return vhost_poll_start(poll, sock->file);
}

static int vhost_net_tx_get_vq_desc(struct vhost_net *net,
				    struct vhost_virtqueue *vq,
				    struct iovec iov[], unsigned int iov_size,
				    unsigned int *out_num, unsigned int *in_num)
{
	unsigned long uninitialized_var(endtime);
	int r = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov),
				  out_num, in_num, NULL, NULL);

	if (r == vq->num && vq->busyloop_timeout) {
		preempt_disable();
		endtime = busy_clock() + vq->busyloop_timeout;
		while (vhost_can_busy_poll(vq->dev, endtime) &&
		       vhost_vq_avail_empty(vq->dev, vq))
			cpu_relax_lowlatency();
		preempt_enable();
		r = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov),
				      out_num, in_num, NULL, NULL);
	}

	return r;
}

/* Expects to be always run from workqueue - which acts as
 * read-size critical section for our kind of RCU. */
static void handle_tx(struct vhost_net *net)
{
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_TX];
	struct vhost_virtqueue *vq = &nvq->vq;
	unsigned out, in;
	int head;
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = MSG_DONTWAIT,
	};
	size_t len, total_len = 0;
	int err;
	size_t hdr_size;
	struct socket *sock;
	struct vhost_net_ubuf_ref *uninitialized_var(ubufs);
	bool zcopy, zcopy_used;

	mutex_lock(&vq->mutex);
	sock = vq->private_data;
	if (!sock)
		goto out;

	if (!vq_iotlb_prefetch(vq))
		goto out;

	vhost_disable_notify(&net->dev, vq);

	hdr_size = nvq->vhost_hlen;
	zcopy = nvq->ubufs;

	//printk(KERN_ERR "entering handle_tx, vq = %p, zcopy = %d, hdr_size = %d \n", vq, zcopy, hdr_size);
	for (;;) {
		/* Release DMAs done buffers first */
		if (zcopy)
			vhost_zerocopy_signal_used(net, vq);

		/* If more outstanding DMAs, queue the work.
		 * Handle upend_idx wrap around
		 */
		if (unlikely((nvq->upend_idx + vq->num - VHOST_MAX_PEND)
			      % UIO_MAXIOV == nvq->done_idx))
			break;

		head = vhost_net_tx_get_vq_desc(net, vq, vq->iov,
						ARRAY_SIZE(vq->iov),
						&out, &in);
		/* On error, stop handling until the next kick. */
		if (unlikely(head < 0))
			break;
		/* Nothing new?  Wait for eventfd to tell us they refilled. */
		if (head == vq->num) {
			if (unlikely(vhost_enable_notify(&net->dev, vq))) {
				vhost_disable_notify(&net->dev, vq);
				continue;
			}
			break;
		}
		if (in) {
			vq_err(vq, "Unexpected descriptor format for TX: "
			       "out %d, int %d\n", out, in);
			break;
		}
		/* Skip header. TODO: support TSO. */
		//vhost_virtqueue_print(vq);
		len = iov_length(vq->iov, out);
		iov_iter_init(&msg.msg_iter, WRITE, vq->iov, out, len);
		iov_iter_advance(&msg.msg_iter, hdr_size);
		//iov_iter_print(&msg.msg_iter);
		/* Sanity check */
		if (!msg_data_left(&msg)) {
			vq_err(vq, "Unexpected header len for TX: "
			       "%zd expected %zd\n",
			       len, hdr_size);
			break;
		}
		len = msg_data_left(&msg);

		zcopy_used = zcopy && len >= VHOST_GOODCOPY_LEN
				   && (nvq->upend_idx + 1) % UIO_MAXIOV !=
				      nvq->done_idx
				   && vhost_net_tx_select_zcopy(net);

		/* use msg_control to pass vhost zerocopy ubuf info to skb */
		if (zcopy_used) {
			struct ubuf_info *ubuf;
			ubuf = nvq->ubuf_info + nvq->upend_idx;

			vq->heads[nvq->upend_idx].id = cpu_to_vhost32(vq, head);
			vq->heads[nvq->upend_idx].len = VHOST_DMA_IN_PROGRESS;
			ubuf->callback = vhost_zerocopy_callback;
			ubuf->ctx = nvq->ubufs;
			ubuf->desc = nvq->upend_idx;
			msg.msg_control = ubuf;
			msg.msg_controllen = sizeof(ubuf);
			ubufs = nvq->ubufs;
			atomic_inc(&ubufs->refcount);
			nvq->upend_idx = (nvq->upend_idx + 1) % UIO_MAXIOV;
		} else {
			msg.msg_control = NULL;
			ubufs = NULL;
		}
		/* TODO: Check specific error and bomb out unless ENOBUFS? */
		err = sock->ops->sendmsg(sock, &msg, len);
		if (unlikely(err < 0)) {
			if (zcopy_used) {
				vhost_net_ubuf_put(ubufs);
				nvq->upend_idx = ((unsigned)nvq->upend_idx - 1)
					% UIO_MAXIOV;
			}
			vhost_discard_vq_desc(vq, 1);
			break;
		}
		if (err != len)
			pr_debug("Truncated TX packet: "
				 " len %d != %zd\n", err, len);
		if (!zcopy_used)
			vhost_add_used_and_signal(&net->dev, vq, head, 0);
		else
			vhost_zerocopy_signal_used(net, vq);
		total_len += len;
		vhost_net_tx_packet(net);
		if (unlikely(total_len >= VHOST_NET_WEIGHT)) {
			vhost_poll_queue(&vq->poll);
			break;
		}
	}
out:
	mutex_unlock(&vq->mutex);
}

static int peek_head_len(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;
	struct sk_buff *head;
	int len = 0;
	unsigned long flags;

	if (sock->ops->peek_len)
		return sock->ops->peek_len(sock);

	spin_lock_irqsave(&sk->sk_receive_queue.lock, flags);
	head = skb_peek(&sk->sk_receive_queue);
	if (likely(head)) {
		len = head->len;
		if (skb_vlan_tag_present(head))
			len += VLAN_HLEN;
	}

	spin_unlock_irqrestore(&sk->sk_receive_queue.lock, flags);
	return len;
}

static int sk_has_rx_data(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;

	if (sock->ops->peek_len)
		return sock->ops->peek_len(sock);

	return skb_queue_empty(&sk->sk_receive_queue);
}

static int vhost_net_rx_peek_head_len(struct vhost_net *net, struct sock *sk)
{
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_TX];
	struct vhost_virtqueue *vq = &nvq->vq;
	unsigned long uninitialized_var(endtime);
	int len = peek_head_len(sk);

	if (!len && vq->busyloop_timeout) {
		/* Both tx vq and rx socket were polled here */
		mutex_lock(&vq->mutex);
		vhost_disable_notify(&net->dev, vq);

		preempt_disable();
		endtime = busy_clock() + vq->busyloop_timeout;

		while (vhost_can_busy_poll(&net->dev, endtime) &&
		       !sk_has_rx_data(sk) &&
		       vhost_vq_avail_empty(&net->dev, vq))
			cpu_relax_lowlatency();

		preempt_enable();

		if (vhost_enable_notify(&net->dev, vq))
			vhost_poll_queue(&vq->poll);
		mutex_unlock(&vq->mutex);

		len = peek_head_len(sk);
	}

	return len;
}

/* This is a multi-buffer version of vhost_get_desc, that works if
 *	vq has read descriptors only.
 * @vq		- the relevant virtqueue
 * @datalen	- data length we'll be reading
 * @iovcount	- returned count of io vectors we fill
 * @log		- vhost log
 * @log_num	- log offset
 * @quota       - headcount quota, 1 for big buffer
 *	returns number of buffer heads allocated, negative on error
 */
static int get_rx_bufs(struct vhost_virtqueue *vq,
		       struct vring_used_elem *heads,
		       int datalen,
		       unsigned *iovcount,
		       struct vhost_log *log,
		       unsigned *log_num,
		       unsigned int quota)
{
	unsigned int out, in;
	int seg = 0;
	int headcount = 0;
	unsigned d;
	int r, nlogs = 0;
	/* len is always initialized before use since we are always called with
	 * datalen > 0.
	 */
	u32 uninitialized_var(len);

	//printk(KERN_ERR "entering get_rx_bufs, vq = %p, datalen = %d, quota = %d \n", vq, datalen, quota);
	//vhost_virtqueue_print_short(vq);
	while (datalen > 0 && headcount < quota) {
		if (unlikely(seg >= UIO_MAXIOV)) {
			r = -ENOBUFS;
			goto err;
		}
		r = vhost_get_vq_desc(vq, vq->iov + seg,
				      ARRAY_SIZE(vq->iov) - seg, &out,
				      &in, log, log_num);
		if (unlikely(r < 0))
			goto err;

		d = r;
		if (d == vq->num) {
			r = 0;
			goto err;
		}
		if (unlikely(out || in <= 0)) {
			vq_err(vq, "unexpected descriptor format for RX: "
				"out %d, in %d\n", out, in);
			r = -EINVAL;
			goto err;
		}
		if (unlikely(log)) {
			nlogs += *log_num;
			log += *log_num;
		}
		heads[headcount].id = cpu_to_vhost32(vq, d);
		len = iov_length(vq->iov + seg, in);
		heads[headcount].len = cpu_to_vhost32(vq, len);
		datalen -= len;
		++headcount;
		seg += in;
	}
	heads[headcount - 1].len = cpu_to_vhost32(vq, len + datalen);
	*iovcount = seg;
	if (unlikely(log))
		*log_num = nlogs;

	/* Detect overrun */
	if (unlikely(datalen > 0)) {
		r = UIO_MAXIOV + 1;
		goto err;
	}
	//printk(KERN_ERR "exiting get_rx_bufs, vq = %p, headcount = %d, len = %d \n", vq, headcount, heads[headcount - 1].len);
	//vhost_virtqueue_print(vq);
	return headcount;
err:
	vhost_discard_vq_desc(vq, headcount);
	return r;
}

static struct vhost_page_info *zcrx_vhost_get_vq_desc(struct vhost_net *net, struct vhost_virtqueue *vq)
{
	struct vhost_page_info *v_page_info;
	int in, out;
	int desc;

	if (vq->saved_desc_page_info) {
		v_page_info = vq->saved_desc_page_info;
		vq->saved_desc_page_info = NULL;
		return v_page_info;
	}

	v_page_info = kmem_cache_alloc(vhost_desc_slab, GFP_KERNEL);
	if (!v_page_info)
		return NULL;
	INIT_HLIST_NODE(&v_page_info->h_link);
	desc = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov), &out, &in, NULL, NULL);
	if (desc == vq->num) {
		return NULL;
	}

	if (out) {
		vq_err(vq, "Unexpected descriptor format for RX: "
		       "out %d, int %d\n", out, in);
		return NULL;
	}
	if (in != 2) {
		vq_err(vq, "Unexpected descriptor format for RX: "
		       "out %d, int %d\n", out, in);
		return NULL;
	}
	v_page_info->desc = desc;
	v_page_info->callback = vhost_rx_zc_callback;
	v_page_info->vnet_hdr = vq->iov[0].iov_base;
	/* xxx verify sizes of vnet_hdr and page len */
	v_page_info->vq = vq;
	v_page_info->virt_page_addr = vq->iov[1].iov_base;
	v_page_info->virt_page_len = vq->iov[1].iov_len;
	v_page_info->offset = 0;
	return v_page_info;
}

static int post_buffers(struct vhost_net *net)
{
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_RX];
	struct vhost_virtqueue *vq = &nvq->vq;
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_control = NULL, /* used to  handle RX aux data */
		.msg_controllen = 0,
		.msg_flags = MSG_DONTWAIT,
	};
	int ret = 0;
	struct socket *sock;
	int num_bufs_posted = 0;
	struct vhost_page_info *v_page_info;

	//printk(KERN_ERR "entering post_buffers, vq = %p, live_bufs = %d \n", vq, vq->live_bufs);

	sock = vq->private_data;


	while (true) {
		/* post next buffer; see if we already have one that we took off the queue and needed to wait */
		//printk(KERN_ERR "post_buffers, saved_desc_page_info = %d \n", vq->saved_desc_page_info);
		v_page_info = zcrx_vhost_get_vq_desc(net, vq);

		/* No buffers? check if additional buffers were posted */
		if (unlikely(!v_page_info)) {
			break;
		}
		vq->live_bufs++;

		msg.msg_control = v_page_info;
		msg.msg_controllen = sizeof(v_page_info);

		ret = sock->ops->recvmsg(sock, &msg, 1, MSG_ZCOPY_RX_POST);
		//printk(KERN_ERR "post_buffers, ret = %d \n", ret);
		// update counters of vhost ring buffer. check for EAGAIN
		if (ret == -EAGAIN) {
			//printk(KERN_ERR "post_buffers, EAGAIN; saved head = %d \n", head);
			vq->saved_desc_page_info = v_page_info;
			vq->live_bufs--;
			break;
		}
		else if (unlikely(ret < 0)) {
			printk(KERN_ERR "post_buffers, error in recvmsg; ret = %d, do something!!! \n", ret);
			vq->saved_desc_page_info = v_page_info;
			vq->live_bufs--;
			/* xxx KM fix this */
			break;
		}
		//printk(KERN_ERR "post_buffers, desc = %d, v_page_info = %p, vnet_hdr = %p \n", v_page_info->desc, v_page_info, v_page_info->vnet_hdr);
		num_bufs_posted++;
	}
	//printk(KERN_ERR "post_buffers: num_bufs_posted = %d \n", num_bufs_posted);
	//if (vhost_enable_notify(&net->dev, vq) || num_bufs_posted)
	if (num_bufs_posted)
	{
		/* need to schedule posting of additional available buffers */
		//printk(KERN_ERR "post_buffers, vq = %p, num_bufs_posted = %d, live_bufs = %d \n", vq, num_bufs_posted, vq->live_bufs);
		//vhost_poll_queue(&vq->poll);
	}

	//printk(KERN_ERR "post_buffers, vq = %p, num_bufs_posted = %d, live_bufs = %d \n", vq, num_bufs_posted, vq->live_bufs);
	//vhost_enable_notify(&net->dev, vq);
	return num_bufs_posted;
}

/*
* must hold lock when calling this function
*/
static void handle_rx_zcopy(struct vhost_net *net)
{
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_RX];
	struct vhost_virtqueue *vq = &nvq->vq;
	//int hdr_size;
	struct socket * sock;
	int ret;
	//int cnt = 0;
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_flags = MSG_DONTWAIT,
	};
	struct vhost_page_info *v_page_info;
	int i, j;
	struct vring_used_elem *v_used_elem;
	//__virtio16 num_buffers;
	struct virtio_net_hdr_mrg_rxbuf *vnet_hdr;
	struct virtio_net_hdr_mrg_rxbuf vnet_hdr2 = {
		.hdr.flags = VIRTIO_NET_HDR_F_DATA_VALID, /* temporary hack until we properly handle checksums */
		//.hdr.flags = 0, 
		.hdr.gso_type = VIRTIO_NET_HDR_GSO_NONE
	};
	int n_buffers = 0;
	int start, end;
	int cnt = 0;
	size_t total_len = 0;
	int sock_len;

	//printk(KERN_ERR "entering handle_rx_zcopy, vq = %p, current = %p \n", vq, current);

	sock = vq->private_data;
	if (!sock) {
		//printk(KERN_ERR "handle_rx_zcopy, sock not set \n");
		goto out;
	}

	//printk(KERN_ERR "handle_rx_zcopy, before vq_iotlb_prefetch \n");
	// xxx KM what does this do? why does it take so long?
	if (!vq_iotlb_prefetch(vq))
		goto out;

	//printk(KERN_ERR "handle_rx_zcopy, before vhost_disable_notify \n");
	vhost_disable_notify(&net->dev, vq);
	//printk(KERN_ERR "handle_rx_zcopy, before vhost_net_disable_vq \n");
	vhost_net_disable_vq(net, vq);
	//printk(KERN_ERR "handle_rx_zcopy, after vhost_net_disable_vq \n");

	post_buffers(net);

	//hdr_size = nvq->vhost_hlen;
	//hdr_size = nvq->vhost_hlen + nvq->sock_hlen;

	/* free up used buffers back to guest */
	//vhost_zerocopy_signal_used(net, vq);
	if (!vq->saved_desc_page_info) {
		vq->saved_desc_page_info = zcrx_vhost_get_vq_desc(net, vq);
	}

	//printk(KERN_ERR "handle_rx_zcopy, before peek_head_len \n");
	//while(true)
	//while ((sock_len = vhost_net_rx_peek_head_len(net, sock->sk)))
	while ((sock_len = peek_head_len(sock->sk)))
	{
		msg.msg_control = vq->v_page_info;
		msg.msg_controllen = sizeof(vq->v_page_info);
		vq->v_page_info[0] = vq->saved_desc_page_info;
		//printk(KERN_ERR "handle_rx_zcopy, before recvmsg MSG_ZCOPY_RX \n");
		n_buffers = sock->ops->recvmsg(sock, &msg, 1, MSG_ZCOPY_RX | MSG_DONTWAIT);
		//printk(KERN_ERR "handle_rx_zcopy, after recvmsg MSG_ZCOPY_RX, n_buffers = %d \n", n_buffers);
		if (n_buffers <= 0) {
			break;
		}
		//cnt += ret;
		/* build the vring_used_elem for the used buffers */
		if (vq->v_page_info[0]) {
			/* it was used by driver to copy into it an skb */
			printk(KERN_ERR "handle_rx_zcopy, using v_page_info[0] \n");
			vq->saved_desc_page_info = NULL;
			vnet_hdr = vq->v_page_info[0]->vnet_hdr;
			start = 0;
			end = n_buffers-1;
			if (n_buffers > 1) {
				printk(KERN_ERR "handle_rx_zcopy, error: n_buffers = %d \n", n_buffers);
			}
			/* prepare a new spare buffer for next read attempt */
			vq->saved_desc_page_info = zcrx_vhost_get_vq_desc(net, vq);
		}
		else {
			vnet_hdr = vq->v_page_info[1]->vnet_hdr;
			start = 1;
			end = n_buffers;
		}
		//printk(KERN_ERR "handle_rx_zcopy, start = %d, end = %d \n", start, end);
		for (i = start, j = 0; i <= end; i++, j++) {
			v_page_info = vq->v_page_info[i];
			//printk(KERN_ERR "handle_rx_zcopy, v_page_info = %p \n", v_page_info);
			v_used_elem = &vq->heads[j];
			//printk(KERN_ERR "handle_rx_zcopy, j = %d, v_used_elem = %p \n", j, v_used_elem);
			v_used_elem->len = cpu_to_vhost16(vq, v_page_info->len);
			v_used_elem->id = cpu_to_vhost16(vq, v_page_info->desc);
			v_used_elem->offset = cpu_to_vhost16(vq, v_page_info->offset);
			v_used_elem->pad = 0;
			total_len += v_page_info->len;

			//printk(KERN_ERR "handle_rx_zcopy, len = %d, desc = %d \n", v_page_info->len, v_page_info->desc);
			/* add back in the vhost header size into bytes consumed */
			//v_used_elem->len += hdr_size;
			//v_used_elem->len += v_page_info->offset;
			kmem_cache_free(vhost_desc_slab, v_page_info);
		}
		/* need to patch num_buffers in VNET hdr */
		vnet_hdr2.num_buffers = cpu_to_vhost16(vq, n_buffers);
		//printk(KERN_ERR "handle_rx_zcopy, num_buffers = %d, vnet_hdr = %p, flags = %x, gso_type = %d \n", n_buffers, vnet_hdr, vnet_hdr2.hdr.flags, vnet_hdr2.hdr.gso_type);
		ret = __copy_to_user(vnet_hdr, &vnet_hdr2, sizeof(vnet_hdr2));
		if (ret < 0) {
			printk(KERN_ERR "handle_rx_zcopy: error in __copy_to_user = %d \n", ret);
		}
		vhost_add_used_and_signal_n(&net->dev, vq, vq->heads, n_buffers);
		//vhost_add_used_n(vq, vq->heads, n_buffers);
		vq->live_bufs -= n_buffers;
		//printk(KERN_ERR "handle_rx_zcopy, after vhost_add_used_and_signal \n");
		/* every so often, need to enable posting of additional buffers and to re-kick the handle_rx thread */
		/* values that work: 32, 16 */
		cnt += n_buffers;
#define BUF_WATERMARK	32
		if (cnt > BUF_WATERMARK) {
			//printk(KERN_ERR "handle_rx_zcopy, setting poll, poll = %p \n", &vq->poll);
			cnt = 0;
			post_buffers(net);
			//vhost_poll_queue(&vq->poll);
			//goto out;
			//break;
		}
		/*
		if (unlikely(total_len >= VHOST_NET_WEIGHT)) {
			//printk(KERN_ERR "handle_rx: total_len = %d \n", total_len);
			//vhost_signal(&net->dev, vq);
			vhost_poll_queue(&vq->poll);
			goto out;
			//break;
		}
		*/
	}
	//post_buffers(net);
	/*
	printk(KERN_ERR "handle_rx_zcopy, before if: total_len = %d \n", total_len);
	if (total_len) {
		vhost_signal(&net->dev, vq);
	}
	*/
	//vhost_poll_queue(&vq->poll);

	//printk(KERN_ERR "handle_rx_zcopy, before vhost_net_enable_vq \n");
	vhost_net_enable_vq(net, vq);
	//printk(KERN_ERR "handle_rx_zcopy, before vhost_enable_notify \n");
	vhost_enable_notify(&net->dev, vq);
	//printk(KERN_ERR "handle_rx_zcopy, after vhost_net_enable_vq \n");

out:
	//printk(KERN_ERR "exiting handle_rx_zcopy, vq = %p, cnt = %d, n_buffers = %d \n", vq, cnt, n_buffers);
	return;
}

/* Expects to be always run from workqueue - which acts as
 * read-size critical section for our kind of RCU. */
static void handle_rx(struct vhost_net *net)
{
	struct vhost_net_virtqueue *nvq = &net->vqs[VHOST_NET_VQ_RX];
	struct vhost_virtqueue *vq = &nvq->vq;
	unsigned uninitialized_var(in), log;
	struct vhost_log *vq_log;
	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_control = NULL, /* FIXME: get and handle RX aux data. */
		.msg_controllen = 0,
		.msg_flags = MSG_DONTWAIT,
	};
	struct virtio_net_hdr hdr = {
		.flags = 0,
		.gso_type = VIRTIO_NET_HDR_GSO_NONE
	};
	size_t total_len = 0;
	int err, mergeable;
	s16 headcount;
	size_t vhost_hlen, sock_hlen;
	size_t vhost_len, sock_len;
	struct socket *sock;
	struct iov_iter fixup;
	__virtio16 num_buffers;

	//printk(KERN_ERR "entering handle_rx, vq = %p \n", vq);
	mutex_lock(&vq->mutex);
	//vhost_virtqueue_print(vq);
	sock = vq->private_data;
	if (!sock)
		goto out;

	if (sock_flag(sock->sk, SOCK_ZEROCOPY_RX)) {
		handle_rx_zcopy(net);
		// go to out: in order to clean up and return.
		goto out;
	}

	if (!vq_iotlb_prefetch(vq))
		goto out;

	vhost_disable_notify(&net->dev, vq);
	vhost_net_disable_vq(net, vq);

	vhost_hlen = nvq->vhost_hlen;
	sock_hlen = nvq->sock_hlen;

	vq_log = unlikely(vhost_has_feature(vq, VHOST_F_LOG_ALL)) ?
		vq->log : NULL;
	mergeable = vhost_has_feature(vq, VIRTIO_NET_F_MRG_RXBUF);

	while ((sock_len = vhost_net_rx_peek_head_len(net, sock->sk))) {
		//printk(KERN_ERR "handle_rx, sock_len = %d, sock_hlen = %d \n", sock_len, sock_hlen);
		sock_len += sock_hlen;
		vhost_len = sock_len + vhost_hlen;
		headcount = get_rx_bufs(vq, vq->heads, vhost_len,
					&in, vq_log, &log,
					likely(mergeable) ? UIO_MAXIOV : 1);
		//printk(KERN_ERR "handle_rx, sock_len = %d, headcount = %d, vhost_len = %d \n", sock_len, headcount, vhost_len);
		/* On error, stop handling until the next kick. */
		if (unlikely(headcount < 0))
			goto out;
		/* On overrun, truncate and discard */
		if (unlikely(headcount > UIO_MAXIOV)) {
			iov_iter_init(&msg.msg_iter, READ, vq->iov, 1, 1);
			err = sock->ops->recvmsg(sock, &msg,
						 1, MSG_DONTWAIT | MSG_TRUNC);
			pr_debug("Discarded rx packet: len %zd\n", sock_len);
			continue;
		}
		/* OK, now we need to know about added descriptors. */
		if (!headcount) {
			if (unlikely(vhost_enable_notify(&net->dev, vq))) {
				/* They have slipped one in as we were
				 * doing that: check again. */
				vhost_disable_notify(&net->dev, vq);
				continue;
			}
			/* Nothing new?  Wait for eventfd to tell us
			 * they refilled. */
			goto out;
		}
		/* We don't need to be notified again. */
		iov_iter_init(&msg.msg_iter, READ, vq->iov, in, vhost_len);
		fixup = msg.msg_iter;
		//iov_iter_print(&fixup);
		if (unlikely((vhost_hlen))) {
			/* We will supply the header ourselves
			 * TODO: support TSO.
			 */
			iov_iter_advance(&msg.msg_iter, vhost_hlen);
		}
		//vhost_virtqueue_print(vq);
		err = sock->ops->recvmsg(sock, &msg,
					 sock_len, MSG_DONTWAIT | MSG_TRUNC);
		/* Userspace might have consumed the packet meanwhile:
		 * it's not supposed to do this usually, but might be hard
		 * to prevent. Discard data we got (if any) and keep going. */
		if (unlikely(err != sock_len)) {
			pr_debug("Discarded rx packet: "
				 " len %d, expected %zd\n", err, sock_len);
			vhost_discard_vq_desc(vq, headcount);
			continue;
		}
		/* Supply virtio_net_hdr if VHOST_NET_F_VIRTIO_NET_HDR */
		if (unlikely(vhost_hlen)) {
			if (copy_to_iter(&hdr, sizeof(hdr),
					 &fixup) != sizeof(hdr)) {
				vq_err(vq, "Unable to write vnet_hdr "
				       "at addr %p\n", vq->iov->iov_base);
				goto out;
			}
		} else {
			/* Header came from socket; we'll need to patch
			 * ->num_buffers over if VIRTIO_NET_F_MRG_RXBUF
			 */
			iov_iter_advance(&fixup, sizeof(hdr));
		}
		/* TODO: Should check and handle checksum. */

		num_buffers = cpu_to_vhost16(vq, headcount);
		//printk(KERN_ERR "handle_rx, num_buffers = %d \n", num_buffers);
		if (likely(mergeable) &&
		    copy_to_iter(&num_buffers, sizeof num_buffers,
				 &fixup) != sizeof num_buffers) {
			vq_err(vq, "Failed num_buffers write");
			vhost_discard_vq_desc(vq, headcount);
			goto out;
		}
		{
		int i;
		for (i = 0; i < headcount; i++) {
			vq->heads[i].offset = 0;
			vq->heads[i].pad = 0;
		}
		}
		vhost_add_used_and_signal_n(&net->dev, vq, vq->heads,
					    headcount);
		if (unlikely(vq_log))
			vhost_log_write(vq, vq_log, log, vhost_len);
		total_len += vhost_len;
		if (unlikely(total_len >= VHOST_NET_WEIGHT)) {
			//printk(KERN_ERR "handle_rx: before vhost_poll_queue \n");
			vhost_poll_queue(&vq->poll);
			goto out;
		}
		//iov_iter_print(&fixup);
	}
	//printk(KERN_ERR "handle_rx: before vhost_net_enable_vq \n");
	vhost_net_enable_vq(net, vq);
	//printk(KERN_ERR "handle_rx: after vhost_net_enable_vq \n");
out:
	//printk(KERN_ERR "exiting handle_rx, vq = %p \n", vq);
	//vhost_virtqueue_print(vq);
	mutex_unlock(&vq->mutex);
}

static void handle_tx_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						  poll.work);
	struct vhost_net *net = container_of(vq->dev, struct vhost_net, dev);

	handle_tx(net);
}

static void handle_rx_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						  poll.work);
	struct vhost_net *net = container_of(vq->dev, struct vhost_net, dev);

	handle_rx(net);
}

static void handle_tx_net(struct vhost_work *work)
{
	struct vhost_net *net = container_of(work, struct vhost_net,
					     poll[VHOST_NET_VQ_TX].work);
	handle_tx(net);
}

static void handle_rx_net(struct vhost_work *work)
{
	struct vhost_net *net = container_of(work, struct vhost_net,
					     poll[VHOST_NET_VQ_RX].work);
	handle_rx(net);
}

static int vhost_net_open(struct inode *inode, struct file *f)
{
	struct vhost_net *n;
	struct vhost_dev *dev;
	struct vhost_virtqueue **vqs;
	int i;
	//struct sock *sk;
	//void *p;

	printk(KERN_ERR "vhost_net_open: inode = %p, f = %p \n", inode, f);
	printk(KERN_ERR "vhost_net_open: current = %p \n", current);
	//p = f->private_data;
	/* xxx dirty hack - need the sock struct to be the first field of the private data */
	//sk = p;
	//printk(KERN_ERR "vhost_net_open: inode = %p, f = %p, sk = %p \n", inode, f, sk);

	vhost_net_features = VHOST_NET_FEATURES;
	//printk(KERN_ERR "entering vhost_net_open, vhost_net_features = %x \n", vhost_net_features);
	if (experimental_zcopyrx) {
		/* cancel the flags for merge buffers and for indirect blocks */
		/* xxx do this per device, and only if it will be zero-copy device */
		//vhost_net_features &= ~(1ULL << VIRTIO_NET_F_MRG_RXBUF);
		//vhost_net_features &= ~(1ULL << VIRTIO_NET_F_CSUM);
		//vhost_net_features &= ~(1ULL << VIRTIO_F_ANY_LAYOUT);
		//vhost_net_features &= ~(1ULL << VIRTIO_RING_F_INDIRECT_DESC);
		vhost_net_features |= (1ULL << VIRTIO_NET_ZERO_COPY_RX);
	}
	printk(KERN_ERR "vhost_net_open, vhost_net_features = %llx \n", vhost_net_features);

	n = kmalloc(sizeof *n, GFP_KERNEL | __GFP_NOWARN | __GFP_REPEAT);
	if (!n) {
		n = vmalloc(sizeof *n);
		if (!n)
			return -ENOMEM;
	}
	vqs = kmalloc(VHOST_NET_VQ_MAX * sizeof(*vqs), GFP_KERNEL);
	if (!vqs) {
		kvfree(n);
		return -ENOMEM;
	}

	dev = &n->dev;
	//printk(KERN_ERR "vhost_net_open, dev = %p \n", dev);
	vqs[VHOST_NET_VQ_TX] = &n->vqs[VHOST_NET_VQ_TX].vq;
	vqs[VHOST_NET_VQ_RX] = &n->vqs[VHOST_NET_VQ_RX].vq;
	n->vqs[VHOST_NET_VQ_TX].vq.handle_kick = handle_tx_kick;
	n->vqs[VHOST_NET_VQ_RX].vq.handle_kick = handle_rx_kick;
	for (i = 0; i < VHOST_NET_VQ_MAX; i++) {
		n->vqs[i].ubufs = NULL;
		n->vqs[i].ubuf_info = NULL;
		n->vqs[i].upend_idx = 0;
		n->vqs[i].done_idx = 0;
		n->vqs[i].vhost_hlen = 0;
		n->vqs[i].sock_hlen = 0;
	}
	vhost_dev_init(dev, vqs, VHOST_NET_VQ_MAX);

	vhost_poll_init(n->poll + VHOST_NET_VQ_TX, handle_tx_net, POLLOUT, dev);
	vhost_poll_init(n->poll + VHOST_NET_VQ_RX, handle_rx_net, POLLIN, dev);

	f->private_data = n;
	//vhost_virtqueue_print(vqs[VHOST_NET_VQ_RX]);

	return 0;
}

static struct socket *vhost_net_stop_vq(struct vhost_net *n,
					struct vhost_virtqueue *vq)
{
	struct socket *sock;

	mutex_lock(&vq->mutex);
	sock = vq->private_data;
	vhost_net_disable_vq(n, vq);
	vq->private_data = NULL;
	mutex_unlock(&vq->mutex);
	return sock;
}

static void vhost_net_stop(struct vhost_net *n, struct socket **tx_sock,
			   struct socket **rx_sock)
{
	*tx_sock = vhost_net_stop_vq(n, &n->vqs[VHOST_NET_VQ_TX].vq);
	*rx_sock = vhost_net_stop_vq(n, &n->vqs[VHOST_NET_VQ_RX].vq);
}

static void vhost_net_flush_vq(struct vhost_net *n, int index)
{
	vhost_poll_flush(n->poll + index);
	vhost_poll_flush(&n->vqs[index].vq.poll);
}

static void vhost_net_flush(struct vhost_net *n)
{
	vhost_net_flush_vq(n, VHOST_NET_VQ_TX);
	vhost_net_flush_vq(n, VHOST_NET_VQ_RX);
	if (n->vqs[VHOST_NET_VQ_TX].ubufs) {
		mutex_lock(&n->vqs[VHOST_NET_VQ_TX].vq.mutex);
		n->tx_flush = true;
		mutex_unlock(&n->vqs[VHOST_NET_VQ_TX].vq.mutex);
		/* Wait for all lower device DMAs done. */
		vhost_net_ubuf_put_and_wait(n->vqs[VHOST_NET_VQ_TX].ubufs);
		mutex_lock(&n->vqs[VHOST_NET_VQ_TX].vq.mutex);
		n->tx_flush = false;
		atomic_set(&n->vqs[VHOST_NET_VQ_TX].ubufs->refcount, 1);
		mutex_unlock(&n->vqs[VHOST_NET_VQ_TX].vq.mutex);
	}
}

static int vhost_net_release(struct inode *inode, struct file *f)
{
	struct vhost_net *n = f->private_data;
	struct socket *tx_sock;
	struct socket *rx_sock;
	struct vhost_net_virtqueue *nvq = &n->vqs[VHOST_NET_VQ_RX];
	struct vhost_virtqueue *vq = &nvq->vq;

	printk("entering vhost_net_release; inode = %p, f = %p \n", inode, f);
	vhost_net_stop(n, &tx_sock, &rx_sock);
	vhost_net_flush(n);
	vhost_dev_stop(&n->dev);
	vhost_dev_cleanup(&n->dev, false);
	vhost_net_vq_reset(n);
	/* free up remaining entries of vhost_desc_slab */
	if (vq->saved_desc_page_info) {
		kmem_cache_free(vhost_desc_slab, vq->saved_desc_page_info);
		vq->saved_desc_page_info = NULL;
	}
	if (tx_sock)
		sockfd_put(tx_sock);
	if (rx_sock)
		sockfd_put(rx_sock);
	/* Make sure no callbacks are outstanding */
	synchronize_rcu_bh();
	/* We do an extra flush before freeing memory,
	 * since jobs can re-queue themselves. */
	vhost_net_flush(n);
	kfree(n->dev.vqs);
	kvfree(n);
	printk("exiting vhost_net_release \n");
	return 0;
}

static struct socket *get_raw_socket(int fd)
{
	struct {
		struct sockaddr_ll sa;
		char  buf[MAX_ADDR_LEN];
	} uaddr;
	int uaddr_len = sizeof uaddr, r;
	struct socket *sock = sockfd_lookup(fd, &r);

	if (!sock)
		return ERR_PTR(-ENOTSOCK);

	/* Parameter checking */
	if (sock->sk->sk_type != SOCK_RAW) {
		r = -ESOCKTNOSUPPORT;
		goto err;
	}

	r = sock->ops->getname(sock, (struct sockaddr *)&uaddr.sa,
			       &uaddr_len, 0);
	if (r)
		goto err;

	if (uaddr.sa.sll_family != AF_PACKET) {
		r = -EPFNOSUPPORT;
		goto err;
	}
	return sock;
err:
	sockfd_put(sock);
	return ERR_PTR(r);
}

static struct socket *get_tap_socket(int fd)
{
	struct file *file = fget(fd);
	struct socket *sock;

	if (!file)
		return ERR_PTR(-EBADF);
	sock = tun_get_socket(file);
	if (!IS_ERR(sock))
		return sock;
	sock = macvtap_get_socket(file);
	if (IS_ERR(sock))
		fput(file);
	return sock;
}

static struct socket *get_socket(int fd)
{
	struct socket *sock;

	/* special case to disable backend */
	if (fd == -1)
		return NULL;
	sock = get_raw_socket(fd);
	if (!IS_ERR(sock))
		return sock;
	sock = get_tap_socket(fd);
	if (!IS_ERR(sock))
		return sock;
	return ERR_PTR(-ENOTSOCK);
}

static long vhost_net_set_backend(struct vhost_net *n, unsigned index, int fd)
{
	struct socket *sock, *oldsock;
	struct vhost_virtqueue *vq;
	struct vhost_net_virtqueue *nvq;
	struct vhost_net_ubuf_ref *ubufs, *oldubufs = NULL;
	int r;

	//printk(KERN_ERR "entering vhost_net_set_backend, n = %p, index = %d, fd = %d \n", n, index, fd);
	//printk(KERN_ERR "vhost_net_set_backend, current = %p \n", current);
	//printk(KERN_ERR "vhost_net_set_backend; before mutex_lock \n");
	mutex_lock(&n->dev.mutex);
	r = vhost_dev_check_owner(&n->dev);
	if (r)
		goto err;

	if (index >= VHOST_NET_VQ_MAX) {
		r = -ENOBUFS;
		goto err;
	}
	vq = &n->vqs[index].vq;
	nvq = &n->vqs[index];
	//printk(KERN_ERR "vhost_net_set_backend; before mutex_lock \n");
	mutex_lock(&vq->mutex);

	/* Verify that ring has been setup correctly. */
	//printk(KERN_ERR "vhost_net_set_backend; before vhost_vq_access_ok \n");
	if (!vhost_vq_access_ok(vq)) {
		r = -EFAULT;
		goto err_vq;
	}
	//printk(KERN_ERR "vhost_net_set_backend; before get_socket \n");
	sock = get_socket(fd);
	//printk(KERN_ERR "vhost_net_set_backend; after get_socket \n");
	//printk(KERN_ERR "vhost_net_set_backend: socket = %p \n", sock);
	if (IS_ERR(sock)) {
		r = PTR_ERR(sock);
		goto err_vq;
	}

	/* start polling new socket */
	oldsock = vq->private_data;
	if (sock != oldsock) {
		ubufs = vhost_net_ubuf_alloc(vq,
					     sock && vhost_sock_zcopy_tx(sock));
		if (IS_ERR(ubufs)) {
			r = PTR_ERR(ubufs);
			goto err_ubufs;
		}

		vhost_net_disable_vq(n, vq);
		vq->private_data = sock;
		r = vhost_vq_init_access(vq);
		if (r)
			goto err_used;
		r = vhost_net_enable_vq(n, vq);
		if (r)
			goto err_used;

		oldubufs = nvq->ubufs;
		nvq->ubufs = ubufs;

		n->tx_packets = 0;
		n->tx_zcopy_err = 0;
		n->tx_flush = false;
	}

	mutex_unlock(&vq->mutex);

	if (oldubufs) {
		vhost_net_ubuf_put_wait_and_free(oldubufs);
		mutex_lock(&vq->mutex);
		vhost_zerocopy_signal_used(n, vq);
		mutex_unlock(&vq->mutex);
	}

	if (oldsock) {
		vhost_net_flush_vq(n, index);
		sockfd_put(oldsock);
	}

	mutex_unlock(&n->dev.mutex);
	//printk(KERN_ERR "exiting vhost_net_set_backend, n = %p, index = %d, fd = %d \n", n, index, fd);
	return 0;

err_used:
	vq->private_data = oldsock;
	vhost_net_enable_vq(n, vq);
	if (ubufs)
		vhost_net_ubuf_put_wait_and_free(ubufs);
err_ubufs:
	sockfd_put(sock);
err_vq:
	printk(KERN_ERR "vhost_net_set_backend with error, before mutex_unlock \n");
	mutex_unlock(&vq->mutex);
err:
	mutex_unlock(&n->dev.mutex);
	printk(KERN_ERR "exiting vhost_net_set_backend with error, n = %p, index = %d, fd = %d \n", n, index, fd);
	return r;
}

static long vhost_net_reset_owner(struct vhost_net *n)
{
	struct socket *tx_sock = NULL;
	struct socket *rx_sock = NULL;
	long err;
	struct vhost_umem *umem;

	mutex_lock(&n->dev.mutex);
	err = vhost_dev_check_owner(&n->dev);
	if (err)
		goto done;
	umem = vhost_dev_reset_owner_prepare();
	if (!umem) {
		err = -ENOMEM;
		goto done;
	}
	vhost_net_stop(n, &tx_sock, &rx_sock);
	vhost_net_flush(n);
	vhost_dev_reset_owner(&n->dev, umem);
	vhost_net_vq_reset(n);
done:
	mutex_unlock(&n->dev.mutex);
	if (tx_sock)
		sockfd_put(tx_sock);
	if (rx_sock)
		sockfd_put(rx_sock);
	return err;
}

static int vhost_net_set_features(struct vhost_net *n, u64 features)
{
	size_t vhost_hlen, sock_hlen, hdr_len;
	int i;

	printk(KERN_ERR "entering vhost_net_set_features, features = %llx  \n", features);
	hdr_len = (features & ((1ULL << VIRTIO_NET_F_MRG_RXBUF) |
			       (1ULL << VIRTIO_F_VERSION_1))) ?
			sizeof(struct virtio_net_hdr_mrg_rxbuf) :
			sizeof(struct virtio_net_hdr);
	if (features & (1 << VHOST_NET_F_VIRTIO_NET_HDR)) {
		/* vhost provides vnet_hdr */
		printk(KERN_ERR "VHOST_NET_F_VIRTIO_NET_HDR set \n");
		vhost_hlen = hdr_len;
		sock_hlen = 0;
	} else {
		printk(KERN_ERR "VHOST_NET_F_VIRTIO_NET_HDR not set \n");
		/* socket provides vnet_hdr */
		vhost_hlen = 0;
		sock_hlen = hdr_len;
	}
	printk(KERN_ERR "vhost_net_set_features: hdr_len = %ld \n", hdr_len);
	mutex_lock(&n->dev.mutex);
	if ((features & (1 << VHOST_F_LOG_ALL)) &&
	    !vhost_log_access_ok(&n->dev))
		goto out_unlock;

	if ((features & (1ULL << VIRTIO_F_IOMMU_PLATFORM))) {
		if (vhost_init_device_iotlb(&n->dev, true))
			goto out_unlock;
	}

	for (i = 0; i < VHOST_NET_VQ_MAX; ++i) {
		mutex_lock(&n->vqs[i].vq.mutex);
		n->vqs[i].vq.acked_features = features;
		n->vqs[i].vhost_hlen = vhost_hlen;
		n->vqs[i].sock_hlen = sock_hlen;
		mutex_unlock(&n->vqs[i].vq.mutex);
	}
	mutex_unlock(&n->dev.mutex);
	return 0;

out_unlock:
	mutex_unlock(&n->dev.mutex);
	return -EFAULT;
}

static long vhost_net_set_owner(struct vhost_net *n)
{
	int r;

	mutex_lock(&n->dev.mutex);
	if (vhost_dev_has_owner(&n->dev)) {
		r = -EBUSY;
		goto out;
	}
	r = vhost_net_set_ubuf_info(n);
	if (r)
		goto out;
	r = vhost_dev_set_owner(&n->dev);
	if (r)
		vhost_net_clear_ubuf_info(n);
	vhost_net_flush(n);
out:
	mutex_unlock(&n->dev.mutex);
	return r;
}

static long vhost_net_ioctl(struct file *f, unsigned int ioctl,
			    unsigned long arg)
{
	struct vhost_net *n = f->private_data;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	struct vhost_vring_file backend;
	u64 features;
	int r;

	//printk(KERN_ERR "entering vhost_net_ioctl: ioctl = %x \n", ioctl);
	switch (ioctl) {
	case VHOST_NET_SET_BACKEND:
		if (copy_from_user(&backend, argp, sizeof backend))
			return -EFAULT;
		return vhost_net_set_backend(n, backend.index, backend.fd);
	case VHOST_GET_FEATURES:
		printk(KERN_ERR "vhost_net_ioctl: get features: %llx \n", vhost_net_features);
		features = vhost_net_features;
		if (copy_to_user(featurep, &features, sizeof features))
			return -EFAULT;
		return 0;
	case VHOST_SET_FEATURES:
		printk(KERN_ERR "vhost_net_ioctl: set features: %llx \n", vhost_net_features);
		if (copy_from_user(&features, featurep, sizeof features))
			return -EFAULT;
		if (features & ~vhost_net_features)
			return -EOPNOTSUPP;
		return vhost_net_set_features(n, features);
	case VHOST_RESET_OWNER:
		return vhost_net_reset_owner(n);
	case VHOST_SET_OWNER:
		printk(KERN_ERR "vhost_net_ioctl: set owner: vhost_net = %p \n", n);
		return vhost_net_set_owner(n);
	default:
		mutex_lock(&n->dev.mutex);
		r = vhost_dev_ioctl(&n->dev, ioctl, argp);
		if (r == -ENOIOCTLCMD)
			r = vhost_vring_ioctl(&n->dev, ioctl, argp);
		else
			vhost_net_flush(n);
		mutex_unlock(&n->dev.mutex);
		return r;
	}
}

#ifdef CONFIG_COMPAT
static long vhost_net_compat_ioctl(struct file *f, unsigned int ioctl,
				   unsigned long arg)
{
	return vhost_net_ioctl(f, ioctl, (unsigned long)compat_ptr(arg));
}
#endif

static ssize_t vhost_net_chr_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct vhost_net *n = file->private_data;
	struct vhost_dev *dev = &n->dev;
	int noblock = file->f_flags & O_NONBLOCK;

	return vhost_chr_read_iter(dev, to, noblock);
}

static ssize_t vhost_net_chr_write_iter(struct kiocb *iocb,
					struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct vhost_net *n = file->private_data;
	struct vhost_dev *dev = &n->dev;

	return vhost_chr_write_iter(dev, from);
}

static unsigned int vhost_net_chr_poll(struct file *file, poll_table *wait)
{
	struct vhost_net *n = file->private_data;
	struct vhost_dev *dev = &n->dev;

	return vhost_chr_poll(file, dev, wait);
}

static const struct file_operations vhost_net_fops = {
	.owner          = THIS_MODULE,
	.release        = vhost_net_release,
	.read_iter      = vhost_net_chr_read_iter,
	.write_iter     = vhost_net_chr_write_iter,
	.poll           = vhost_net_chr_poll,
	.poll           = vhost_net_chr_poll,
	.unlocked_ioctl = vhost_net_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = vhost_net_compat_ioctl,
#endif
	.open           = vhost_net_open,
	.llseek		= noop_llseek,
};

static struct miscdevice vhost_net_misc = {
	.minor = VHOST_NET_MINOR,
	.name = "vhost-net",
	.fops = &vhost_net_fops,
};

static int vhost_net_init(void)
{
	int ret;
	printk(KERN_ERR "entering vhost_net_init \n");
	if (experimental_zcopytx)
		vhost_net_enable_zcopy(VHOST_NET_VQ_TX);
	/* 
	if (experimental_zcopyrx)
		vhost_net_enable_zcopy(VHOST_NET_VQ_RX);
	*/
	/* allocate slab to track mappings of buffers to virtio descriptors */
	vhost_desc_slab = kmem_cache_create("vhost_desc_slab", sizeof(struct vhost_page_info), 0, 0, NULL);
	if (!vhost_desc_slab)
		return -ENOMEM;
	ret = misc_register(&vhost_net_misc);
	printk(KERN_ERR "exiting vhost_net_init \n");
	return ret;
}
module_init(vhost_net_init);

static void vhost_net_exit(void)
{
	printk(KERN_ERR "entering vhost_net_exit \n");
	kmem_cache_destroy(vhost_desc_slab);
	misc_deregister(&vhost_net_misc);
	printk(KERN_ERR "exiting vhost_net_exit \n");
}
module_exit(vhost_net_exit);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Michael S. Tsirkin");
MODULE_DESCRIPTION("Host kernel accelerator for virtio net");
MODULE_ALIAS_MISCDEV(VHOST_NET_MINOR);
MODULE_ALIAS("devname:vhost-net");
