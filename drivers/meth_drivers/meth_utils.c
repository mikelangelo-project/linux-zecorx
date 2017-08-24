
#include <linux/init.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/uio.h>
#include <linux/mm_types.h>
#include <linux/meth_utils.h>
#include <linux/scatterlist.h>

#define MAX_BUF_PRINT	100

void buf_print(void *buf, int len)
{
	int n_bytes;
	unsigned char tmp_buf[MAX_BUF_PRINT];
	int i;

	n_bytes = min(len, MAX_BUF_PRINT-1);
	if (!n_bytes) return;
	memcpy(tmp_buf, buf, n_bytes);
	tmp_buf[n_bytes] = '\0';
	printk(KERN_ERR "inside buf_print, buf = %p, len = %d \n", buf, len);
	printk(KERN_ERR " ");
	for (i = 0; i < n_bytes; i++) {
		printk("%02x ", tmp_buf[i]);
	}
	printk(KERN_ERR "\n");
}
EXPORT_SYMBOL(buf_print);

void skb_print_short(struct sk_buff *skb)
{
	int i;
	skb_frag_t *frag;
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	int n_frags = shinfo->nr_frags;
	struct page *p;
	void *v;
	printk(KERN_ERR "inside skb_print_short, skb = %p, sock = %p, queue_mapping = %d, users = %d \n", skb, skb->sk, skb_get_queue_mapping(skb), skb->users);
	if (!skb) return;
	printk(KERN_ERR "len = %d, data_len = %d, truesize = %d dev = %p\n", skb->len, skb->data_len, skb->truesize, skb->dev);
	printk(KERN_ERR "head = %p, data = %p, tail = %d, end = %d \n", skb->head, skb->data, skb->tail, skb->end);
	/* print out shared info */
	printk(KERN_ERR "nr_frags = %d, \n", n_frags);
	for (i=0; i < n_frags; i++) {
		frag = &shinfo->frags[i];
		p = skb_frag_page(frag);
		v = skb_frag_address(frag);
		printk(KERN_ERR "frag_num = %d, page = %p, offset = %d, size = %d, page address = %p \n", i, p, frag->page_offset, frag->size, v);
	}
	printk(KERN_ERR "exiting skb_print_short, skb = %p \n", skb);
}
EXPORT_SYMBOL(skb_print_short);


void skb_print(struct sk_buff *skb)
{
	skb_frag_t *frag;
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	int n_frags = shinfo->nr_frags;
	struct page *p;
	void *v;

	printk(KERN_ERR "inside skb_print, skb = %p, sock = %p, queue_mapping = %d \n", skb, skb->sk, skb_get_queue_mapping(skb));
	skb_print_short(skb);

	buf_print(skb->data, (skb->len - skb->data_len));

	if (n_frags > 0) {
		printk(KERN_ERR "printing frag 0 \n");
		frag = &shinfo->frags[0];
		p = skb_frag_page(frag);
		v = skb_frag_address(frag);
		buf_print(v, 50);
	}
	if (n_frags > 1) {
		printk(KERN_ERR "printing frag 1 \n");
		frag = &shinfo->frags[1];
		p = skb_frag_page(frag);
		v = skb_frag_address(frag);
		buf_print(v, 50);
	}
	printk(KERN_ERR "exiting skb_print \n");
}
EXPORT_SYMBOL(skb_print);

void skb_frag_print(struct sk_buff *skb, int frag_num)
{
	skb_frag_t *frag;
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	int n_frags = shinfo->nr_frags;
	struct page *p;
	void *v;

	printk(KERN_ERR "inside skb_frag_print, skb = %p, frag_num = %d \n", skb, frag_num);

	if (n_frags <= frag_num) {
		printk(KERN_ERR "frag %d does not exit \n", frag_num);
		return;
	}
	frag = &shinfo->frags[frag_num];
	p = skb_frag_page(frag);
	v = skb_frag_address(frag);
	buf_print(v, 50);

	printk(KERN_ERR "exiting skb_frag_print \n");
}
EXPORT_SYMBOL(skb_frag_print);

void addr_print(unsigned char *addr)
{
	printk(KERN_ERR "%02x %02x %02x %02x %02x %02x \n",
			addr[0],
			addr[1],
			addr[2],
			addr[3],
			addr[4],
			addr[5]);
}
EXPORT_SYMBOL(addr_print);

void my_netdev_printk(struct net_device *dev)
{
	unsigned char *addr;
	int i;
	struct netdev_rx_queue *q;

	if (!dev) {
		printk(KERN_ERR "NULL net_device \n");
		return;
	}
	addr = dev->dev_addr;
	printk(KERN_ERR "%s%s \n", netdev_name(dev), netdev_reg_state(dev));
	addr_print(addr);
}
EXPORT_SYMBOL(my_netdev_printk);

void iovec_print(struct iovec *iov, int n_segs, int total_count)
{
	int seg;
	int sum = 0;
	int len;
	for (seg = 0; seg < 3 && seg < n_segs && sum < total_count; seg++)
	{
		printk(KERN_ERR "seg: %d, base = %p, len = %d \n", seg, iov[seg].iov_base, iov[seg].iov_len);
		len = min(iov[seg].iov_len, total_count - sum);
		buf_print(iov[seg].iov_base, len);
		sum += len;
	}
}

void scatterlist_print(struct scatterlist *sg, int n_segs)
{
	int seg;
	int len;
	struct scatterlist *s;

	printk(KERN_ERR "inside scatterlist_print, sg = %p, n_segs = %d \n", sg, n_segs);
	for (seg = 0; seg < n_segs; seg++)
	{
		s = &sg[seg];
		printk(KERN_ERR "seg: %d, page_link = %lx, offset = %d, length = %d \n", seg, s->page_link, s->offset, s->length);
	}
}
EXPORT_SYMBOL(iovec_print);

void iov_iter_print (struct iov_iter *iter)
{
	struct iovec *iov;
	int seg;
	int total_count = 0;
	printk(KERN_ERR "inside iov_iter_print, iter = %p \n", iter);
	iov = iter->iov;
	printk(KERN_ERR "type = %d, iov_offset = %d, count = %d, nr_segs = %d, total_length = %d \n", iter->type, iter->iov_offset, iter->count, iter->nr_segs, iov_length(iov, iter->nr_segs));
	total_count = iter->count + iter->iov_offset;
	iovec_print(iov, iter->nr_segs, total_count);
}
EXPORT_SYMBOL(iov_iter_print);


// xxx revise comments
/* examine entries of iovec. skip the first one or 2, since they are not full pages, page aligned, and are for message headers. map the rest to page structures and enter into skb frags. */
// xxx allow even non-page aligned buffer.
// check and simplify to assume all buffers are up to one page long.
/* later copy some header info from skb back into first buffer(s) of iovec */
/* map only up to MAX_SKB_FRAGS pages */
/* return number of frags - full pages */
int map_iovec_to_skb(struct sk_buff *skb, struct iov_iter *from)
{
	struct iovec *iov;
	int seg;
	int frag_num = 0;
	struct page *p;
	int total_length;
	skb_frag_t *frag;
	uint page_mask = PAGE_SIZE - 1;
	struct page *page_info;
	int i;
	void *v;
	int len, offset;

	iov = from->iov;
	total_length = iov_length(iov, from->nr_segs);

	if (total_length < PAGE_SIZE)
		return 0;
								 
	/* first segments may be incomplete, and may hold message headers */
	for (seg = 0; seg < from->nr_segs; seg++) {
		if (iov[seg].iov_len > PAGE_SIZE) {
			len = PAGE_SIZE;
		}
		else {
			len = iov[seg].iov_len;
		}

		if (PAGE_ALIGNED(iov[seg].iov_base)) {
			offset = 0;
		}
		else {
			offset =  ((unsigned long) iov[seg].iov_base) & ~PAGE_MASK;
		}

		/* get page structure for each page */
		// this also pins the page in memory
		get_user_pages_fast(iov[seg].iov_base, 1, 1, &page_info);
		/* map iovec segment to skb frag */
		skb_fill_page_desc(skb, seg, page_info, offset, len);
		skb->len += len;
		skb->data_len += len;
	}
	// verify that other fields are correct: tail, end, len, etc
	return frag_num;
}
EXPORT_SYMBOL(map_iovec_to_skb);

void upmap_skb_frags(struct sk_buff *skb)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	int n_frags = shinfo->nr_frags;
	skb_frag_t *frag;
	int i;
	int len;

	if (!skb) return;
	/* print out shared info */
	//skb_release_data(skb);
	// perform callback
	for (i=n_frags-1; i >=0; i--) {
		frag = &skb_shinfo(skb)->frags[i];
		// xxx think some more about this
		len = min(frag->size, skb->data_len);
		skb_frag_unref(skb, i);
		skb->data_len -= len;
		skb->len -= len;
		shinfo->nr_frags--;
	}
}
EXPORT_SYMBOL(upmap_skb_frags);

static int meth_init(void)
{
	printk(KERN_ALERT "entering meth_init \n");
	return 0;
}

static void meth_exit(void)
{
	printk(KERN_ALERT "entering meth_exit \n");
}

module_init(meth_init);
module_exit(meth_exit);

MODULE_LICENSE("GPL");

