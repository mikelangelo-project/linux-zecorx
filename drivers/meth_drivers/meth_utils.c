
#include <linux/init.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/uio.h>
#include <linux/mm_types.h>
#include <linux/meth_utils.h>

void skb_print(struct sk_buff *skb)
{
	int i;
	skb_frag_t *frag;
	struct skb_shared_info *shinfo = skb_shinfo(skb);
	int n_frags = shinfo->nr_frags;
	struct page *p;
	void *v;
	printk(KERN_INFO "inside skb_print, skb = %p, sock = %p \n", skb, skb->sk);
	if (!skb) return;
	printk(KERN_INFO "len = %d, data_len = %d, truesize = %d dev = %p\n", skb->len, skb->data_len, skb->truesize, skb->dev);
	printk(KERN_INFO "head = %p, data = %p, tail = %d, end = %d \n", skb->head, skb->data, skb->tail, skb->end);
	/* print out shared info */
	printk(KERN_INFO "nr_frags = %d, \n", n_frags);
	for (i=0; i < n_frags; i++) {
		frag = &shinfo->frags[i];
		p = skb_frag_page(frag);
		v = skb_frag_address(frag);
		printk(KERN_INFO "frag_num = %d, page = %p, offset = %d, size = %d, page address = %p \n", i, p, frag->page_offset, frag->size, v);
	}
}
EXPORT_SYMBOL(skb_print);

void my_netdev_printk(struct net_device *dev)
{
	if (dev) {
		unsigned char *addr;
		addr = dev->dev_addr;
		printk(KERN_INFO "%s%s \n", netdev_name(dev), netdev_reg_state(dev));
		printk(KERN_INFO "%2x %2x %2x %2x %2x %2x %2x %2x \n",
			addr[0],
			addr[1],
			addr[2],
			addr[3],
			addr[4],
			addr[5]);
	} else {
		printk(KERN_INFO "NULL net_device \n");
	}
}
EXPORT_SYMBOL(my_netdev_printk);

void iov_iter_print (struct iov_iter *iter)
{
	struct iovec *iov;
	int seg;
	printk(KERN_DEBUG "inside iov_iter_print, iter = %p \n", iter);
	iov = iter->iov;
	printk(KERN_DEBUG "type = %d, iov_offset = %d, count = %d, nr_segs = %d, total_length = %d \n", iter->type, iter->iov_offset, iter->count, iter->nr_segs, iov_length(iov, iter->nr_segs));
	for (seg = 0; seg < iter->nr_segs; seg++)
	{
		printk(KERN_DEBUG "seg: %d, base = %p, len = %d \n", seg, iov[seg].iov_base, iov[seg].iov_len);
	}

}
EXPORT_SYMBOL(iov_iter_print);


/* examine entries of iovec. skip the first one or 2, since they are not full pages, page aligned, and are for message headers. map the rest to page structures and enter into skb frags. */
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
	int n_pages;
	int n_pages2;
	struct page *pages[MAX_SKB_FRAGS];
	int i;
	void *v;

	iov = from->iov;
	total_length = iov_length(iov, from->nr_segs);

	printk(KERN_INFO "entering map_iovec_to_skb, total_length = %d, iov = %p, count = %d\n", total_length, iov, iov_iter_count(from));

	if (total_length < PAGE_SIZE)
		return 0;
								 
	/* xxx copy headers to beginning of skb */

	for (seg = 0; seg < from->nr_segs; seg++) {
		printk(KERN_DEBUG "seg: %d, base = %p, len = %d \n", seg, iov[seg].iov_base, iov[seg].iov_len);
		/* check if segment is page aligned and of size equal to multiple pages */
		if (!PAGE_ALIGNED(iov[seg].iov_base)) {
			/* not page aligned */
			continue;
		}
		if (iov[seg].iov_len & page_mask) {
			/* not multiple page length */
			continue;
		}
		/* xxx do wih a shift */
		n_pages = iov[seg].iov_len / PAGE_SIZE;
		/* get page structure for each page */
		n_pages2 = get_user_pages_fast(iov[seg].iov_base, n_pages, 1, pages);
		/* printk(KERN_DEBUG "n_pages = %d, n_pages2 = %d \n", n_pages, n_pages2); */
		/* map iovec segment to skb frag */
		for (i = 0; i < n_pages2; i++) {
			frag = &skb_shinfo(skb)->frags[frag_num];
			frag->page.p = pages[i];
			frag->page_offset = 0;
			skb_frag_size_set(frag, PAGE_SIZE);
			p = skb_frag_page(frag);
			v = skb_frag_address(frag);
			printk(KERN_DEBUG "frag_num = %d, page = %p, offset = %d, size = %d, page address = %p \n", frag_num, p, frag->page_offset, frag->size, v);
			/* fix up skb len fields */
			/* what do we do with the pfmemalloc flag? */
			frag_num++;
			skb_shinfo(skb)->nr_frags = frag_num;
			/* skb_shinfo(skb)->rx_flags |= SKBRX_DEV_ZEROCOPY; */
			if (frag_num >= MAX_SKB_FRAGS) {
				printk(KERN_INFO "exiting map_iovec_to_skb, reached MAX_SKB_FRAGS \n");
				return frag_num;
			}
		}
	}
	printk(KERN_INFO "exiting map_iovec_to_skb \n");
	return frag_num;
}
EXPORT_SYMBOL(map_iovec_to_skb);



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

