// SPDX-License-Identifier: GPL-2.0

#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/time.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/sysctl.h>
#include <net/pingtrace.h>
#include <net/net_namespace.h>

static unsigned int sysctl_pingtrace = 1;
static u32 sysctl_icmp_pingtrace_user_id;

DEFINE_STATIC_KEY_TRUE(pingtrace_control);

#define PINGTRACE_TRANSPORT_PACKET_MIN_LEN \
	(sizeof(struct icmphdr) + sizeof(struct pingtrace_hdr))

static bool iphdr_check(struct iphdr *iph)
{
	return iph->ihl == 5 && iph->version == 4 &&
	       iph->protocol == IPPROTO_ICMP;
}

static bool icmphdr_check(struct icmphdr *icmph, u64 flags)
{
	return ((icmph->type == ICMP_ECHO && (flags & PINGTRACE_F_ECHO)) ||
		(icmph->type == ICMP_ECHOREPLY &&
		 (flags & PINGTRACE_F_ECHOREPLY))) &&
	       icmph->code == PINGTRACE_CODE_MAGIC;
}

static bool pingtracehdr_check(struct pingtrace_pkt *pt)
{
	return pt->hdr.version == 0 &&
	       ntohs(pt->hdr.magic) == PINGTRACE_HDR_MAGIC;
}

static u32 truncate_ts_usec(u64 usec)
{
	return usec & ((1UL << 32) - 1);
}

static u32 get_current_usec(void)
{
	return truncate_ts_usec(ktime_get_mono_fast_ns() / 1000);
}

static void
build_pingtrace_timestamp(struct pingtrace_timestamp *ts, struct net *net,
			  struct sk_buff *skb, u32 function_id, u32 usec)
{
	u16 user_id = sysctl_icmp_pingtrace_user_id & 0xffff;

	if (likely(net))
		ts->ns_id = htonl(net->ns.inum);
	else
		ts->ns_id = 0;

	if (likely(skb->dev))
		ts->ifindex = htonl(skb->dev->ifindex);
	else
		ts->ifindex = 0;

	ts->user_id = htons(user_id);
	ts->function_id = htons(function_id);
	ts->ts = htonl(usec);
}

static int pingtrace_add_ts(struct sk_buff *skb, struct pingtrace_pkt *pkt,
			    u32 packet_size, struct pingtrace_timestamp *entry)
{
	u32 offset, len;
	int ret;

	len = sizeof(struct pingtrace_hdr) +
	      sizeof(struct pingtrace_timestamp) * pkt->hdr.num;
	if (len + sizeof(struct pingtrace_timestamp) > packet_size)
		return -E2BIG;

	offset = (void *)pkt - (void *)(skb->data) + len;
	ret = skb_store_bits(skb, offset, entry, sizeof(*entry));
	if (!ret)
		pkt->hdr.num += 1;
	return ret;
}

static void
calculate_checksum(struct sk_buff *skb, struct icmphdr *icmph, u32 icmp_size)
{
	u32 offset = ((void *)icmph) - (void *)(skb->data);

	icmph->checksum = 0;
	icmph->checksum = csum_fold(skb_checksum(skb, offset, icmp_size, 0));
}

static bool header_pointer_set(struct sk_buff *skb, struct iphdr **piph,
			       struct icmphdr **picmph,
			       struct pingtrace_pkt **ppt)
{
	if (unlikely(!skb_transport_header_was_set(skb)))
		return false;

	if (!pskb_may_pull(skb, skb_transport_offset(skb) +
					   PINGTRACE_TRANSPORT_PACKET_MIN_LEN))
		return false;

	*piph = ip_hdr(skb);
	*picmph = icmp_hdr(skb);
	*ppt = (void *)((*picmph) + 1);

	return true;
}

static int do_skb_pingtrace_check(struct pingtrace_pkt *pt,
				  struct icmphdr *icmph, struct iphdr *iph,
				  u64 flags)
{
	return iphdr_check(iph) && icmphdr_check(icmph, flags) &&
	       pingtracehdr_check(pt);
}

bool skb_pingtrace_check(struct sk_buff *skb, u64 flags)
{
	struct pingtrace_pkt *pt;
	struct icmphdr *icmph;
	struct iphdr *iph;

	if (!header_pointer_set(skb, &iph, &icmph, &pt))
		return false;
	return do_skb_pingtrace_check(pt, icmph, iph, flags);
}

static int icmp_packet_size(struct icmphdr *icmph, struct iphdr *iph)
{
	return ntohs(iph->tot_len) - ((void *)icmph - (void *)iph);
}

static bool is_dontadd_flag_set(struct pingtrace_pkt *pt)
{
	u16 flags = ntohs(pt->hdr.flags);

	return flags & PINGTRACE_F_DONTADD;
}

static void
pingtrace_process_flags(struct sk_buff *skb, struct icmphdr *icmph,
			struct pingtrace_pkt *pt, int icmp_size, u64 flags)
{
	if (flags & PINGTRACE_F_CALCULATE_CHECKSUM)
		calculate_checksum(skb, icmph, icmp_size);
}

int skb_pingtrace_add_ts(struct sk_buff *skb, struct net *net, u32 function_id,
			 u64 flags)
{
	int ret = 0, pt_size, icmp_size;
	struct pingtrace_timestamp entry;
	struct pingtrace_pkt *pt;
	struct icmphdr *icmph;
	struct iphdr *iph;
	u32 usec;

	if (!header_pointer_set(skb, &iph, &icmph, &pt))
		return -EINVAL;
	icmp_size = icmp_packet_size(icmph, iph);
	pt_size = icmp_size - sizeof(*icmph);

	if (is_dontadd_flag_set(pt))
		return 0;

	usec = truncate_ts_usec(get_current_usec());
	build_pingtrace_timestamp(&entry, net, skb, function_id, usec);
	ret = pingtrace_add_ts(skb, pt, pt_size, &entry);
	if (ret)
		return ret;
	pingtrace_process_flags(skb, icmph, pt, icmp_size, flags);
	return 0;
}

static int pingtrace_sysctl_proc(struct ctl_table *table, int write,
				 void __user *buffer, size_t *lenp,
				 loff_t *ppos)
{
	unsigned int old_value = sysctl_pingtrace;
	int ret;

	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (ret == 0 && write && sysctl_pingtrace != old_value) {
		if (!sysctl_pingtrace)
			static_branch_disable(&pingtrace_control);
		else
			static_branch_enable(&pingtrace_control);
	}
	return ret;
}

static struct ctl_table pingtrace_table[] = {
	{
		.procname       = "icmp_pingtrace",
		.data           = &sysctl_pingtrace,
		.maxlen         = sizeof(sysctl_pingtrace),
		.mode           = 0644,
		.proc_handler   = pingtrace_sysctl_proc,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname       = "icmp_pingtrace_user_id",
		.data           = &sysctl_icmp_pingtrace_user_id,
		.maxlen         = sizeof(sysctl_icmp_pingtrace_user_id),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	{ }
};

static __init int sysctl_pingtrace_init(void)
{
	struct ctl_table_header *header;

	header = register_net_sysctl(&init_net, "net/ipv4", pingtrace_table);
	if (IS_ERR(header))
		return PTR_ERR(header);
	return 0;
}

fs_initcall(sysctl_pingtrace_init);
