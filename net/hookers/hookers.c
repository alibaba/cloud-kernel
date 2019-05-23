// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019 Alibaba Group Holding Limited.  All Rights Reserved. */

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/cpu.h>
#include <asm/cacheflush.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>
#include <net/tcp.h>
#include <net/transp_v6.h>
#include <net/inet_common.h>
#include <net/ipv6.h>
#include <linux/inet.h>

#include <linux/hookers.h>

struct hooked_place {
	const char *name;	/* position information shown in procfs */
	void *place;		/* the kernel address to be hook */
	void *orig;		/* original content at hooked place */
	void *stub;		/* hooker function stub */
	int nr_hookers;		/* how many hookers are linked at below chain */
	struct list_head chain;	/* hookers chain */
};

static spinlock_t hookers_lock;

static struct sock *
ipv4_specific_syn_recv_sock_stub(struct sock *sk,
				 struct sk_buff *skb, struct request_sock *req,
				 struct dst_entry *dst,
				 struct request_sock *req_unhash,
				 bool *own_req);
static int
inet_stream_ops_getname_stub(struct socket *sock,
			     struct sockaddr *uaddr, int peer);
#if IS_ENABLED(CONFIG_IPV6)
static struct sock *
ipv6_specific_syn_recv_sock_stub(struct sock *sk,
				 struct sk_buff *skb, struct request_sock *req,
				 struct dst_entry *dst,
				 struct request_sock *req_unhash,
				 bool *own_req);
static struct sock *
ipv6_mapped_syn_recv_sock_stub(struct sock *sk,
			       struct sk_buff *skb, struct request_sock *req,
			       struct dst_entry *dst,
			       struct request_sock *req_unhash,
			       bool *own_req);
static int
inet6_stream_ops_getname_stub(struct socket *sock,
			      struct sockaddr *uaddr, int peer);
#endif

enum pt_types {
	IPV4_SPECIFIC_SYN_RECV_SOCK = 0,
	INET_STREAM_OPS_GETNAME,
#if IS_ENABLED(CONFIG_IPV6)
	IPV6_SPECIFIC_SYN_RECV_SOCK,
	IPV6_MAPPED_SYN_RECV_SOCK,
	INET6_STREAM_OPS_GETNAME,
#endif
	PLACE_TABLE_SZ
};

static struct hooked_place place_table[] = {
	{
		.name = "ipv4_specific.syn_recv_sock",
		.place = (void *)&ipv4_specific.syn_recv_sock,
		.stub = ipv4_specific_syn_recv_sock_stub,
	},

	{
		.name = "inet_stream_ops.getname",
		.place = (void *)&inet_stream_ops.getname,
		.stub = inet_stream_ops_getname_stub,
	},

#if IS_ENABLED(CONFIG_IPV6)
	{
		.name = "ipv6_specific.syn_recv_sock",
		.place = (void *)&ipv6_specific.syn_recv_sock,
		.stub = ipv6_specific_syn_recv_sock_stub,
	},

	{
		.name = "ipv6_mapped.syn_recv_sock",
		.place = (void *)&ipv6_mapped.syn_recv_sock,
		.stub = ipv6_mapped_syn_recv_sock_stub,
	},

	{
		.name = "inet6_stream_ops.getname",
		.place = (void *)&inet6_stream_ops.getname,
		.stub = inet6_stream_ops_getname_stub,
	},
#endif
};

static struct sock *
__syn_recv_sock_hstub(struct hooked_place *place,
		      struct sock *sk, struct sk_buff *skb,
		      struct request_sock *req, struct dst_entry *dst,
		      struct request_sock *req_unhash, bool *own_req)
{
	struct hooker *iter;
	struct sock *(*hooker_func)(struct sock *sk, struct sk_buff *skb,
				    struct request_sock *req,
				    struct dst_entry *dst,
				    struct request_sock *req_unhash,
				    bool *own_req,
				    struct sock **ret);
	struct sock *(*orig_func)(struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req,
				  struct dst_entry *dst,
				  struct request_sock *req_unhash,
				  bool *own_req);
	struct sock *ret;

	orig_func = place->orig;
	ret = orig_func(sk, skb, req, dst, req_unhash, own_req);

	rcu_read_lock();
	list_for_each_entry_rcu(iter, &place->chain, chain) {
		hooker_func = iter->func;
		hooker_func(sk, skb, req, dst, req_unhash, own_req, &ret);
	}
	rcu_read_unlock();

	return ret;
}

static int __getname_hstub(struct hooked_place *place,
			   struct socket *sock, struct sockaddr *uaddr,
			   int peer)
{
	struct hooker *iter;
	int (*hooker_func)(struct socket *sock, struct sockaddr *uaddr,
			   int peer, int *ret);
	int (*orig_func)(struct socket *sock, struct sockaddr *uaddr,
			 int peer);
	int ret;

	orig_func = place->orig;
	ret = orig_func(sock, uaddr, peer);

	rcu_read_lock();
	list_for_each_entry_rcu(iter, &place->chain, chain) {
		hooker_func = iter->func;
		hooker_func(sock, uaddr, peer, &ret);
	}
	rcu_read_unlock();

	return ret;
}

static struct sock *
ipv4_specific_syn_recv_sock_stub(struct sock *sk,
				 struct sk_buff *skb, struct request_sock *req,
				 struct dst_entry *dst,
				 struct request_sock *req_unhash,
				 bool *own_req)
{
	return __syn_recv_sock_hstub(&place_table[IPV4_SPECIFIC_SYN_RECV_SOCK],
				     sk, skb, req, dst, req_unhash, own_req);
}

static int
inet_stream_ops_getname_stub(struct socket *sock,
			     struct sockaddr *uaddr, int peer)
{
	return __getname_hstub(&place_table[INET_STREAM_OPS_GETNAME], sock,
			       uaddr, peer);
}

#if IS_ENABLED(CONFIG_IPV6)
static struct sock *
ipv6_specific_syn_recv_sock_stub(struct sock *sk,
				 struct sk_buff *skb, struct request_sock *req,
				 struct dst_entry *dst,
				 struct request_sock *req_unhash,
				 bool *own_req)
{
	return __syn_recv_sock_hstub(&place_table[IPV6_SPECIFIC_SYN_RECV_SOCK],
				     sk, skb, req, dst, req_unhash, own_req);
}

static struct sock *
ipv6_mapped_syn_recv_sock_stub(struct sock *sk,
			       struct sk_buff *skb, struct request_sock *req,
			       struct dst_entry *dst,
			       struct request_sock *req_unhash,
			       bool *own_req)
{
	return __syn_recv_sock_hstub(&place_table[IPV6_MAPPED_SYN_RECV_SOCK],
				     sk, skb, req, dst, req_unhash, own_req);
}

static int
inet6_stream_ops_getname_stub(struct socket *sock,
			      struct sockaddr *uaddr, int peer)
{
	return __getname_hstub(&place_table[INET6_STREAM_OPS_GETNAME], sock,
			       uaddr, peer);
}
#endif

int hooker_install(const void *place, struct hooker *h)
{
	enum pt_types i;
	struct hooked_place *hplace;

	/* synchronize_rcu() */
	might_sleep();

	if (!place || !h || !h->func)
		return -EINVAL;

	for (i = 0; i < PLACE_TABLE_SZ; i++) {
		hplace = &place_table[i];
		if (hplace->place == place) {
			INIT_LIST_HEAD(&h->chain);
			spin_lock(&hookers_lock);
			hplace->nr_hookers++;
			h->hplace = hplace;
			list_add_tail_rcu(&h->chain, &place_table[i].chain);
			spin_unlock(&hookers_lock);
			synchronize_rcu();
			break;
		}
	}

	return (i >= PLACE_TABLE_SZ) ? -EINVAL : 0;
}
EXPORT_SYMBOL_GPL(hooker_install);

void hooker_uninstall(struct hooker *h)
{
	 /* synchronize_rcu(); */
	might_sleep();

	spin_lock(&hookers_lock);
	list_del_rcu(&h->chain);
	h->hplace->nr_hookers--;
	h->hplace = NULL;
	spin_unlock(&hookers_lock);
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(hooker_uninstall);

static inline unsigned int hookers_clear_cr0(void)
{
	unsigned int cr0 = read_cr0();

	write_cr0(cr0 & 0xfffeffff);
	return cr0;
}

static inline void hookers_restore_cr0(unsigned int val)
{
	write_cr0(val);
}

static void *hookers_seq_start(struct seq_file *seq, loff_t *pos)
{
	if (*pos < PLACE_TABLE_SZ)
		return &place_table[*pos];
	return NULL;
}

static void *hookers_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	if (++(*pos) >= PLACE_TABLE_SZ)
		return NULL;

	return (void *)&place_table[*pos];
}

static void hookers_seq_stop(struct seq_file *seq, void *v)
{
}

static int hookers_seq_show(struct seq_file *seq, void *v)
{
	struct hooked_place *hplace = (struct hooked_place *)v;

	seq_printf(seq, "name:%-24s addr:0x%p hookers:%-10d\n",
		   hplace->name, hplace->place, hplace->nr_hookers);
	return 0;
}

static const struct seq_operations hookers_seq_ops = {
	.start = hookers_seq_start,
	.next  = hookers_seq_next,
	.stop  = hookers_seq_stop,
	.show  = hookers_seq_show,
};

static int hookers_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &hookers_seq_ops);
}

static const struct proc_ops hookers_seq_fops = {
	.proc_open = hookers_seq_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = seq_release,
};

static int hookers_init(void)
{
	enum pt_types i;

	if (!proc_create("hookers", 0444, NULL, &hookers_seq_fops))
		return -ENODEV;

	spin_lock_init(&hookers_lock);
	for (i = 0; i < PLACE_TABLE_SZ; i++) {
		unsigned int cr0;
		void **place = place_table[i].place;

		place_table[i].orig = *place;
		if (!place_table[i].stub)
			break;
		INIT_LIST_HEAD(&place_table[i].chain);
		get_online_cpus();
		cr0 = hookers_clear_cr0();
		*place = place_table[i].stub;
		hookers_restore_cr0(cr0);
		put_online_cpus();
	}

	return 0;
}

static void hookers_exit(void)
{
	enum pt_types i;

	remove_proc_entry("hookers", NULL);

	for (i = 0; i < PLACE_TABLE_SZ; i++) {
		unsigned int cr0;
		void **place = place_table[i].place;

		get_online_cpus();
		cr0 = hookers_clear_cr0();
		*place = place_table[i].orig;
		hookers_restore_cr0(cr0);
		put_online_cpus();
	}
	synchronize_rcu();
}

module_init(hookers_init);
module_exit(hookers_exit);
MODULE_LICENSE("GPL");
