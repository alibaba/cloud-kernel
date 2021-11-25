/* SPDX-License-Identifier: GPL-2.0 */
/* AF_XDP internal functions
 * Copyright(c) 2018 Intel Corporation.
 */

#ifndef _LINUX_XDP_SOCK_H
#define _LINUX_XDP_SOCK_H

#include <linux/workqueue.h>
#include <linux/if_xdp.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <net/sock.h>

struct net_device;
struct xsk_queue;

struct xdp_umem_props {
	u64 chunk_mask;
	u64 size;
};

struct xdp_umem_page {
	void *addr;
	dma_addr_t dma;
};

struct xdp_umem {
	struct xsk_queue *fq;
	struct xsk_queue *cq;
	struct xdp_umem_page *pages;
	struct xdp_umem_props props;
	u32 headroom;
	u32 chunk_size_nohr;
	struct user_struct *user;
	unsigned long address;
	refcount_t users;
	struct work_struct work;
	struct page **pgs;
	u32 npgs;
	struct net_device *dev;
	u16 queue_id;
	bool zc;
	bool delay_unpin;
	spinlock_t xsk_list_lock;
	struct list_head xsk_list;
};

/* Nodes are linked in the struct xdp_sock map_list field, and used to
 * track which maps a certain socket reside in.
 */
struct xsk_map;
struct xsk_map_node {
	struct list_head node;
	struct xsk_map *map;
	struct xdp_sock **map_entry;
};

struct xdp_sock {
	/* struct sock must be the first member of struct xdp_sock */
	struct sock sk;
	struct xsk_queue *rx;
	struct net_device *dev;
	struct xdp_umem *umem;
	struct list_head flush_node;
	u16 queue_id;
	struct xsk_queue *tx ____cacheline_aligned_in_smp;
	struct list_head list;
	bool zc;
	/* Protects multiple processes in the control path */
	struct mutex mutex;
	/* Mutual exclusion of NAPI TX thread and sendmsg error paths
	 * in the SKB destructor callback.
	 */
	spinlock_t tx_completion_lock;
	u64 rx_dropped;
	struct list_head map_list;
	/* Protects map_list */
	spinlock_t map_list_lock;
};

struct xdp_buff;
#ifdef CONFIG_XDP_SOCKETS
int xsk_generic_rcv(struct xdp_sock *xs, struct xdp_buff *xdp);
int xsk_rcv(struct xdp_sock *xs, struct xdp_buff *xdp);
void xsk_flush(struct xdp_sock *xs);
bool xsk_is_setup_for_bpf_map(struct xdp_sock *xs);
/* Used from netdev driver */
u64 *xsk_umem_peek_addr(struct xdp_umem *umem, u64 *addr);
void xsk_umem_discard_addr(struct xdp_umem *umem);
void xsk_umem_complete_tx(struct xdp_umem *umem, u32 nb_entries);
bool xsk_umem_consume_tx(struct xdp_umem *umem, struct xdp_desc *desc);
void xsk_umem_consume_tx_done(struct xdp_umem *umem);

struct page **xsk_umem_pgs_delay_unpin(struct xdp_umem *umem, u64 *npgs);
void xsk_umem_unpin_pages(struct page **pgs, u64 npgs);

void xsk_map_try_sock_delete(struct xsk_map *map, struct xdp_sock *xs,
			     struct xdp_sock **map_entry);
int xsk_map_inc(struct xsk_map *map);
void xsk_map_put(struct xsk_map *map);

static inline char *xdp_umem_get_data(struct xdp_umem *umem, u64 addr)
{
	return umem->pages[addr >> PAGE_SHIFT].addr + (addr & (PAGE_SIZE - 1));
}

static inline dma_addr_t xdp_umem_get_dma(struct xdp_umem *umem, u64 addr)
{
	return umem->pages[addr >> PAGE_SHIFT].dma + (addr & (PAGE_SIZE - 1));
}

static inline struct page *xdp_umem_get_page(struct xdp_umem *umem, u64 addr)
{
	return umem->pgs[addr >> PAGE_SHIFT];
}

#else
static inline int xsk_generic_rcv(struct xdp_sock *xs, struct xdp_buff *xdp)
{
	return -ENOTSUPP;
}

static inline int xsk_rcv(struct xdp_sock *xs, struct xdp_buff *xdp)
{
	return -ENOTSUPP;
}

static inline void xsk_flush(struct xdp_sock *xs)
{
}

static inline bool xsk_is_setup_for_bpf_map(struct xdp_sock *xs)
{
	return false;
}

static inline u64 *xsk_umem_peek_addr(struct xdp_umem *umem, u64 *addr)
{
	return NULL;
}

static inline void xsk_umem_discard_addr(struct xdp_umem *umem)
{
}

static inline void xsk_umem_complete_tx(struct xdp_umem *umem, u32 nb_entries)
{
}

static inline bool xsk_umem_consume_tx(struct xdp_umem *umem, struct xdp_desc *desc)
{
	return false;
}

static inline void xsk_umem_consume_tx_done(struct xdp_umem *umem)
{
}

static inline char *xdp_umem_get_data(struct xdp_umem *umem, u64 addr)
{
	return NULL;
}

static inline dma_addr_t xdp_umem_get_dma(struct xdp_umem *umem, u64 addr)
{
	return 0;
}

static inline struct page *xdp_umem_get_page(struct xdp_umem *umem, u64 addr)
{
	return NULL;
}

static inline struct page **xsk_umem_pgs_delay_unpin(struct xdp_umem *umem, u64 *npgs)
{
	return NULL;
}

static inline void xsk_umem_unpin_pages(struct page **pgs, u64 npgs)
{
}
#endif /* CONFIG_XDP_SOCKETS */

#endif /* _LINUX_XDP_SOCK_H */
