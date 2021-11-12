// SPDX-License-Identifier: GPL-2.0
/*
 * KFENCE guarded object allocator and fault handling.
 *
 * Copyright (C) 2020, Google LLC.
 */

#define pr_fmt(fmt) "kfence: " fmt

#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/debugfs.h>
#include <linux/irq_work.h>
#include <linux/kcsan-checks.h>
#include <linux/kfence.h>
#include <linux/kmemleak.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/memblock.h>
#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/sched/clock.h>
#include <linux/sched/sysctl.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include <asm/kfence.h>

#include "kfence.h"

/* Disables KFENCE on the first warning assuming an irrecoverable error. */
#define KFENCE_WARN_ON(cond)                                                   \
	({                                                                     \
		const bool __cond = WARN_ON(cond);                             \
		if (unlikely(__cond))                                          \
			WRITE_ONCE(kfence_enabled, false);                     \
		__cond;                                                        \
	})

/* === Data ================================================================= */

static bool kfence_enabled __read_mostly;

static unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
unsigned long kfence_num_objects __read_mostly = CONFIG_KFENCE_NUM_OBJECTS;
EXPORT_SYMBOL(kfence_num_objects);

#ifdef MODULE_PARAM_PREFIX
#undef MODULE_PARAM_PREFIX
#endif
#define MODULE_PARAM_PREFIX "kfence."
#ifdef CONFIG_KFENCE_STATIC_KEYS
/* The static key to set up a KFENCE allocation. */
DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);
#endif
DEFINE_STATIC_KEY_FALSE(kfence_skip_interval);
DEFINE_STATIC_KEY_FALSE(kfence_once_inited);
EXPORT_SYMBOL(kfence_once_inited);

static int param_set_sample_interval(const char *val, const struct kernel_param *kp)
{
	unsigned long num;
	int ret = kstrtoul(val, 0, &num);

	if (ret < 0)
		return ret;

	if (!num) { /* Using 0 to indicate KFENCE is disabled. */
		WRITE_ONCE(kfence_enabled, false);
#ifdef CONFIG_KFENCE_STATIC_KEYS
		static_branch_disable(&kfence_allocation_key);
#endif
	} else if (!READ_ONCE(kfence_enabled) && system_state != SYSTEM_BOOTING) {
		return -EINVAL; /* Cannot (re-)enable KFENCE on-the-fly. */
	}

	*((unsigned long *)kp->arg) = num;
	return 0;
}

static int param_get_sample_interval(char *buffer, const struct kernel_param *kp)
{
	if (!READ_ONCE(kfence_enabled))
		return sprintf(buffer, "0\n");

	return param_get_ulong(buffer, kp);
}

static const struct kernel_param_ops sample_interval_param_ops = {
	.set = param_set_sample_interval,
	.get = param_get_sample_interval,
};
module_param_cb(sample_interval, &sample_interval_param_ops, &kfence_sample_interval, 0600);

static int param_set_num_objects(const char *val, const struct kernel_param *kp)
{
	unsigned long num;
	int ret = kstrtoul(val, 0, &num);

	if (ret < 0)
		return ret;

	if (system_state != SYSTEM_BOOTING)
		return -EINVAL;

	*((unsigned long *)kp->arg) = num;
	return 0;
}

static int param_get_num_objects(char *buffer, const struct kernel_param *kp)
{
	if (!READ_ONCE(kfence_enabled))
		return sprintf(buffer, "0\n");

	return param_get_ulong(buffer, kp);
}

static const struct kernel_param_ops num_objects_param_ops = {
	.set = param_set_num_objects,
	.get = param_get_num_objects,
};
module_param_cb(num_objects_pernode, &num_objects_param_ops, &kfence_num_objects, 0600);

/*
 * The pool of pages used for guard pages and objects.
 * Only used in booting init state. Will be cleared after that.
 */
char **__kfence_pool_node;

/* The binary tree maintaining all kfence pool areas */
struct rb_root kfence_pool_root = RB_ROOT;
EXPORT_SYMBOL(kfence_pool_root);

/* Freelist with available objects. */
struct kfence_freelist_node {
	struct list_head freelist;
	raw_spinlock_t lock;
};

struct kfence_freelist_cpu {
	struct list_head freelist;
	unsigned long count;
};

struct kfence_freelist {
	struct kfence_freelist_node *node;
	struct kfence_freelist_cpu __percpu *cpu;
};
static struct kfence_freelist freelist;

/* Gates the allocation, ensuring only one succeeds in a given period. */
atomic_t kfence_allocation_gate = ATOMIC_INIT(1);

/* Statistics counters for debugfs. */
enum kfence_counter_id {
	KFENCE_COUNTER_ALLOCATED,
	KFENCE_COUNTER_ALLOCS,
	KFENCE_COUNTER_FREES,
	KFENCE_COUNTER_ZOMBIES,
	KFENCE_COUNTER_ALLOCATED_PAGE,
	KFENCE_COUNTER_ALLOCS_PAGE,
	KFENCE_COUNTER_FREES_PAGE,
	KFENCE_COUNTER_BUGS,
	KFENCE_COUNTER_COUNT,
};
struct kfence_counter {
	s64 counter[KFENCE_COUNTER_COUNT];
};
static struct kfence_counter __percpu *counters;
static const char *const counter_names[] = {
	[KFENCE_COUNTER_ALLOCATED]	= "currently slab allocated",
	[KFENCE_COUNTER_ALLOCS]		= "total slab allocations",
	[KFENCE_COUNTER_FREES]		= "total slab frees",
	[KFENCE_COUNTER_ZOMBIES]	= "zombie slab allocations",
	[KFENCE_COUNTER_ALLOCATED_PAGE]	= "currently page allocated",
	[KFENCE_COUNTER_ALLOCS_PAGE]	= "total page allocations",
	[KFENCE_COUNTER_FREES_PAGE]	= "total page frees",
	[KFENCE_COUNTER_BUGS]		= "total bugs",
};
static_assert(ARRAY_SIZE(counter_names) == KFENCE_COUNTER_COUNT);

/* === Internals ============================================================ */

static bool kfence_protect(unsigned long addr)
{
	return !KFENCE_WARN_ON(!kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), true));
}

static bool kfence_unprotect(unsigned long addr)
{
	return !KFENCE_WARN_ON(!kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), false));
}

static inline struct kfence_metadata *addr_to_metadata(unsigned long addr)
{
	long index;
	struct kfence_metadata *kfence_metadata;
	struct kfence_pool_area *kpa = get_kfence_pool_area((void *)addr);

	/* The checks do not affect performance; only called from slow-paths. */

	if (!kpa)
		return NULL;

	kfence_metadata = kpa->meta;

	/*
	 * May be an invalid index if called with an address at the edge of
	 * __kfence_pool, in which case we would report an "invalid access"
	 * error.
	 */
	index = (addr - (unsigned long)kpa->addr) / (PAGE_SIZE * 2) - 1;
	if (index < 0 || index >= kpa->nr_objects)
		return NULL;

	return &kfence_metadata[index];
}

static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
{
	struct kfence_pool_area *kpa = meta->kpa;
	unsigned long offset = (meta - kpa->meta + 1) * PAGE_SIZE * 2;
	unsigned long pageaddr = (unsigned long)&kpa->addr[offset];

	/* The checks do not affect performance; only called from slow-paths. */

	/* Only call with a pointer into kfence_metadata. */
	if (KFENCE_WARN_ON(meta < kpa->meta || meta >= kpa->meta + kpa->nr_objects))
		return 0;

	/*
	 * This metadata object only ever maps to 1 page; verify that the stored
	 * address is in the expected range.
	 */
	if (KFENCE_WARN_ON(ALIGN_DOWN(meta->addr, PAGE_SIZE) != pageaddr))
		return 0;

	return pageaddr;
}

/*
 * Update the object's metadata state, including updating the alloc/free stacks
 * depending on the state transition.
 */
static noinline void metadata_update_state(struct kfence_metadata *meta,
					   enum kfence_object_state next)
{
	struct kfence_track *track =
		next == KFENCE_OBJECT_FREED ? &meta->free_track : &meta->alloc_track;

	lockdep_assert_held(&meta->lock);

	/*
	 * Skip over 1 (this) functions; noinline ensures we do not accidentally
	 * skip over the caller by never inlining.
	 */
	track->num_stack_entries = stack_trace_save(track->stack_entries, KFENCE_STACK_DEPTH, 1);
	track->pid = task_pid_nr(current);
	track->cpu = raw_smp_processor_id();
	track->ts_nsec = local_clock(); /* Same source as printk timestamps. */

	/*
	 * Pairs with READ_ONCE() in
	 *	kfence_shutdown_cache(),
	 *	kfence_handle_page_fault().
	 */
	WRITE_ONCE(meta->state, next);
}

/* Write canary byte to @addr. */
static inline bool set_canary_byte(u8 *addr)
{
	*addr = KFENCE_CANARY_PATTERN(addr);
	return true;
}

/* Check canary byte at @addr. */
static inline bool check_canary_byte(u8 *addr)
{
	if (likely(*addr == KFENCE_CANARY_PATTERN(addr)))
		return true;

	raw_cpu_ptr(counters)->counter[KFENCE_COUNTER_BUGS]++;
	kfence_report_error((unsigned long)addr, false, NULL, addr_to_metadata((unsigned long)addr),
			    KFENCE_ERROR_CORRUPTION);
	return false;
}

/* __always_inline this to ensure we won't do an indirect call to fn. */
static __always_inline void for_each_canary(const struct kfence_metadata *meta, bool (*fn)(u8 *))
{
	const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
	unsigned long addr, start = pageaddr, end = pageaddr + PAGE_SIZE;

	/* this func will take most cost so we shrink it when no interval limit */
	if (static_branch_likely(&kfence_skip_interval)) {
		start = max(ALIGN_DOWN(meta->addr - 1, L1_CACHE_BYTES), start);
		end = min(ALIGN(meta->addr + meta->size + 1, L1_CACHE_BYTES), end);
	}

	lockdep_assert_held(&meta->lock);

	/*
	 * We'll iterate over each canary byte per-side until fn() returns
	 * false. However, we'll still iterate over the canary bytes to the
	 * right of the object even if there was an error in the canary bytes to
	 * the left of the object. Specifically, if check_canary_byte()
	 * generates an error, showing both sides might give more clues as to
	 * what the error is about when displaying which bytes were corrupted.
	 */

	/* Apply to left of object. */
	for (addr = start; addr < meta->addr; addr++) {
		if (!fn((u8 *)addr))
			break;
	}

	/* Apply to right of object. */
	for (addr = meta->addr + meta->size; addr < end; addr++) {
		if (!fn((u8 *)addr))
			break;
	}
}

static inline struct kfence_metadata *
get_free_meta_from_node(struct kfence_freelist_node *kfence_freelist)
{
	struct kfence_metadata *object = NULL;
	unsigned long flags;

	raw_spin_lock_irqsave(&kfence_freelist->lock, flags);
	if (!list_empty(&kfence_freelist->freelist)) {
		object = list_entry(kfence_freelist->freelist.next, struct kfence_metadata, list);
		list_del_init(&object->list);
	}
	raw_spin_unlock_irqrestore(&kfence_freelist->lock, flags);

	return object;
}

#define KFENCE_FREELIST_PERCPU_SIZE 100

static struct kfence_metadata *
get_free_meta_slowpath(struct kfence_freelist_cpu *c,
		       struct kfence_freelist_node *kfence_freelist)
{
	struct kfence_metadata *object = NULL;
	struct list_head *entry = &kfence_freelist->freelist;

	KFENCE_WARN_ON(!list_empty(&c->freelist));

	raw_spin_lock(&kfence_freelist->lock);

	if (list_empty(&kfence_freelist->freelist))
		goto out;

	object = list_first_entry(entry, struct kfence_metadata, list);
	list_del_init(&object->list);

	do {
		entry = READ_ONCE(entry->next);

		if (entry == &kfence_freelist->freelist) {
			entry = entry->prev;
			break;
		}

		c->count++;
	} while (c->count < KFENCE_FREELIST_PERCPU_SIZE);

	list_cut_position(&c->freelist, &kfence_freelist->freelist, entry);

out:
	raw_spin_unlock(&kfence_freelist->lock);

	return object;
}

static struct kfence_metadata *get_free_meta(int node)
{
	unsigned long flags;
	struct kfence_freelist_cpu *c;
	struct kfence_freelist_node *kfence_freelist = &freelist.node[node];
	struct kfence_metadata *object;

	/* If target page not on current node, directly get from its nodelist */
	if (unlikely(node != numa_node_id()))
		return get_free_meta_from_node(kfence_freelist);

	local_irq_save(flags);
	c = get_cpu_ptr(freelist.cpu);

	if (unlikely(!c->count)) {
		object = get_free_meta_slowpath(c, kfence_freelist);
	} else {
		object = list_first_entry(&c->freelist, struct kfence_metadata, list);
		list_del_init(&object->list);
		c->count--;
	}

	put_cpu_ptr(c);
	local_irq_restore(flags);

	return object;
}

static inline void __init_meta(struct kfence_metadata *meta, size_t size, struct kmem_cache *cache)
{
	struct kfence_counter *this_cpu_counter = raw_cpu_ptr(counters);

	lockdep_assert_held(&meta->lock);

	meta->addr = metadata_to_pageaddr(meta);
	/* Unprotect if we're reusing this page. */
	if (meta->state == KFENCE_OBJECT_FREED)
		kfence_unprotect(meta->addr);

	/*
	 * Note: for allocations made before RNG initialization, will always
	 * return zero. We still benefit from enabling KFENCE as early as
	 * possible, even when the RNG is not yet available, as this will allow
	 * KFENCE to detect bugs due to earlier allocations. The only downside
	 * is that the out-of-bounds accesses detected are deterministic for
	 * such allocations.
	 */
	if (cache && this_cpu_counter->counter[KFENCE_COUNTER_ALLOCS] % 2) {
		/* Allocate on the "right" side, re-calculate address. */
		meta->addr += PAGE_SIZE - size;
		meta->addr = ALIGN_DOWN(meta->addr, cache->align);
	}

	/* Update remaining metadata. */
	metadata_update_state(meta, KFENCE_OBJECT_ALLOCATED);
	/* Pairs with READ_ONCE() in kfence_shutdown_cache(). */
	WRITE_ONCE(meta->cache, cache);
	meta->size = size;
}

static void put_free_meta(struct kfence_metadata *object, int node);
static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp, int node)
{
	struct kfence_metadata *meta;
	struct kfence_counter *this_cpu_counter = raw_cpu_ptr(counters);
	unsigned long flags;
	struct page *page;
	void *addr;

	/* Try to obtain a free object. */
	meta = get_free_meta(node);
	if (!meta)
		return NULL;

	if (unlikely(!raw_spin_trylock_irqsave(&meta->lock, flags))) {
		/*
		 * This is extremely unlikely -- we are reporting on a
		 * use-after-free, which locked meta->lock, and the reporting
		 * code via printk calls kmalloc() which ends up in
		 * kfence_alloc() and tries to grab the same object that we're
		 * reporting on. While it has never been observed, lockdep does
		 * report that there is a possibility of deadlock. Fix it by
		 * using trylock and bailing out gracefully.
		 * Put the object back on the freelist.
		 */
		put_free_meta(meta, node);

		return NULL;
	}

	__init_meta(meta, size, cache);

	addr = (void *)meta->addr;
	for_each_canary(meta, set_canary_byte);

	/* Set required struct page fields. */
	page = virt_to_page(meta->addr);
	__SetPageSlab(page);
	page->slab_cache = cache;
	if (IS_ENABLED(CONFIG_SLUB))
		page->objects = 1;
	if (IS_ENABLED(CONFIG_SLAB))
		page->s_mem = addr;

	raw_spin_unlock_irqrestore(&meta->lock, flags);

	/* Memory initialization. */

	/*
	 * We check slab_want_init_on_alloc() ourselves, rather than letting
	 * SL*B do the initialization, as otherwise we might overwrite KFENCE's
	 * redzone.
	 */
	if (unlikely(slab_want_init_on_alloc(gfp, cache)))
		memzero_explicit(addr, size);
	if (cache->ctor)
		cache->ctor(addr);

	if (CONFIG_KFENCE_STRESS_TEST_FAULTS && !prandom_u32_max(CONFIG_KFENCE_STRESS_TEST_FAULTS))
		kfence_protect(meta->addr); /* Random "faults" by protecting the object. */

	this_cpu_counter->counter[KFENCE_COUNTER_ALLOCATED]++;
	this_cpu_counter->counter[KFENCE_COUNTER_ALLOCS]++;

	return addr;
}

static struct page *kfence_guarded_alloc_page(int node)
{
	struct kfence_metadata *meta;
	struct kfence_counter *this_cpu_counter = raw_cpu_ptr(counters);
	unsigned long flags;
	struct page *page;
	void *addr;

	/* Try to obtain a free object. */
	meta = get_free_meta(node);
	if (!meta)
		return NULL;

	if (unlikely(!raw_spin_trylock_irqsave(&meta->lock, flags))) {
		/*
		 * This is extremely unlikely -- we are reporting on a
		 * use-after-free, which locked meta->lock, and the reporting
		 * code via printk calls kmalloc() which ends up in
		 * kfence_alloc() and tries to grab the same object that we're
		 * reporting on. While it has never been observed, lockdep does
		 * report that there is a possibility of deadlock. Fix it by
		 * using trylock and bailing out gracefully.
		 * Put the object back on the freelist.
		 */
		put_free_meta(meta, node);

		return NULL;
	}

	__init_meta(meta, PAGE_SIZE, NULL);

	addr = (void *)meta->addr;
	page = virt_to_page(addr);
	__ClearPageSlab(page);
#ifdef CONFIG_DEBUG_VM
	atomic_set(&page->_refcount, 0);
#endif

	raw_spin_unlock_irqrestore(&meta->lock, flags);

	if (CONFIG_KFENCE_STRESS_TEST_FAULTS && !prandom_u32_max(CONFIG_KFENCE_STRESS_TEST_FAULTS))
		kfence_protect(meta->addr); /* Random "faults" by protecting the object. */

	this_cpu_counter->counter[KFENCE_COUNTER_ALLOCATED_PAGE]++;
	this_cpu_counter->counter[KFENCE_COUNTER_ALLOCS_PAGE]++;

	return page;
}

static inline void put_free_meta_to_node(struct kfence_metadata *object,
					 struct kfence_freelist_node *kfence_freelist)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&kfence_freelist->lock, flags);
	list_add_tail(&object->list, &kfence_freelist->freelist);
	raw_spin_unlock_irqrestore(&kfence_freelist->lock, flags);
}

static void put_free_meta_slowpath(struct kfence_freelist_cpu *c,
				   struct kfence_freelist_node *kfence_freelist)
{
	struct list_head *entry = &c->freelist, new_list;

	do {
		entry = entry->next;
		c->count--;
	} while (c->count > KFENCE_FREELIST_PERCPU_SIZE);

	list_cut_position(&new_list, &c->freelist, entry);
	raw_spin_lock(&kfence_freelist->lock);
	list_splice_tail(&new_list, &kfence_freelist->freelist);
	raw_spin_unlock(&kfence_freelist->lock);
}

static void put_free_meta(struct kfence_metadata *object, int node)
{
	unsigned long flags;
	struct kfence_freelist_cpu *c;
	struct kfence_freelist_node *kfence_freelist = &freelist.node[node];

	KFENCE_WARN_ON(!list_empty(&object->list));

	/* If meta not on current node, just return it to its own nodelist */
	if (unlikely(node != numa_node_id())) {
		put_free_meta_to_node(object, kfence_freelist);
		return;
	}

	local_irq_save(flags);
	c = get_cpu_ptr(freelist.cpu);

	list_add_tail(&object->list, &c->freelist);
	c->count++;

	if (unlikely(c->count == KFENCE_FREELIST_PERCPU_SIZE * 2))
		put_free_meta_slowpath(c, kfence_freelist);

	put_cpu_ptr(c);
	local_irq_restore(flags);
}

static inline bool __free_meta(void *addr, struct kfence_metadata *meta, bool zombie, bool is_page)
{
	struct kcsan_scoped_access assert_page_exclusive;
	struct kfence_counter *this_cpu_counter = raw_cpu_ptr(counters);
	unsigned long flags;

	raw_spin_lock_irqsave(&meta->lock, flags);

	if (meta->state != KFENCE_OBJECT_ALLOCATED || meta->addr != (unsigned long)addr) {
		/* Invalid or double-free, bail out. */
		this_cpu_counter->counter[KFENCE_COUNTER_BUGS]++;
		kfence_report_error((unsigned long)addr, false, NULL, meta,
				    KFENCE_ERROR_INVALID_FREE);
		raw_spin_unlock_irqrestore(&meta->lock, flags);
		return false;
	}

	/* Detect racy use-after-free, or incorrect reallocation of this page by KFENCE. */
	kcsan_begin_scoped_access((void *)ALIGN_DOWN((unsigned long)addr, PAGE_SIZE), PAGE_SIZE,
				  KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT,
				  &assert_page_exclusive);

	if (CONFIG_KFENCE_STRESS_TEST_FAULTS)
		kfence_unprotect((unsigned long)addr); /* To check canary bytes. */

	/* Restore page protection if there was an OOB access. */
	if (meta->unprotected_page) {
		memzero_explicit((void *)ALIGN_DOWN(meta->unprotected_page, PAGE_SIZE), PAGE_SIZE);
		kfence_protect(meta->unprotected_page);
		meta->unprotected_page = 0;
	}

	if (!is_page) {
		/* Check canary bytes for memory corruption. */
		for_each_canary(meta, check_canary_byte);

		/*
		 * Clear memory if init-on-free is set. While we protect the page, the
		 * data is still there, and after a use-after-free is detected, we
		 * unprotect the page, so the data is still accessible.
		 */
		if (!zombie && unlikely(slab_want_init_on_free(meta->cache)))
			memzero_explicit(addr, meta->size);
	}

	/* Mark the object as freed. */
	metadata_update_state(meta, KFENCE_OBJECT_FREED);

	raw_spin_unlock_irqrestore(&meta->lock, flags);

	/* Protect to detect use-after-frees. */
	kfence_protect((unsigned long)addr);

	kcsan_end_scoped_access(&assert_page_exclusive);

	return true;
}

static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool zombie)
{
	int node = virt_to_nid(addr);
	struct kfence_counter *this_cpu_counter = raw_cpu_ptr(counters);

	if (!__free_meta(addr, meta, zombie, false))
		return;

	if (!zombie) {
		put_free_meta(meta, node);

		this_cpu_counter->counter[KFENCE_COUNTER_ALLOCATED]--;
		this_cpu_counter->counter[KFENCE_COUNTER_FREES]++;
	} else {
		/* See kfence_shutdown_cache(). */
		this_cpu_counter->counter[KFENCE_COUNTER_ZOMBIES]++;
	}
}

static void kfence_guarded_free_page(struct page *page, void *addr, struct kfence_metadata *meta)
{
	int node = page_to_nid(page);
	struct kfence_counter *this_cpu_counter = raw_cpu_ptr(counters);

	if (!__free_meta(addr, meta, false, true))
		return;

	put_free_meta(meta, node);

	this_cpu_counter->counter[KFENCE_COUNTER_ALLOCATED_PAGE]--;
	this_cpu_counter->counter[KFENCE_COUNTER_FREES_PAGE]++;

}

static void rcu_guarded_free(struct rcu_head *h)
{
	struct kfence_metadata *meta = container_of(h, struct kfence_metadata, rcu_head);

	kfence_guarded_free((void *)meta->addr, meta, false);
}

static inline void kfence_clear_page_info(unsigned long addr, unsigned long size)
{
	unsigned long i;

	for (i = addr; i < addr + size; i += PAGE_SIZE) {
		struct page *page = virt_to_page(i);

		__ClearPageKfence(page);
		__ClearPageSlab(page);
		page->mapping = NULL;
		atomic_set(&page->_refcount, 1);
		kfence_unprotect(i);
	}
}

static bool __init_freelist(void)
{
	int i;

	freelist.node = kmalloc_array(nr_node_ids, sizeof(struct kfence_freelist_node),
				      GFP_KERNEL);
	freelist.cpu = alloc_percpu(struct kfence_freelist_cpu);
	counters = alloc_percpu(struct kfence_counter);

	if (!freelist.node || !freelist.cpu || !counters)
		return false;

	for_each_node(i) {
		INIT_LIST_HEAD(&freelist.node[i].freelist);
		raw_spin_lock_init(&freelist.node[i].lock);
	}

	for_each_possible_cpu(i)
		INIT_LIST_HEAD(&per_cpu_ptr(freelist.cpu, i)->freelist);

	return true;
}

static void __free_freelist(void)
{
	kfree(freelist.node);
	freelist.node = NULL;
	free_percpu(freelist.cpu);
	freelist.cpu = NULL;
	free_percpu(counters);
	counters = NULL;
}

#define KFENCE_MAX_SIZE_WITH_INTERVAL 65535
static struct delayed_work kfence_timer;
static void __start_kfence(void)
{
	struct kfence_pool_area *kpa;
	struct rb_node *iter;

	kfence_for_each_area(kpa, iter) {
		pr_info("initialized - using %lu bytes for %lu objects on node %d",
			kpa->pool_size, kpa->nr_objects, kpa->node);
		if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
			pr_cont(" at 0x%px-0x%px\n", (void *)kpa->addr,
				(void *)(kpa->addr + kpa->pool_size));
		else
			pr_cont("\n");
	}

	WRITE_ONCE(kfence_enabled, true);
	static_branch_enable(&kfence_once_inited);
	if (kfence_num_objects > KFENCE_MAX_SIZE_WITH_INTERVAL) {
		static_branch_enable(&kfence_skip_interval);
		static_branch_enable(&kfence_allocation_key);
	} else {
		queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
	}
}

static bool __kfence_init_pool_area(struct kfence_pool_area *kpa)
{
	char *__kfence_pool = kpa->addr;
	struct kfence_metadata *kfence_metadata = kpa->meta;
	struct kfence_freelist_node *kfence_freelist = &freelist.node[kpa->node];
	unsigned long addr = (unsigned long)__kfence_pool;
	struct page *pages;
	int i;

	if (!arch_kfence_init_pool(kpa))
		goto err;

	pages = virt_to_page(addr);

	/*
	 * Set up object pages: they must have PG_slab set, to avoid freeing
	 * these as real pages.
	 *
	 * We also want to avoid inserting kfence_free() in the kfree()
	 * fast-path in SLUB, and therefore need to ensure kfree() correctly
	 * enters __slab_free() slow-path.
	 */
	for (i = 0; i < kpa->pool_size / PAGE_SIZE; i++) {
		__SetPageKfence(&pages[i]);

		if (!i || (i % 2))
			continue;

		/* Verify we do not have a compound head page. */
		if (WARN_ON(compound_head(&pages[i]) != &pages[i]))
			goto err;
	}

	/*
	 * Protect the first 2 pages. The first page is mostly unnecessary, and
	 * merely serves as an extended guard page. However, adding one
	 * additional page in the beginning gives us an even number of pages,
	 * which simplifies the mapping of address to metadata index.
	 */
	for (i = 0; i < 2; i++) {
		if (unlikely(!kfence_protect(addr)))
			goto err;

		addr += PAGE_SIZE;
	}

	for (i = 0; i < kpa->nr_objects; i++) {
		struct kfence_metadata *meta = &kfence_metadata[i];

		/* Initialize metadata. */
		INIT_LIST_HEAD(&meta->list);
		raw_spin_lock_init(&meta->lock);
		meta->state = KFENCE_OBJECT_UNUSED;
		meta->addr = addr; /* Initialize for validation in metadata_to_pageaddr(). */
		meta->kpa = kpa;
		list_add_tail(&meta->list, &kfence_freelist->freelist);

		/* Protect the right redzone. */
		if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
			goto err;

		addr += 2 * PAGE_SIZE;
	}

	/*
	 * The pool is live and will never be deallocated from this point on.
	 * Remove the pool object from the kmemleak object tree, as it would
	 * otherwise overlap with allocations returned by kfence_alloc(), which
	 * are registered with kmemleak through the slab post-alloc hook.
	 */
	kmemleak_free(__kfence_pool);

	return true;

err:
	kfence_clear_page_info((unsigned long)kpa->addr, kpa->pool_size);
	return false;
}

static bool kfence_rb_less(struct rb_node *a, const struct rb_node *b)
{
	return (unsigned long)kfence_rbentry(a)->addr < (unsigned long)kfence_rbentry(b)->addr;
}

static bool __init kfence_init_pool_node(int node)
{
	char *__kfence_pool = __kfence_pool_node[node];
	struct kfence_pool_area *kpa;
	unsigned long metadata_size = sizeof(struct kfence_metadata) * kfence_num_objects;
	unsigned long kfence_pool_size = (kfence_num_objects + 1) * 2 * PAGE_SIZE;

	if (!__kfence_pool)
		return false;

	kpa = kzalloc_node(sizeof(struct kfence_pool_area), GFP_KERNEL, node);
	if (!kpa)
		goto fail;
	kpa->meta = vzalloc_node(metadata_size, node);
	if (!kpa->meta)
		goto fail;
	kpa->addr = __kfence_pool;
	kpa->pool_size = kfence_pool_size;
	kpa->nr_objects = kfence_num_objects;
	kpa->node = node;

	if (!__kfence_init_pool_area(kpa))
		goto fail;

	rb_add(&kpa->rb_node, &kfence_pool_root, kfence_rb_less);

	return true;

fail:
	memblock_free_late(__pa(__kfence_pool), kfence_pool_size);
	__kfence_pool_node[node] = NULL;
	if (kpa) {
		vfree(kpa->meta);
		kfree(kpa);
	}

	return false;
}

static bool __init kfence_init_pool(void)
{
	int node;
	bool success_once = false;

	for_each_node(node) {
		if (kfence_init_pool_node(node))
			success_once = true;
		else
			pr_err("failed to init kfence pool on node %d\n", node);
	}

	return success_once;
}

/* === DebugFS Interface ==================================================== */

static int stats_show(struct seq_file *seq, void *v)
{
	int i, cpu;

	seq_printf(seq, "enabled: %i\n", READ_ONCE(kfence_enabled));

	if (!counters)
		return 0;

	for (i = 0; i < KFENCE_COUNTER_COUNT; i++) {
		s64 sum = 0;
		/*
		 * This calculation may not accurate, but don't mind since we are
		 * mostly interested in bugs and zombies. They are rare and likely
		 * not changed during calculating.
		 */
		for_each_possible_cpu(cpu)
			sum += per_cpu_ptr(counters, cpu)->counter[i];
		seq_printf(seq, "%s: %lld\n", counter_names[i], sum);
	}

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(stats);

/*
 * debugfs seq_file operations for /sys/kernel/debug/kfence/objects.
 * start_object() and next_object() return the metadata.
 */
static void *start_object(struct seq_file *seq, loff_t *pos)
{
	loff_t index = *pos;
	struct kfence_pool_area *kpa;
	struct rb_node *iter;

	kfence_for_each_area(kpa, iter) {
		if (index >= kpa->nr_objects) {
			index -= kpa->nr_objects;
			continue;
		}
		return &kpa->meta[index];
	}
	return NULL;
}

static void stop_object(struct seq_file *seq, void *v)
{
}

static void *next_object(struct seq_file *seq, void *v, loff_t *pos)
{
	struct kfence_metadata *meta = (struct kfence_metadata *)v;
	struct kfence_pool_area *kpa = meta->kpa;
	struct rb_node *cur = &kpa->rb_node;

	++*pos;
	++meta;
	if (meta - kpa->meta < kpa->nr_objects)
		return meta;
	seq_puts(seq, "---------------------------------\n");
	cur = rb_next(cur);
	if (!cur)
		return NULL;

	return kfence_rbentry(cur)->meta;
}

static int show_object(struct seq_file *seq, void *v)
{
	struct kfence_metadata *meta = (struct kfence_metadata *)v;
	unsigned long flags;
	char buf[20];

	if (!meta)
		return 0;

	sprintf(buf, "node %d:\n", meta->kpa->node);
	seq_puts(seq, buf);
	raw_spin_lock_irqsave(&meta->lock, flags);
	kfence_print_object(seq, meta);
	raw_spin_unlock_irqrestore(&meta->lock, flags);
	seq_puts(seq, "---------------------------------\n");

	return 0;
}

static const struct seq_operations object_seqops = {
	.start = start_object,
	.next = next_object,
	.stop = stop_object,
	.show = show_object,
};

static int open_objects(struct inode *inode, struct file *file)
{
	return seq_open(file, &object_seqops);
}

static const struct file_operations objects_fops = {
	.open = open_objects,
	.read = seq_read,
	.llseek = seq_lseek,
};

static int __init kfence_debugfs_init(void)
{
	struct dentry *kfence_dir = debugfs_create_dir("kfence", NULL);

	debugfs_create_file("stats", 0444, kfence_dir, NULL, &stats_fops);
	debugfs_create_file("objects", 0400, kfence_dir, NULL, &objects_fops);
	return 0;
}

late_initcall(kfence_debugfs_init);

/* === Allocation Gate Timer ================================================ */

#ifdef CONFIG_KFENCE_STATIC_KEYS
/* Wait queue to wake up allocation-gate timer task. */
static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);

static void wake_up_kfence_timer(struct irq_work *work)
{
	wake_up(&allocation_wait);
}
static DEFINE_IRQ_WORK(wake_up_kfence_timer_work, wake_up_kfence_timer);
#endif

/*
 * Set up delayed work, which will enable and disable the static key. We need to
 * use a work queue (rather than a simple timer), since enabling and disabling a
 * static key cannot be done from an interrupt.
 *
 * Note: Toggling a static branch currently causes IPIs, and here we'll end up
 * with a total of 2 IPIs to all CPUs. If this ends up a problem in future (with
 * more aggressive sampling intervals), we could get away with a variant that
 * avoids IPIs, at the cost of not immediately capturing allocations if the
 * instructions remain cached.
 */
static void toggle_allocation_gate(struct work_struct *work)
{
	if (!READ_ONCE(kfence_enabled))
		return;

	atomic_set(&kfence_allocation_gate, 0);
#ifdef CONFIG_KFENCE_STATIC_KEYS
	/* Enable static key, and await allocation to happen. */
	static_branch_enable(&kfence_allocation_key);

	if (sysctl_hung_task_timeout_secs) {
		/*
		 * During low activity with no allocations we might wait a
		 * while; let's avoid the hung task warning.
		 */
		wait_event_idle_timeout(allocation_wait, atomic_read(&kfence_allocation_gate),
					sysctl_hung_task_timeout_secs * HZ / 2);
	} else {
		wait_event_idle(allocation_wait, atomic_read(&kfence_allocation_gate));
	}

	/* Disable static key and reset timer. */
	static_branch_disable(&kfence_allocation_key);
#endif
	queue_delayed_work(system_unbound_wq, &kfence_timer,
			   msecs_to_jiffies(kfence_sample_interval));
}
static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);

/* === Public interface ===================================================== */

void __init kfence_alloc_pool(void)
{
	int node;
	unsigned long kfence_pool_size = (kfence_num_objects + 1) * 2 * PAGE_SIZE;

	/* Setting kfence_sample_interval to 0 on boot disables KFENCE. */
	if (!READ_ONCE(kfence_sample_interval))
		return;

	__kfence_pool_node = memblock_alloc(sizeof(char *) * nr_node_ids, PAGE_SIZE);

	if (!__kfence_pool_node) {
		WRITE_ONCE(kfence_sample_interval, 0);
		return;
	}

	for_each_node(node) {
		__kfence_pool_node[node] = memblock_alloc_node(kfence_pool_size, PAGE_SIZE, node);
		if (!__kfence_pool_node[node]) {
			pr_err("kfence alloc pool on node %d failed\n", node);
		}
	}
}

void __init kfence_init(void)
{
	int node;
	unsigned long kfence_pool_size = (kfence_num_objects + 1) * 2 * PAGE_SIZE;

	if (!READ_ONCE(kfence_sample_interval))
		return;

	if (!__init_freelist())
		goto fail;

	if (!kfence_init_pool()) {
		pr_err("%s failed on all nodes!\n", __func__);
		goto fail;
	}

	__start_kfence();
	goto out;

fail:
	for_each_node(node) {
		if (__kfence_pool_node[node]) {
			memblock_free_late(__pa(__kfence_pool_node[node]), kfence_pool_size);
			__kfence_pool_node[node] = NULL;
		}
	}

	__free_freelist();

out:
	memblock_free_late(__pa(__kfence_pool_node), sizeof(char *) * nr_node_ids);
	__kfence_pool_node = NULL;
}

static void kfence_shutdown_cache_area(struct kmem_cache *s, struct kfence_pool_area *kpa)
{
	unsigned long flags;
	struct kfence_metadata *meta, *kfence_metadata = kpa->meta;
	int i;

	for (i = 0; i < kpa->nr_objects; i++) {
		bool in_use;

		meta = &kfence_metadata[i];

		/*
		 * If we observe some inconsistent cache and state pair where we
		 * should have returned false here, cache destruction is racing
		 * with either kmem_cache_alloc() or kmem_cache_free(). Taking
		 * the lock will not help, as different critical section
		 * serialization will have the same outcome.
		 */
		if (READ_ONCE(meta->cache) != s ||
		    READ_ONCE(meta->state) != KFENCE_OBJECT_ALLOCATED)
			continue;

		raw_spin_lock_irqsave(&meta->lock, flags);
		in_use = meta->cache == s && meta->state == KFENCE_OBJECT_ALLOCATED;
		raw_spin_unlock_irqrestore(&meta->lock, flags);

		if (in_use) {
			/*
			 * This cache still has allocations, and we should not
			 * release them back into the freelist so they can still
			 * safely be used and retain the kernel's default
			 * behaviour of keeping the allocations alive (leak the
			 * cache); however, they effectively become "zombie
			 * allocations" as the KFENCE objects are the only ones
			 * still in use and the owning cache is being destroyed.
			 *
			 * We mark them freed, so that any subsequent use shows
			 * more useful error messages that will include stack
			 * traces of the user of the object, the original
			 * allocation, and caller to shutdown_cache().
			 */
			kfence_guarded_free((void *)meta->addr, meta, /*zombie=*/true);
		}
	}

	for (i = 0; i < kpa->nr_objects; i++) {
		meta = &kfence_metadata[i];

		/* See above. */
		if (READ_ONCE(meta->cache) != s || READ_ONCE(meta->state) != KFENCE_OBJECT_FREED)
			continue;

		raw_spin_lock_irqsave(&meta->lock, flags);
		if (meta->cache == s && meta->state == KFENCE_OBJECT_FREED)
			meta->cache = NULL;
		raw_spin_unlock_irqrestore(&meta->lock, flags);
	}
}

void kfence_shutdown_cache(struct kmem_cache *s)
{
	struct kfence_pool_area *kpa;
	struct rb_node *iter;

	if (!static_branch_unlikely(&kfence_once_inited))
		return;

	kfence_for_each_area(kpa, iter)
		kfence_shutdown_cache_area(s, kpa);
}

void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags, int node)
{
	/*
	 * Perform size check before switching kfence_allocation_gate, so that
	 * we don't disable KFENCE without making an allocation.
	 */
	if (size > PAGE_SIZE)
		return NULL;

	/*
	 * Skip allocations from non-default zones, including DMA. We cannot
	 * guarantee that pages in the KFENCE pool will have the requested
	 * properties (e.g. reside in DMAable memory).
	 */
	if ((flags & GFP_ZONEMASK) ||
	    (s->flags & (SLAB_CACHE_DMA | SLAB_CACHE_DMA32)))
		return NULL;

	if (static_branch_likely(&kfence_skip_interval))
		goto alloc;

	/*
	 * allocation_gate only needs to become non-zero, so it doesn't make
	 * sense to continue writing to it and pay the associated contention
	 * cost, in case we have a large number of concurrent allocations.
	 */
	if (atomic_read(&kfence_allocation_gate) || atomic_inc_return(&kfence_allocation_gate) > 1)
		return NULL;
#ifdef CONFIG_KFENCE_STATIC_KEYS
	/*
	 * waitqueue_active() is fully ordered after the update of
	 * kfence_allocation_gate per atomic_inc_return().
	 */
	if (waitqueue_active(&allocation_wait)) {
		/*
		 * Calling wake_up() here may deadlock when allocations happen
		 * from within timer code. Use an irq_work to defer it.
		 */
		irq_work_queue(&wake_up_kfence_timer_work);
	}
#endif

alloc:
	if (!READ_ONCE(kfence_enabled))
		return NULL;

	if (node == NUMA_NO_NODE)
		node = numa_node_id();

	return kfence_guarded_alloc(s, size, flags, node);
}

struct page *__kfence_alloc_page(int node, gfp_t flags)
{
	if (static_branch_likely(&kfence_skip_interval))
		goto alloc;

	/*
	 * allocation_gate only needs to become non-zero, so it doesn't make
	 * sense to continue writing to it and pay the associated contention
	 * cost, in case we have a large number of concurrent allocations.
	 */
	if (atomic_read(&kfence_allocation_gate) || atomic_inc_return(&kfence_allocation_gate) > 1)
		return NULL;
#ifdef CONFIG_KFENCE_STATIC_KEYS
	/*
	 * waitqueue_active() is fully ordered after the update of
	 * kfence_allocation_gate per atomic_inc_return().
	 */
	if (waitqueue_active(&allocation_wait)) {
		/*
		 * Calling wake_up() here may deadlock when allocations happen
		 * from within timer code. Use an irq_work to defer it.
		 */
		irq_work_queue(&wake_up_kfence_timer_work);
	}
#endif

alloc:
	if (!READ_ONCE(kfence_enabled))
		return NULL;

	return kfence_guarded_alloc_page(node);
}

size_t kfence_ksize(const void *addr)
{
	struct kfence_metadata *meta;

	if (!static_branch_unlikely(&kfence_once_inited))
		return 0;

	meta = addr_to_metadata((unsigned long)addr);

	/*
	 * Read locklessly -- if there is a race with __kfence_alloc(), this is
	 * either a use-after-free or invalid access.
	 */
	return meta ? meta->size : 0;
}

void *kfence_object_start(const void *addr)
{
	struct kfence_metadata *meta;

	if (!static_branch_unlikely(&kfence_once_inited))
		return NULL;

	meta = addr_to_metadata((unsigned long)addr);

	/*
	 * Read locklessly -- if there is a race with __kfence_alloc(), this is
	 * either a use-after-free or invalid access.
	 */
	return meta ? (void *)meta->addr : NULL;
}

void __kfence_free(void *addr)
{
	struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);

	/*
	 * If the objects of the cache are SLAB_TYPESAFE_BY_RCU, defer freeing
	 * the object, as the object page may be recycled for other-typed
	 * objects once it has been freed. meta->cache may be NULL if the cache
	 * was destroyed.
	 */
	if (unlikely(meta->cache && (meta->cache->flags & SLAB_TYPESAFE_BY_RCU)))
		call_rcu(&meta->rcu_head, rcu_guarded_free);
	else
		kfence_guarded_free(addr, meta, false);
}

void __kfence_free_page(struct page *page, void *addr)
{
	struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);

	kfence_guarded_free_page(page, addr, meta);
}

bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs *regs)
{
	int page_index;
	struct kfence_metadata *to_report = NULL;
	enum kfence_error_type error_type;
	unsigned long flags;
	struct kfence_pool_area *kpa;

	if (!static_branch_unlikely(&kfence_once_inited))
		return false;

	kpa = get_kfence_pool_area((void *)addr);
	if (!kpa)
		return false;

	if (!READ_ONCE(kfence_enabled)) /* If disabled at runtime ... */
		return kfence_unprotect(addr); /* ... unprotect and proceed. */

	raw_cpu_ptr(counters)->counter[KFENCE_COUNTER_BUGS]++;

	page_index = (addr - (unsigned long)kpa->addr) / PAGE_SIZE;

	if (page_index % 2) {
		/* This is a redzone, report a buffer overflow. */
		struct kfence_metadata *meta;
		int distance = 0;

		meta = addr_to_metadata(addr - PAGE_SIZE);
		if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
			to_report = meta;
			/* Data race ok; distance calculation approximate. */
			distance = addr - data_race(meta->addr + meta->size);
		}

		meta = addr_to_metadata(addr + PAGE_SIZE);
		if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
			/* Data race ok; distance calculation approximate. */
			if (!to_report || distance > data_race(meta->addr) - addr)
				to_report = meta;
		}

		if (!to_report)
			goto out;

		raw_spin_lock_irqsave(&to_report->lock, flags);
		to_report->unprotected_page = addr;
		error_type = KFENCE_ERROR_OOB;

		/*
		 * If the object was freed before we took the look we can still
		 * report this as an OOB -- the report will simply show the
		 * stacktrace of the free as well.
		 */
	} else {
		to_report = addr_to_metadata(addr);
		if (!to_report)
			goto out;

		raw_spin_lock_irqsave(&to_report->lock, flags);
		error_type = KFENCE_ERROR_UAF;
		/*
		 * We may race with __kfence_alloc(), and it is possible that a
		 * freed object may be reallocated. We simply report this as a
		 * use-after-free, with the stack trace showing the place where
		 * the object was re-allocated.
		 */
	}

out:
	if (to_report) {
		kfence_report_error(addr, is_write, regs, to_report, error_type);
		raw_spin_unlock_irqrestore(&to_report->lock, flags);
	} else {
		/* This may be a UAF or OOB access, but we can't be sure. */
		kfence_report_error(addr, is_write, regs, NULL, KFENCE_ERROR_INVALID);
	}

	return kfence_unprotect(addr); /* Unprotect and let access proceed. */
}
