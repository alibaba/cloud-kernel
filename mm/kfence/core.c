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
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/sched/clock.h>
#include <linux/sched/sysctl.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/stop_machine.h>
#include <linux/string.h>
#include <linux/mmzone.h>
#include <linux/gfp.h>
#include <linux/nodemask.h>

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
/* true = node mode, false = global mode. */
static bool kfence_pool_node_mode __read_mostly;
static DEFINE_MUTEX(kfence_mutex);
static long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
unsigned long kfence_num_objects __read_mostly = CONFIG_KFENCE_NUM_OBJECTS;
EXPORT_SYMBOL(kfence_num_objects);
static unsigned long kfence_num_objects_snap __read_mostly; /* Used to record upstream ver. */
static int *kfence_node_map; /* Map real node to "virtual kfence node". */
struct kfence_alloc_node_cond {
	long need;
	long allocated;
};
/*
 * An array to record how many objects need to be allocated
 * and how many has been allocated on each node.
 */
static struct kfence_alloc_node_cond *kfence_num_objects_stat;
/* Only used in BOOTING, record partition info about __kfence_pool_area[] */
static unsigned long kfence_nr_areas_per_node;

#ifdef MODULE_PARAM_PREFIX
#undef MODULE_PARAM_PREFIX
#endif
#define MODULE_PARAM_PREFIX "kfence."
#ifdef CONFIG_KFENCE_STATIC_KEYS
/* The static key to set up a KFENCE allocation. */
DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);
#endif
DEFINE_STATIC_KEY_FALSE(kfence_short_canary);
DEFINE_STATIC_KEY_FALSE(kfence_skip_interval);
DEFINE_STATIC_KEY_FALSE(kfence_once_inited);
EXPORT_SYMBOL(kfence_once_inited);
DEFINE_STATIC_KEY_TRUE(kfence_order0_page);

#define KFENCE_MAX_OBJECTS_PER_AREA (PUD_SIZE / PAGE_SIZE / 2 - 1)

static int param_set_sample_interval(const char *val, const struct kernel_param *kp)
{
	long num;
	int ret = kstrtol(val, 0, &num);

	if (ret < 0)
		return ret;

	if (system_state == SYSTEM_BOOTING) {
		*((unsigned long *)kp->arg) = num;
		return 0;
	}

	/* Not allow sample interval switching between positive and negative */
	if ((kfence_sample_interval > 0 && num < 0) ||
	    (kfence_sample_interval < 0 && num > 0)) {
		return -EINVAL;
	}

	if (!num) /* Using 0 to indicate KFENCE is disabled. */
		kfence_disable();

	*((unsigned long *)kp->arg) = num;

	if (!READ_ONCE(kfence_enabled))
		kfence_init_late();

	return 0;
}

static int param_get_sample_interval(char *buffer, const struct kernel_param *kp)
{
	if (!READ_ONCE(kfence_enabled))
		return sprintf(buffer, "0\n");

	return param_get_long(buffer, kp);
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

	if (READ_ONCE(kfence_enabled) || !num)
		return -EINVAL; /* can not change num_objects when enabled */

	*((unsigned long *)kp->arg) = num;
	return 0;
}

static int param_get_num_objects(char *buffer, const struct kernel_param *kp)
{
	return param_get_ulong(buffer, kp);
}

static const struct kernel_param_ops num_objects_param_ops = {
	.set = param_set_num_objects,
	.get = param_get_num_objects,
};
module_param_cb(num_objects, &num_objects_param_ops, &kfence_num_objects, 0600);

static int param_set_pool_mode(const char *val, const struct kernel_param *kp)
{
	bool mode;
	char *s = strstrip((char *)val);

	if (READ_ONCE(kfence_enabled))
		return -EINVAL; /* can not change mode when enabled */

	if (!strcmp(s, "global"))
		mode = false;
	else if (!strcmp(s, "node"))
		mode = true;
	else
		return -EINVAL;

	*((bool *)kp->arg) = mode;

	return 0;
}

static int param_get_pool_mode(char *buffer, const struct kernel_param *kp)
{
	return sprintf(buffer, "%s\n", *(bool *)kp->arg ? "node" : "global");
}

static const struct kernel_param_ops pool_mode_param_ops = {
	.set = param_set_pool_mode,
	.get = param_get_pool_mode,
};
module_param_cb(pool_mode, &pool_mode_param_ops, &kfence_pool_node_mode, 0600);

static int param_set_order0_page(const char *val, const struct kernel_param *kp)
{
	bool res;
	int ret = kstrtobool(val, &res);

	if (ret < 0)
		return ret;

	if (res)
		static_branch_enable(&kfence_order0_page);
	else
		static_branch_disable(&kfence_order0_page);

	return 0;
}

static int param_get_order0_page(char *buffer, const struct kernel_param *kp)
{
	return sprintf(buffer, "%d\n", static_branch_likely(&kfence_order0_page) ? 1 : 0);
}

static const struct kernel_param_ops order0_page_param_ops = {
	.set = param_set_order0_page,
	.get = param_get_order0_page,
};
module_param_cb(order0_page, &order0_page_param_ops, NULL, 0600);

/*
 * The pool of pages used for guard pages and objects.
 * Only used in booting init state. Will be cleared after that.
 */
char **__kfence_pool_area;

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
static struct irq_work __percpu *kfence_flush_work;
static atomic_t kfence_flush_res;

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
	if (static_branch_likely(&kfence_short_canary)) {
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

static struct kfence_metadata *get_free_meta(int real_node)
{
	unsigned long flags;
	struct kfence_freelist_cpu *c;
	struct kfence_freelist_node *kfence_freelist;
	struct kfence_metadata *object;
	int node = kfence_node_map[real_node];

	if (node >= 0)
		kfence_freelist = &freelist.node[node];
	else
		kfence_freelist = &freelist.node[real_node];

	/* If target page not on current node, directly get from its nodelist */
	if (unlikely(node != kfence_node_map[numa_node_id()] || kfence_num_objects_snap))
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
	percpu_ref_get(&meta->kpa->refcnt);
}

static void put_free_meta(struct kfence_metadata *object);
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
		put_free_meta(meta);

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
		put_free_meta(meta);

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

static void put_free_meta(struct kfence_metadata *object)
{
	int node = object->kpa->node;
	unsigned long flags;
	struct kfence_freelist_cpu *c;
	struct kfence_freelist_node *kfence_freelist = &freelist.node[node];

	KFENCE_WARN_ON(!list_empty(&object->list));

	/* If meta not on current node, just return it to its own nodelist */
	if (unlikely(!kfence_node_map || node != kfence_node_map[numa_node_id()] ||
		     kfence_num_objects_snap)) {
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

	percpu_ref_put(&meta->kpa->refcnt);

	raw_spin_unlock_irqrestore(&meta->lock, flags);

	/* Protect to detect use-after-frees. */
	kfence_protect((unsigned long)addr);

	kcsan_end_scoped_access(&assert_page_exclusive);

	return true;
}

static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool zombie)
{
	struct kfence_counter *this_cpu_counter = raw_cpu_ptr(counters);

	if (!__free_meta(addr, meta, zombie, false))
		return;

	if (!zombie) {
		put_free_meta(meta);

		this_cpu_counter->counter[KFENCE_COUNTER_ALLOCATED]--;
		this_cpu_counter->counter[KFENCE_COUNTER_FREES]++;
	} else {
		/* See kfence_shutdown_cache(). */
		this_cpu_counter->counter[KFENCE_COUNTER_ZOMBIES]++;
	}
}

static void kfence_guarded_free_page(struct page *page, void *addr, struct kfence_metadata *meta)
{
	struct kfence_counter *this_cpu_counter = raw_cpu_ptr(counters);

	if (!__free_meta(addr, meta, false, true))
		return;

	put_free_meta(meta);

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

static void __free_freelist(void)
{
	kfree(freelist.node);
	freelist.node = NULL;
	free_percpu(freelist.cpu);
	freelist.cpu = NULL;
	free_percpu(counters);
	counters = NULL;
	free_percpu(kfence_flush_work);
	kfence_flush_work = NULL;
}

static void kfence_flush(struct irq_work *work);
static bool __init_freelist(void)
{
	int i;

	/*
	 * freelist.node, freelist.cpu, counters and kfence_flush_work are
	 * inited together, we only need to check one of them and know whether
	 * we are now in re-enabling.
	 */
	if (counters)
		return true;

	freelist.node = kmalloc_array(nr_node_ids, sizeof(struct kfence_freelist_node),
				      GFP_KERNEL);
	freelist.cpu = alloc_percpu(struct kfence_freelist_cpu);
	counters = alloc_percpu(struct kfence_counter);
	kfence_flush_work = alloc_percpu(struct irq_work);

	if (!freelist.node || !freelist.cpu || !counters || !kfence_flush_work)
		goto fail;

	for_each_node(i) {
		INIT_LIST_HEAD(&freelist.node[i].freelist);
		raw_spin_lock_init(&freelist.node[i].lock);
	}

	for_each_possible_cpu(i) {
		INIT_LIST_HEAD(&per_cpu_ptr(freelist.cpu, i)->freelist);
		init_irq_work(per_cpu_ptr(kfence_flush_work, i), kfence_flush);
	}

	return true;

fail:
	__free_freelist();
	return false;
}

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
	if (kfence_sample_interval < 0) {
		static_branch_enable(&kfence_short_canary);
		static_branch_enable(&kfence_skip_interval);
		static_branch_enable(&kfence_allocation_key);
	} else {
		static_branch_disable(&kfence_skip_interval);
		queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
	}
}

static bool __kfence_init_pool_area(struct kfence_pool_area *kpa)
{
	char *__kfence_pool = kpa->addr;
	struct kfence_metadata *kfence_metadata = kpa->meta;
	struct kfence_freelist_node *kfence_freelist = &freelist.node[kpa->node];
	unsigned long addr = (unsigned long)__kfence_pool, flags;
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

	/* Protect the right redzone. */
	for (i = 0; i < kpa->nr_objects; i++) {
		if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
			goto err;
		addr += 2 * PAGE_SIZE;
	}

	addr = (unsigned long)__kfence_pool + 2 * PAGE_SIZE;
	raw_spin_lock_irqsave(&kfence_freelist->lock, flags);
	for (i = 0; i < kpa->nr_objects; i++) {
		struct kfence_metadata *meta = &kfence_metadata[i];

		/* Initialize metadata. */
		INIT_LIST_HEAD(&meta->list);
		raw_spin_lock_init(&meta->lock);
		meta->state = KFENCE_OBJECT_UNUSED;
		meta->addr = addr; /* Initialize for validation in metadata_to_pageaddr(). */
		meta->kpa = kpa;
		list_add_tail(&meta->list, &kfence_freelist->freelist);

		addr += 2 * PAGE_SIZE;
	}
	raw_spin_unlock_irqrestore(&kfence_freelist->lock, flags);

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

static void __init kfence_alloc_pool_node(int node)
{
	unsigned long nr_need = kfence_num_objects_stat[node].need;
	unsigned long nr_request = min(nr_need, KFENCE_MAX_OBJECTS_PER_AREA);
	unsigned long index = kfence_nr_areas_per_node * node;

	while (nr_need) {
		unsigned long kfence_pool_size = (nr_request + 1) * 2 * PAGE_SIZE;

		__kfence_pool_area[index] = memblock_alloc_node(kfence_pool_size, PUD_SIZE, node);
		if (!__kfence_pool_area[index]) {
			pr_err("kfence alloc pool on node %d failed\n", node);
			break;
		}
		index++;
		nr_need -= nr_request;
		nr_request = min(nr_request, nr_need);
	}
}

static void kpa_release(struct percpu_ref *ref);
static void kfence_free_area(struct work_struct *work);
static inline bool __init_kpa(struct kfence_pool_area *kpa, char *__kfence_pool, int node,
			      unsigned long nr_objects, unsigned long pool_size)
{
	kpa->meta = vzalloc_node(sizeof(struct kfence_metadata) * nr_objects, node);
	if (!kpa->meta)
		goto fail;
	if (percpu_ref_init(&kpa->refcnt, kpa_release, PERCPU_REF_ALLOW_REINIT, GFP_KERNEL))
		goto fail;
	INIT_WORK(&kpa->work, kfence_free_area);
	kpa->addr = __kfence_pool;
	kpa->pool_size = pool_size;
	kpa->nr_objects = nr_objects;
	kpa->node = node;

	if (!__kfence_init_pool_area(kpa))
		goto fail;

	return true;

fail:
	vfree(kpa->meta);
	percpu_ref_exit(&kpa->refcnt);

	return false;
}

static bool __init kfence_init_pool_area(int node, int area)
{
	int index = node * kfence_nr_areas_per_node + area;
	char *__kfence_pool = __kfence_pool_area[index];
	struct kfence_pool_area *kpa;
	unsigned long nr_objects, pool_size;

	if (!__kfence_pool)
		return false;

	nr_objects = min(kfence_num_objects, KFENCE_MAX_OBJECTS_PER_AREA);
	pool_size = (nr_objects + 1) * 2 * PAGE_SIZE;

	kpa = kzalloc_node(sizeof(struct kfence_pool_area), GFP_KERNEL, node);
	if (!kpa)
		goto fail;

	if (!__init_kpa(kpa, __kfence_pool, node, nr_objects, pool_size))
		goto fail;

	rb_add(&kpa->rb_node, &kfence_pool_root, kfence_rb_less);
	__kfence_pool_area[index] = NULL;
	kpa->on_rb_tree = true;
	kfence_num_objects_stat[node].allocated += nr_objects;

	return true;

fail:
	memblock_free_late(__pa(__kfence_pool), pool_size);
	__kfence_pool_area[index] = NULL;
	kfree(kpa);

	return false;
}

static bool __init kfence_init_pool(void)
{
	int area, node;
	bool success_once = false;

	for_each_node(node) {
		for (area = 0; area < kfence_nr_areas_per_node; area++) {
			if (kfence_init_pool_area(node, area))
				success_once = true;
		}
	}

	return success_once;
}

static void kfence_alloc_pool_late_node(int node, struct list_head *ready, bool fallback)
{
	unsigned long nr_need, nr_request;
	struct kfence_alloc_node_cond *knos = &kfence_num_objects_stat[node];
	gfp_t gfp_mask = GFP_KERNEL | __GFP_ZERO;

	if (knos->allocated >= knos->need)
		return;

	nr_need = roundup(knos->need - knos->allocated, KFENCE_MAX_OBJECTS_PER_AREA);
	nr_request = KFENCE_MAX_OBJECTS_PER_AREA;
	if (!fallback)
		gfp_mask |= __GFP_THISNODE;

	while (nr_need) {
		struct page *page;
		struct kfence_pool_area *kpa;
		unsigned long nr_pages = (nr_request + 1) * 2;

		page = alloc_contig_pages(nr_pages, gfp_mask, node, NULL);
		if (!page) {
			pr_err("kfence alloc metadata on node %d failed\n", node);
			return;
		}
		kpa = kzalloc_node(sizeof(struct kfence_pool_area), GFP_KERNEL, node);
		if (!kpa)
			goto fail;

		if (!__init_kpa(kpa, page_to_virt(page), node, nr_request, nr_pages * PAGE_SIZE))
			goto fail;

		list_add(&kpa->list, ready);
		nr_need -= nr_request;
		knos->allocated += nr_request;
		nr_request = min(nr_request, nr_need);

		continue;

fail:
		free_contig_range(page_to_pfn(page), nr_pages);
		kfree(kpa);

		return;
	}
}

static inline void kfence_free_pool_area(struct kfence_pool_area *kpa)
{
	phys_addr_t cursor = PFN_UP(__pa(kpa->addr));
	phys_addr_t end = PFN_DOWN(__pa((unsigned long)kpa->addr + kpa->pool_size));

	for (; cursor < end; cursor++) {
		__free_pages_core(pfn_to_page(cursor), 0);
		totalram_pages_inc();
	}
}

static inline void kfence_free_pool_late_area(struct kfence_pool_area *kpa)
{
	free_contig_range(page_to_pfn(virt_to_page(kpa->addr)), kpa->pool_size / PAGE_SIZE);
}

static int kfence_update_pool_root(void *info)
{
	struct list_head *ready_list = info;
	struct kfence_pool_area *kpa;
	struct rb_node *cur, *next;

	for (cur = rb_first(&kfence_pool_root); cur; cur = next) {
		kpa = kfence_rbentry(cur);
		next = rb_next(cur);
		if (!kpa->nr_objects) {
			rb_erase(&kpa->rb_node, &kfence_pool_root);
			kfree(kpa);
		} else {
			percpu_ref_resurrect(&kpa->refcnt);
		}
	}

	while (!list_empty(ready_list)) {
		kpa = list_first_entry(ready_list, struct kfence_pool_area, list);
		rb_add(&kpa->rb_node, &kfence_pool_root, kfence_rb_less);
		kpa->on_rb_tree = true;
		list_del(&kpa->list);
	}

	return 0;
}

/* Flush this cpu's per cpu freelist to per node freelist. */
static inline void __kfence_flush(void)
{
	struct kfence_freelist_cpu *c;
	struct kfence_freelist_node *kfence_freelist;
	struct kfence_metadata *meta;
	unsigned long flags;

	c = get_cpu_ptr(freelist.cpu);
	if (list_empty(&c->freelist))
		goto out;

	meta = list_first_entry(&c->freelist, struct kfence_metadata, list);
	kfence_freelist = &freelist.node[meta->kpa->node];

	raw_spin_lock_irqsave(&kfence_freelist->lock, flags);
	list_splice_tail_init(&c->freelist, &kfence_freelist->freelist);
	raw_spin_unlock_irqrestore(&kfence_freelist->lock, flags);

out:
	c->count = 0;
	put_cpu_ptr(c);
}

static DECLARE_WAIT_QUEUE_HEAD(kfence_flush_wait);

/*
 * This function is called by kfence_flush_call() through irq_work_queue().
 * DO NOT call it directly.
 */
static void kfence_flush(struct irq_work *work)
{
	__kfence_flush();

	if (!atomic_dec_return(&kfence_flush_res))
		wake_up(&kfence_flush_wait);
}

static void kfence_flush_call(void *info)
{
	irq_work_queue(raw_cpu_ptr(kfence_flush_work));
}

/* Flush percpu freelists on all cpus and wait for return. */
static inline bool kfence_flush_all_and_wait(void)
{
	cpus_read_lock();
	atomic_set(&kfence_flush_res, num_online_cpus());
	on_each_cpu(kfence_flush_call, NULL, 0);
	cpus_read_unlock();

	if (sysctl_hung_task_timeout_secs) {
		if (!wait_event_idle_timeout(kfence_flush_wait, !atomic_read(&kfence_flush_res),
					     sysctl_hung_task_timeout_secs * HZ / 2))
			return false;
	} else {
		wait_event_idle(kfence_flush_wait, !atomic_read(&kfence_flush_res));
	}

	return true;
}

static bool kfence_can_recover_tlb(struct kfence_pool_area *kpa)
{
#ifdef CONFIG_X86_64
	/* only recover 1GiB aligned tlb */
	return kpa->pool_size == PUD_SIZE;
#else
	/*
	 * On arm64, the direct mapping area is already splited to page granularity
	 * with CONFIG_RODATA_FULL_DEFAULT_ENABLED=y, or CONFIG_KFENCE=y. So we will
	 * not recover tlb to pud huge. See upstream commit 840b23986344
	 * ("arm64, kfence: enable KFENCE for ARM64") in detail.
	 */
	return false;
#endif
}

static inline void __kfence_recover_tlb(unsigned long addr)
{
	if (!arch_kfence_free_pool(addr)) {
		pr_warn("fail to recover tlb to 1G");
		if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
			pr_cont(" at 0x%px-0x%px\n", (void *)addr, (void *)(addr + PUD_SIZE));
		else
			pr_cont("\n");
	}
}

static inline void kfence_recover_tlb(struct kfence_pool_area *kpa)
{
	unsigned long base = ALIGN_DOWN((unsigned long)kpa->addr, PUD_SIZE);

	if (kfence_can_recover_tlb(kpa))
		__kfence_recover_tlb(base);
}

/* Free a specific area. The refcnt has been down to 0. */
static void kfence_free_area(struct work_struct *work)
{
	unsigned long flags, i;
	struct page *page;
	struct kfence_pool_area *kpa = container_of(work, struct kfence_pool_area, work);
	struct kfence_freelist_node *kfence_freelist = &freelist.node[kpa->node];

	mutex_lock(&kfence_mutex);
	if (READ_ONCE(kfence_enabled))
		goto out_unlock;

	if (!kfence_flush_all_and_wait())
		goto out_unlock;

	raw_spin_lock_irqsave(&kfence_freelist->lock, flags);
	for (i = 0; i < kpa->nr_objects; i++)
		list_del(&kpa->meta[i].list);

	raw_spin_unlock_irqrestore(&kfence_freelist->lock, flags);

	pr_info("freed %lu bytes for %lu objects on node %d",
		kpa->pool_size, kpa->nr_objects, kpa->node);
	if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
		pr_cont(" at 0x%px-0x%px\n", (void *)kpa->addr,
			(void *)(kpa->addr + kpa->pool_size));
	else
		pr_cont("\n");

	kfence_clear_page_info((unsigned long)kpa->addr, kpa->pool_size);
	kfence_recover_tlb(kpa);
	page = virt_to_page(kpa->addr);

	if (PageReserved(page))
		kfence_free_pool_area(kpa);
	else
		kfence_free_pool_late_area(kpa);

	vfree(kpa->meta);
	kpa->meta = NULL;
	percpu_ref_exit(&kpa->refcnt);
	kpa->nr_objects = 0;
	kpa->pool_size = 0;
	if (!kpa->on_rb_tree)
		kfree(kpa);

out_unlock:
	mutex_unlock(&kfence_mutex);
}

static void kpa_release(struct percpu_ref *ref)
{
	struct kfence_pool_area *kpa = container_of(ref, struct kfence_pool_area, refcnt);

	queue_work(system_long_wq, &kpa->work);
}

static void calculate_need_alloc(void)
{
	int node, nr_kpas, base, remain, nr_node_has_cpu;
	enum node_states node_stat = N_CPU;

	if (!kfence_num_objects_stat)
		return;

	if (kfence_pool_node_mode) {
		for_each_node(node) {
			kfence_num_objects_stat[node].need = kfence_num_objects;
		}
		return;
	}

	if (kfence_num_objects < KFENCE_MAX_OBJECTS_PER_AREA) {
		kfence_num_objects_stat[first_online_node].need = kfence_num_objects;
		return;
	}

	/* In global mode, we only alloc on nodes with cpus (i.e., not on pmem nodes) */
	nr_node_has_cpu = num_node_state(node_stat);
	if (!nr_node_has_cpu) {
		node_stat = N_ONLINE;
		nr_node_has_cpu = num_node_state(node_stat);
	}
	nr_kpas = kfence_num_objects / KFENCE_MAX_OBJECTS_PER_AREA;
	base = nr_kpas / nr_node_has_cpu;
	remain = nr_kpas - base * nr_node_has_cpu;
	for_each_node_state(node, node_stat) {
		kfence_num_objects_stat[node].need = (base + (!!remain)) *
						     KFENCE_MAX_OBJECTS_PER_AREA;
		if (remain)
			remain--;
	}
}

static inline bool __check_map_change(int *new_node_map)
{
	int node;

	for_each_node(node) {
		if (kfence_node_map[node] != new_node_map[node])
			return true;
	}

	return false;
}

static bool update_kfence_node_map(void)
{
	int *new_node_map = kmalloc_array(nr_node_ids, sizeof(int), GFP_KERNEL | __GFP_ZERO);
	int *old_node_map;
	int node;
	enum node_states node_stat = N_CPU;
	struct zonelist *zonelist;
	struct zone *zone;
	struct zoneref *z;

	if (!new_node_map)
		return false;

	memset(new_node_map, -1, sizeof(int) * nr_node_ids);

	if (!num_node_state(node_stat))
		node_stat = N_ONLINE;

	for_each_node_state(node, node_stat) {
		if (kfence_num_objects_stat[node].allocated) {
			new_node_map[node] = node;
			continue;
		}

		/* We borrow from zonelist to get the nearest node to map. */
		zonelist = node_zonelist(node, GFP_KERNEL);
		for_each_zone_zonelist_nodemask(zone, z, zonelist, ZONE_NORMAL, NULL) {
			if (kfence_num_objects_stat[zone_to_nid(zone)].allocated) {
				new_node_map[node] = zone_to_nid(zone);
				break;
			}
		}
	}

	/* It's the first time of init */
	if (!kfence_node_map) {
		kfence_node_map = new_node_map;
		return true;
	}

	if (!__check_map_change(new_node_map)) {
		kfree(new_node_map);
		return true;
	}

	old_node_map = kfence_node_map;
	kfence_node_map = NULL;
	synchronize_rcu();

	if (!kfence_flush_all_and_wait()) {
		kfree(new_node_map);
		return false;
	}

	kfence_node_map = new_node_map;
	kfree(old_node_map);
	return true;
}

/* === DebugFS Interface ==================================================== */

static inline void print_pool_size(struct seq_file *seq, unsigned long byte)
{
	if (byte < SZ_1K)
		seq_printf(seq, "%lu B\n", byte);
	else if (byte < SZ_1M)
		seq_printf(seq, "%lu KB\n", byte / SZ_1K);
	else if (byte < SZ_1G)
		seq_printf(seq, "%lu MB\n", byte / SZ_1M);
	else
		seq_printf(seq, "%lu GB\n", byte / SZ_1G);
}

static int stats_show(struct seq_file *seq, void *v)
{
	int i, cpu;
	struct kfence_pool_area *kpa;
	struct rb_node *iter;
	unsigned long *size_count;

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
		seq_printf(seq, "%-30s:%20lld\n", counter_names[i], sum);
	}

	size_count = kmalloc_array(nr_node_ids * 2, sizeof(unsigned long), GFP_KERNEL | __GFP_ZERO);
	if (!size_count)
		return 0;

	mutex_lock(&kfence_mutex);
	kfence_for_each_area(kpa, iter) {
		if (!kpa->nr_objects)
			continue;
		size_count[kpa->node] += kpa->nr_objects;
		size_count[kpa->node + nr_node_ids] += kpa->pool_size;
	}
	mutex_unlock(&kfence_mutex);

	seq_puts(seq, "\nnode\tobject_size\tpool_size\n");
	for_each_node(i) {
		seq_printf(seq, "%-8d%-16lu", i, size_count[i]);
		print_pool_size(seq, size_count[i + nr_node_ids]);
	}

	kfree(size_count);

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

	mutex_lock(&kfence_mutex);
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
	mutex_unlock(&kfence_mutex);
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
next_meta:
	cur = rb_next(cur);
	if (!cur)
		return NULL;
	kpa = kfence_rbentry(cur);
	if (!kpa->nr_objects)
		goto next_meta;

	return kpa->meta;
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
	.release = seq_release,
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

	/* Setting kfence_sample_interval to 0 on boot disables KFENCE. */
	if (!READ_ONCE(kfence_sample_interval))
		return;

	/*
	 * Not allow both pool size < 1GiB and enabling node mode.
	 * Not allow both pool size < 1GiB and non-interval alloc.
	 */
	if (kfence_num_objects < KFENCE_MAX_OBJECTS_PER_AREA &&
	    (kfence_pool_node_mode || kfence_sample_interval < 0))
		goto fail;

	kfence_num_objects_stat = memblock_alloc(sizeof(struct kfence_alloc_node_cond) *
						 nr_node_ids, PAGE_SIZE);
	if (!kfence_num_objects_stat)
		goto fail;

	/*
	 * If pool size less than 1GiB, use the upstream mode;
	 * else, align pool size up to 1GiB, for tlb split and
	 * recover thought.
	 */
	if (kfence_num_objects >= KFENCE_MAX_OBJECTS_PER_AREA)
		kfence_num_objects = roundup(kfence_num_objects, KFENCE_MAX_OBJECTS_PER_AREA);
	else
		kfence_num_objects_snap = kfence_num_objects;

	calculate_need_alloc();

	for_each_node(node) {
		if (kfence_nr_areas_per_node < kfence_num_objects_stat[node].need)
			kfence_nr_areas_per_node = kfence_num_objects_stat[node].need;
	}
	kfence_nr_areas_per_node /= KFENCE_MAX_OBJECTS_PER_AREA;
	if (!kfence_nr_areas_per_node)
		kfence_nr_areas_per_node = 1;

	__kfence_pool_area = memblock_alloc(sizeof(char *) * nr_node_ids *
					    kfence_nr_areas_per_node, PAGE_SIZE);
	if (!__kfence_pool_area)
		goto fail;

	for_each_node(node)
		kfence_alloc_pool_node(node);

	return;

fail:
	if (kfence_num_objects_stat) {
		memblock_free(__pa(kfence_num_objects_stat),
			      sizeof(struct kfence_alloc_node_cond) * nr_node_ids);
		kfence_num_objects_stat = NULL;
	}
	WRITE_ONCE(kfence_sample_interval, 0);
}

void __init kfence_init(void)
{
	int node, area, index;
	unsigned long nr_objects = min(kfence_num_objects, KFENCE_MAX_OBJECTS_PER_AREA);
	unsigned long kfence_pool_size = (nr_objects + 1) * 2 * PAGE_SIZE;

	if (!READ_ONCE(kfence_sample_interval))
		return;

	if (!__init_freelist())
		goto fail;

	if (!kfence_init_pool()) {
		pr_err("%s failed on all nodes!\n", __func__);
		goto fail;
	}

	if (!update_kfence_node_map()) {
		struct kfence_pool_area *kpa;
		struct rb_node *iter;

		kfence_for_each_area(kpa, iter)
			percpu_ref_kill(&kpa->refcnt);
		goto fail;
	}

	__start_kfence();
	goto out;

fail:
	for_each_node(node) {
		for (area = 0; area < kfence_nr_areas_per_node; area++) {
			index = kfence_nr_areas_per_node * node + area;
			if (__kfence_pool_area[index]) {
				memblock_free_late(__pa(__kfence_pool_area[index]),
						   kfence_pool_size);
				__kfence_pool_area[index] = NULL;
			}
		}
	}

out:
	memblock_free_late(__pa(__kfence_pool_area), sizeof(char *) * nr_node_ids *
			   kfence_nr_areas_per_node);
	__kfence_pool_area = NULL;
	memblock_free_late(__pa(kfence_num_objects_stat),
			   sizeof(struct kfence_alloc_node_cond) * nr_node_ids);
	kfence_num_objects_stat = NULL;
}

void kfence_init_late(void)
{
	int node;
	LIST_HEAD(ready_list);
	struct kfence_pool_area *kpa;
	struct rb_node *iter;
	bool ret;

	if (!READ_ONCE(kfence_sample_interval))
		return;

	mutex_lock(&kfence_mutex);

	if (READ_ONCE(kfence_enabled))
		goto out;

	/*
	 * Keep upstream mode remaining the same.
	 * Otherwise we "forget" the upstream version whose pool size < 1GiB.
	 */
	if (kfence_num_objects > kfence_num_objects_snap || kfence_pool_node_mode) {
		kfence_num_objects = roundup(kfence_num_objects, KFENCE_MAX_OBJECTS_PER_AREA);
		kfence_num_objects_snap = 0;
	}

	if (kfence_num_objects < KFENCE_MAX_OBJECTS_PER_AREA && kfence_sample_interval < 0)
		goto fail;

	if (!__init_freelist())
		goto fail;

	kfence_num_objects_stat = kmalloc_array(nr_node_ids, sizeof(struct kfence_alloc_node_cond),
						GFP_KERNEL | __GFP_ZERO);
	if (!kfence_num_objects_stat)
		goto fail;

	calculate_need_alloc();

	kfence_for_each_area(kpa, iter) {
		if (kpa->nr_objects >= KFENCE_MAX_OBJECTS_PER_AREA || kfence_num_objects_snap)
			kfence_num_objects_stat[kpa->node].allocated += kpa->nr_objects;
	}

	for_each_node(node)
		kfence_alloc_pool_late_node(node, &ready_list, false);

	/*
	 * Try to alloc again if there exists some nodes we fail to alloc on.
	 * These nodes may have no enough contig memory, so fallback to find on
	 * other nodes.
	 */
	for_each_node(node)
		kfence_alloc_pool_late_node(node, &ready_list, true);

	ret = update_kfence_node_map();
	kfree(kfence_num_objects_stat);
	kfence_num_objects_stat = NULL;

	if (!ret) {
		while (!list_empty(&ready_list)) {
			kpa = list_first_entry(&ready_list, struct kfence_pool_area, list);
			list_del(&kpa->list);
			percpu_ref_kill(&kpa->refcnt);
		}
		goto fail;
	}

	if (list_empty(&ready_list) && !static_branch_unlikely(&kfence_once_inited))
		goto fail;

	stop_machine(kfence_update_pool_root, &ready_list, NULL);

	__start_kfence();
	goto out;

fail:
	WRITE_ONCE(kfence_sample_interval, 0);
out:
	mutex_unlock(&kfence_mutex);
}

void kfence_disable(void)
{
	struct kfence_pool_area *kpa;
	struct rb_node *iter;

	if (!xchg(&kfence_enabled, false))
		return;

	synchronize_rcu();

	mutex_lock(&kfence_mutex);

#ifdef CONFIG_KFENCE_STATIC_KEYS
	static_branch_disable(&kfence_allocation_key);
#endif

	kfence_for_each_area(kpa, iter)
		percpu_ref_kill(&kpa->refcnt);

	mutex_unlock(&kfence_mutex);
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

#ifdef CONFIG_SLUB
	if (!s->kfence_enabled)
		return NULL;
#endif

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
