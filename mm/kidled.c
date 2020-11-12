// SPDX-License-Identifier: GPL-2.0
#include <linux/kthread.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/mm_inline.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/page-flags.h>
#include <linux/page_idle.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/kidled.h>
#include <uapi/linux/sched/types.h>

struct kidled_scan_period kidled_scan_period;
const int kidled_default_buckets[NUM_KIDLED_BUCKETS] = {
	1, 2, 5, 15, 30, 60, 120, 240 };
static DECLARE_WAIT_QUEUE_HEAD(kidled_wait);
static unsigned long kidled_scan_rounds __read_mostly;

static inline int kidled_get_bucket(int *idle_buckets, int age)
{
	int bucket;

	if (age < idle_buckets[0])
		return -EINVAL;

	for (bucket = 1; bucket <= (NUM_KIDLED_BUCKETS - 1); bucket++) {
		if (age < idle_buckets[bucket])
			return bucket - 1;
	}

	return NUM_KIDLED_BUCKETS - 1;
}

static inline int kidled_get_idle_type(struct page *page)
{
	int idle_type = KIDLE_BASE;

	if (PageDirty(page) || PageWriteback(page))
		idle_type |= KIDLE_DIRTY;
	if (page_is_file_lru(page))
		idle_type |= KIDLE_FILE;
	/*
	 * Couldn't call page_evictable() here, because we have not held
	 * the page lock, so use page flags instead. Different from
	 * PageMlocked().
	 */
	if (PageUnevictable(page))
		idle_type |= KIDLE_UNEVICT;
	if (PageActive(page))
		idle_type |= KIDLE_ACTIVE;
	return idle_type;
}

#ifndef KIDLED_AGE_NOT_IN_PAGE_FLAGS
int kidled_inc_page_age(pg_data_t *pgdat, unsigned long pfn)
{
	struct page *page = pfn_to_page(pfn);
	unsigned long old, new;
	int age;

	do  {
		age = ((page->flags >> KIDLED_AGE_PGSHIFT) & KIDLED_AGE_MASK);
		if (age >= KIDLED_AGE_MASK)
			break;

		age++;
		new = old = page->flags;
		new &= ~(KIDLED_AGE_MASK << KIDLED_AGE_PGSHIFT);
		new |= ((age & KIDLED_AGE_MASK) << KIDLED_AGE_PGSHIFT);
	} while (unlikely(cmpxchg(&page->flags, old, new) != old));

	return age;
}
EXPORT_SYMBOL_GPL(kidled_inc_page_age);

void kidled_set_page_age(pg_data_t *pgdat, unsigned long pfn, int val)
{
	struct page *page = pfn_to_page(pfn);
	unsigned long old, new;

	do  {
		new = old = page->flags;
		new &= ~(KIDLED_AGE_MASK << KIDLED_AGE_PGSHIFT);
		new |= ((val & KIDLED_AGE_MASK) << KIDLED_AGE_PGSHIFT);
	} while (unlikely(cmpxchg(&page->flags, old, new) != old));

}
EXPORT_SYMBOL_GPL(kidled_set_page_age);
#endif /* !KIDLED_AGE_NOT_IN_PAGE_FLAGS */

#ifdef CONFIG_MEMCG
static inline void kidled_mem_cgroup_account(struct page *page,
					     int age,
					     int nr_pages)
{
	struct mem_cgroup *memcg;
	struct idle_page_stats *stats;
	int type, bucket;

	if (mem_cgroup_disabled())
		return;

	type = kidled_get_idle_type(page);

	memcg = lock_page_memcg(page);
	if (unlikely(!memcg)) {
		unlock_page_memcg(page);
		return;
	}

	stats = mem_cgroup_get_unstable_idle_stats(memcg);
	bucket = kidled_get_bucket(stats->buckets, age);
	if (bucket >= 0)
		stats->count[type][bucket] += nr_pages;

	unlock_page_memcg(page);
}

void kidled_mem_cgroup_move_stats(struct mem_cgroup *from,
				  struct mem_cgroup *to,
				  struct page *page,
				  unsigned int nr_pages)
{
	pg_data_t *pgdat = page_pgdat(page);
	unsigned long pfn = page_to_pfn(page);
	struct idle_page_stats *stats[4] = { NULL, };
	int type, bucket, age;

	if (mem_cgroup_disabled())
		return;

	type = kidled_get_idle_type(page);
	stats[0] = mem_cgroup_get_stable_idle_stats(from);
	stats[1] = mem_cgroup_get_unstable_idle_stats(from);
	if (to) {
		stats[2] = mem_cgroup_get_stable_idle_stats(to);
		stats[3] = mem_cgroup_get_unstable_idle_stats(to);
	}

	/*
	 * We assume the all page ages are same if this is a compound page.
	 * Also we uses node's cursor (@node_idle_scan_pfn) to check if current
	 * page should be removed from the source memory cgroup or charged
	 * to target memory cgroup, without introducing locking mechanism.
	 * This may lead to slightly inconsistent statistics, but it's fine
	 * as it will be reshuffled in next round of scanning.
	 */
	age = kidled_get_page_age(pgdat, pfn);
	if (age < 0)
		return;

	bucket = kidled_get_bucket(stats[1]->buckets, age);
	if (bucket < 0)
		return;

	/* Remove from the source memory cgroup */
	if (stats[0]->count[type][bucket] > nr_pages)
		stats[0]->count[type][bucket] -= nr_pages;
	else
		stats[0]->count[type][bucket] = 0;
	if (pgdat->node_idle_scan_pfn >= pfn) {
		if (stats[1]->count[type][bucket] > nr_pages)
			stats[1]->count[type][bucket] -= nr_pages;
		else
			stats[1]->count[type][bucket] = 0;
	}

	/* Charge to the target memory cgroup */
	if (!to)
		return;

	bucket = kidled_get_bucket(stats[3]->buckets, age);
	if (bucket < 0)
		return;

	stats[2]->count[type][bucket] += nr_pages;
	if (pgdat->node_idle_scan_pfn >= pfn)
		stats[3]->count[type][bucket] += nr_pages;
}
EXPORT_SYMBOL_GPL(kidled_mem_cgroup_move_stats);

static inline void kidled_mem_cgroup_scan_done(struct kidled_scan_period period)
{
	struct mem_cgroup *memcg;
	struct idle_page_stats *stable_stats, *unstable_stats;

	for (memcg = mem_cgroup_iter(NULL, NULL, NULL);
	     memcg != NULL;
	     memcg = mem_cgroup_iter(NULL, memcg, NULL)) {

		down_write(&memcg->idle_stats_rwsem);
		stable_stats = mem_cgroup_get_stable_idle_stats(memcg);
		unstable_stats = mem_cgroup_get_unstable_idle_stats(memcg);

		/*
		 * Switch when scanning buckets is valid, or copy buckets
		 * from stable_stats's buckets which may have user's new
		 * buckets(maybe valid or not).
		 */
		if (!KIDLED_IS_BUCKET_INVALID(unstable_stats->buckets)) {
			mem_cgroup_idle_page_stats_switch(memcg);
			memcg->idle_scans++;
		} else {
			memcpy(unstable_stats->buckets, stable_stats->buckets,
			       sizeof(unstable_stats->buckets));
		}

		memcg->scan_period = period;
		up_write(&memcg->idle_stats_rwsem);

		unstable_stats = mem_cgroup_get_unstable_idle_stats(memcg);
		memset(&unstable_stats->count, 0,
		       sizeof(unstable_stats->count));
	}
}

static inline void kidled_mem_cgroup_reset(void)
{
	struct mem_cgroup *memcg;
	struct idle_page_stats *stable_stats, *unstable_stats;

	for (memcg = mem_cgroup_iter(NULL, NULL, NULL);
	     memcg != NULL;
	     memcg = mem_cgroup_iter(NULL, memcg, NULL)) {
		down_write(&memcg->idle_stats_rwsem);
		stable_stats = mem_cgroup_get_stable_idle_stats(memcg);
		unstable_stats = mem_cgroup_get_unstable_idle_stats(memcg);
		memset(&stable_stats->count, 0, sizeof(stable_stats->count));

		memcg->idle_scans = 0;
		kidled_reset_scan_period(&memcg->scan_period);
		up_write(&memcg->idle_stats_rwsem);

		memset(&unstable_stats->count, 0,
		       sizeof(unstable_stats->count));
	}
}
#else /* !CONFIG_MEMCG */
static inline void kidled_mem_cgroup_account(struct page *page,
					     int age,
					     int nr_pages)
{
}
static inline void kidled_mem_cgroup_scan_done(struct kidled_scan_period
					       scan_period)
{
}
static inline void kidled_mem_cgroup_reset(void)
{
}
#endif /* CONFIG_MEMCG */

/*
 * An idle page with an older age is more likely idle, while a busy page is
 * more likely busy, so we can reduce the sampling frequency to save cpu
 * resource when meet these pages. And we will keep sampling each time when
 * an idle page is young. See tables below:
 *
 *  idle age |   down ratio
 * ----------+-------------
 * [0, 1)    |     1/2      # busy
 * [1, 4)    |      1       # young idle
 * [4, 8)    |     1/2      # idle
 * [8, 16)   |     1/4      # old idle
 * [16, +inf)|     1/8      # older idle
 */
static inline bool kidled_need_check_idle(pg_data_t *pgdat, unsigned long pfn)
{
	struct page *page = pfn_to_page(pfn);
	int age = kidled_get_page_age(pgdat, pfn);
	unsigned long pseudo_random;

	if (age < 0)
		return false;

	/*
	 * kidled will check different pages at each round when need
	 * reduce sampling frequency, this depends on current pfn and
	 * global scanning rounds. There exist some special pfns, for
	 * one huge page, we can only check the head page, while tail
	 * pages would be checked in low levels and will be skipped.
	 * Shifting HPAGE_PMD_ORDER bits is to achieve good load balance
	 * for each round when system has many huge pages, 1GB is not
	 * considered here.
	 */
	if (PageTransHuge(page))
		pfn >>= compound_order(page);

	pseudo_random = pfn + kidled_scan_rounds;
	if (age == 0)
		return pseudo_random & 0x1UL;
	else if (age < 4)
		return true;
	else if (age < 8)
		return pseudo_random & 0x1UL;
	else if (age < 16)
		return (pseudo_random & 0x3UL) == 0x3UL;
	else
		return (pseudo_random & 0x7UL) == 0x7UL;
}

static inline int kidled_scan_page(pg_data_t *pgdat, unsigned long pfn)
{
	struct page *page;
	int age, nr_pages = 1, idx;
	bool idle = false;

	if (!pfn_valid(pfn))
		goto out;

	page = pfn_to_page(pfn);
	if (!page || !PageLRU(page)) {
		kidled_set_page_age(pgdat, pfn, 0);
		goto out;
	}

	/*
	 * Try to skip clear PTE references which is an expensive call.
	 * PG_idle should be cleared when free a page and we have checked
	 * PG_lru flag above, so the race is acceptable to us.
	 */
	if (page_is_idle(page)) {
		if (kidled_need_check_idle(pgdat, pfn)) {
			if (!get_page_unless_zero(page)) {
				kidled_set_page_age(pgdat, pfn, 0);
				goto out;
			}

			/*
			 * Check again after get a reference count, while in
			 * page_idle_get_page() it gets zone_lru_lock at first,
			 * it seems useless.
			 *
			 * Also we can't hold LRU lock here as the consumed
			 * time to finish the scanning is fixed. Otherwise,
			 * the accumulated statistics will be cleared out
			 * and scan interval (@scan_period_in_seconds) will
			 * be doubled. However, this may incur race between
			 * kidled and page reclaim. The page reclaim may dry
			 * run due to dumped refcount, but it's acceptable.
			 */
			if (unlikely(!PageLRU(page))) {
				put_page(page);
				kidled_set_page_age(pgdat, pfn, 0);
				goto out;
			}

			page_idle_clear_pte_refs(page);
			if (page_is_idle(page))
				idle = true;
			put_page(page);
		} else if (kidled_get_page_age(pgdat, pfn) > 0) {
			idle = true;
		}
	}

	if (PageTransHuge(page))
		nr_pages = 1 << compound_order(page);

	if (idle) {
		age = kidled_inc_page_age(pgdat, pfn);
		if (age > 0)
			kidled_mem_cgroup_account(page, age, nr_pages);
		else
			age = 0;
	} else {
		age = 0;
		kidled_set_page_age(pgdat, pfn, 0);
		if (get_page_unless_zero(page)) {
			if (likely(PageLRU(page)))
				set_page_idle(page);
			put_page(page);
		}
	}

	for (idx = 1; idx < nr_pages; idx++)
		kidled_set_page_age(pgdat, pfn + idx, age);

out:
	return nr_pages;
}

static bool kidled_scan_node(pg_data_t *pgdat,
			     struct kidled_scan_period scan_period,
			     bool restart)
{
	unsigned long pfn, end, node_end;

#ifdef KIDLED_AGE_NOT_IN_PAGE_FLAGS
	if (unlikely(!pgdat->node_page_age)) {
		pgdat->node_page_age = vzalloc(pgdat->node_spanned_pages);
		if (unlikely(!pgdat->node_page_age))
			return false;
	}
#endif /* KIDLED_AGE_NOT_IN_PAGE_FLAGS */

	node_end = pgdat_end_pfn(pgdat);
	pfn = pgdat->node_start_pfn;
	if (!restart && pfn < pgdat->node_idle_scan_pfn)
		pfn = pgdat->node_idle_scan_pfn;
	end = min(pfn + DIV_ROUND_UP(pgdat->node_spanned_pages,
				     scan_period.duration), node_end);
	while (pfn < end) {
		/* Restart new scanning when user updates the period */
		if (unlikely(!kidled_is_scan_period_equal(&scan_period)))
			break;

		cond_resched();
		pfn += kidled_scan_page(pgdat, pfn);
	}

	pgdat->node_idle_scan_pfn = pfn;
	return pfn >= node_end;
}

static inline void kidled_scan_done(struct kidled_scan_period scan_period)
{
	kidled_mem_cgroup_scan_done(scan_period);
	kidled_scan_rounds++;
}

static inline void kidled_reset(bool free)
{
	pg_data_t *pgdat;

	kidled_mem_cgroup_reset();

	get_online_mems();

#ifdef KIDLED_AGE_NOT_IN_PAGE_FLAGS
	for_each_online_pgdat(pgdat) {
		if (!pgdat->node_page_age)
			continue;

		if (free) {
			vfree(pgdat->node_page_age);
			pgdat->node_page_age = NULL;
		} else {
			memset(pgdat->node_page_age, 0,
			pgdat->node_spanned_pages);
		}

		cond_resched();
	}
#else
	for_each_online_pgdat(pgdat) {
		unsigned long pfn, end_pfn = pgdat->node_start_pfn +
					     pgdat->node_spanned_pages;

		for (pfn = pgdat->node_start_pfn; pfn < end_pfn; pfn++) {
			if (!pfn_valid(pfn))
				continue;

			kidled_set_page_age(pgdat, pfn, 0);

			if (pfn % HPAGE_PMD_NR == 0)
				cond_resched();
		}
	}
#endif /* KIDLED_AGE_NOT_IN_PAGE_FLAGS */

	put_online_mems();
}

static inline bool kidled_should_run(struct kidled_scan_period *p, bool *new)
{
	if (unlikely(!kidled_is_scan_period_equal(p))) {
		struct kidled_scan_period scan_period;

		scan_period  = kidled_get_current_scan_period();
		if (p->duration)
			kidled_reset(!scan_period.duration);
		*p = scan_period;
		*new = true;
	} else {
		*new = false;
	}

	if (p->duration > 0)
		return true;

	return false;
}

static int kidled(void *dummy)
{
	int busy_loop = 0;
	bool restart = true;
	struct kidled_scan_period scan_period;

	kidled_reset_scan_period(&scan_period);

	while (!kthread_should_stop()) {
		pg_data_t *pgdat;
		u64 start_jiffies, elapsed;
		bool new, scan_done = true;

		wait_event_interruptible(kidled_wait,
					 kidled_should_run(&scan_period, &new));
		if (unlikely(new)) {
			restart = true;
			busy_loop = 0;
		}

		if (unlikely(scan_period.duration == 0))
			continue;

		start_jiffies = jiffies_64;
		get_online_mems();
		for_each_online_pgdat(pgdat) {
			scan_done &= kidled_scan_node(pgdat,
						      scan_period,
						      restart);
		}
		put_online_mems();

		if (scan_done) {
			kidled_scan_done(scan_period);
			restart = true;
		} else {
			restart = false;
		}

		/*
		 * We hope kidled can scan specified pages which depends on
		 * scan_period in each slice, and supposed to finish each
		 * slice in one second:
		 *
		 *	pages_to_scan = total_pages / scan_duration
		 *	for_each_slice() {
		 *		start_jiffies = jiffies_64;
		 *		scan_pages(pages_to_scan);
		 *		elapsed = jiffies_64 - start_jiffies;
		 *		sleep(HZ - elapsed);
		 *	}
		 *
		 * We thought it's busy when elapsed >= (HZ / 2), and if keep
		 * busy for several consecutive times, we'll scale up the
		 * scan duration.
		 *
		 * NOTE it's a simple guard, not a promise.
		 */
#define KIDLED_BUSY_RUNNING		(HZ / 2)
#define KIDLED_BUSY_LOOP_THRESHOLD	10
		elapsed = jiffies_64 - start_jiffies;
		if (elapsed < KIDLED_BUSY_RUNNING) {
			busy_loop = 0;
			schedule_timeout_interruptible(HZ - elapsed);
		} else if (++busy_loop == KIDLED_BUSY_LOOP_THRESHOLD) {
			busy_loop = 0;
			if (kidled_try_double_scan_period(scan_period)) {
				pr_warn_ratelimited("%s: period -> %u\n",
					__func__,
					kidled_get_current_scan_duration());
			}

			/* sleep for a while to relax cpu */
			schedule_timeout_interruptible(elapsed);
		}
	}

	return 0;
}

static ssize_t kidled_scan_period_show(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       char *buf)
{
	return sprintf(buf, "%u\n", kidled_get_current_scan_duration());
}

/*
 * We will update the real scan period and do reset asynchronously,
 * avoid stall when kidled is busy waiting for other resources.
 */
static ssize_t kidled_scan_period_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	unsigned long secs;
	int ret;

	ret = kstrtoul(buf, 10, &secs);
	if (ret || secs > KIDLED_MAX_SCAN_DURATION)
		return -EINVAL;

	kidled_set_scan_duration(secs);
	wake_up_interruptible(&kidled_wait);
	return count;
}

static struct kobj_attribute kidled_scan_period_attr =
	__ATTR(scan_period_in_seconds, 0644,
	       kidled_scan_period_show, kidled_scan_period_store);

static struct attribute *kidled_attrs[] = {
	&kidled_scan_period_attr.attr,
	NULL
};
static struct attribute_group kidled_attr_group = {
	.name = "kidled",
	.attrs = kidled_attrs,
};

static int __init kidled_init(void)
{
	struct task_struct *thread;
	struct sched_param param = { .sched_priority = 0 };
	int ret;

	ret = sysfs_create_group(mm_kobj, &kidled_attr_group);
	if (ret) {
		pr_warn("%s: Error %d on creating sysfs files\n",
		       __func__, ret);
		return ret;
	}

	thread = kthread_run(kidled, NULL, "kidled");
	if (IS_ERR(thread)) {
		sysfs_remove_group(mm_kobj, &kidled_attr_group);
		pr_warn("%s: Failed to start kthread\n", __func__);
		return PTR_ERR(thread);
	}

	/* Make kidled as nice as possible. */
	sched_setscheduler(thread, SCHED_IDLE, &param);

	return 0;
}

module_init(kidled_init);
