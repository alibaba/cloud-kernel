/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_KIDLED_H
#define _LINUX_MM_KIDLED_H

#ifdef CONFIG_KIDLED

#include <linux/types.h>

#define KIDLED_VERSION			"1.0"

/*
 * We want to get more info about a specified idle page, whether it's
 * a page cache or in active LRU list and so on. We use KIDLE_<flag>
 * to mark these different page attributes, we support 4 flags:
 *
 * KIDLE_DIRTY  : page is dirty or not;
 * KIDLE_FILE   : page is a page cache or not;
 * KIDLE_UNEVIT : page is unevictable or evictable;
 * KIDLE_ACTIVE : page is in active LRU list or not.
 *
 * Each KIDLE_<flag> occupies one bit position in a specified idle type.
 * There exist total 2^4=16 idle types.
 */
#define KIDLE_BASE			0
#define KIDLE_DIRTY			(1 << 0)
#define KIDLE_FILE			(1 << 1)
#define KIDLE_UNEVICT			(1 << 2)
#define KIDLE_ACTIVE			(1 << 3)

#define KIDLE_NR_TYPE			16

/*
 * Each page has an idle age which means how long the page is keeping
 * in idle state, the age's unit is in one scan period. Each page's
 * idle age will consume one byte, so the max age must be 255.
 * Buckets are used for histogram sampling depends on the idle age,
 * e.g. the bucket [5,15) means page's idle age ge than 5 scan periods
 * and lt 15 scan periods. A specified bucket value is a split line of
 * the idle age. We support a maximum of NUM_KIDLED_BUCKETS sampling
 * regions.
 */
#define KIDLED_MAX_IDLE_AGE		U8_MAX
#define NUM_KIDLED_BUCKETS		8

/*
 * Since it's not convenient to get an immediate statistics for a memory
 * cgroup, we use a ping-pong buffer. One is used to store the stable
 * statistics which call it 'stable buffer', it's used for showing.
 * Another is used to store the statistics being updated by scanning
 * threads which call it 'unstable buffer'. Switch them when one scanning
 * round is finished.
 */
#define KIDLED_STATS_NR_TYPE		2

/*
 * When user wants not to account for a specified instance (e.g. may
 * be a memory cgoup), then mark the corresponding buckets to be invalid.
 * kidled will skip accounting when encounter invalid buckets. Note the
 * scanning is still on.
 *
 * When users update new buckets, it means current statistics should be
 * invalid. But we can't reset immediately, reasons as above. We'll reset
 * at a safe point(i.e. one round finished). Store new buckets in stable
 * stats's buckets, while mark unstable stats's buckets to be invalid.
 *
 * This value must be greater than KIDLED_MAX_IDLE_AGE, and can be only
 * used for the first bucket value, so it can return quickly when call
 * kidled_get_bucket(). User shouldn't use KIDLED_INVALID_BUCKET directly.
 */
#define KIDLED_INVALID_BUCKET		(KIDLED_MAX_IDLE_AGE + 1)

#define KIDLED_MARK_BUCKET_INVALID(buckets)	\
	(buckets[0] = KIDLED_INVALID_BUCKET)
#define KIDLED_IS_BUCKET_INVALID(buckets)	\
	(buckets[0] == KIDLED_INVALID_BUCKET)

/*
 * We account number of idle pages depending on idle type and buckets
 * for a specified instance (e.g. one memory cgroup or one process...)
 */
struct idle_page_stats {
	int			buckets[NUM_KIDLED_BUCKETS];
	unsigned long		count[KIDLE_NR_TYPE][NUM_KIDLED_BUCKETS];
};

/*
 * Duration is in seconds, it means kidled will take how long to finish
 * one round (just try, no promise). Sequence number will be increased
 * when user updates the sysfs file each time, it can protect readers
 * won't get stale statistics by comparing the sequence number even
 * duration keep the same. However, there exists a rare race that seq
 * num may wrap and be the same as previous seq num. So we also check
 * the duration to make readers won't get strange statistics. But it may
 * be still stale when seq and duration are both the same as previous
 * value, but I think it's acceptable because duration is the same at
 * least.
 */
#define KIDLED_MAX_SCAN_DURATION	U16_MAX		/* max 65536 seconds */
struct kidled_scan_period {
	union {
		atomic_t		val;
		struct {
			u16		seq;		/* inc when update */
			u16		duration;	/* in seconds */
		};
	};
};
extern struct kidled_scan_period kidled_scan_period;

#define KIDLED_OP_SET_DURATION		(1 << 0)
#define KIDLED_OP_INC_SEQ		(1 << 1)

static inline struct kidled_scan_period kidled_get_current_scan_period(void)
{
	struct kidled_scan_period scan_period;

	atomic_set(&scan_period.val, atomic_read(&kidled_scan_period.val));
	return scan_period;
}

static inline unsigned int kidled_get_current_scan_duration(void)
{
	struct kidled_scan_period scan_period =
		kidled_get_current_scan_period();

	return scan_period.duration;
}

static inline void kidled_reset_scan_period(struct kidled_scan_period *p)
{
	atomic_set(&p->val, 0);
}

/*
 * Compare with global kidled_scan_period, return true if equals.
 */
static inline bool kidled_is_scan_period_equal(struct kidled_scan_period *p)
{
	return atomic_read(&p->val) == atomic_read(&kidled_scan_period.val);
}

static inline bool kidled_set_scan_period(int op, u16 duration,
					  struct kidled_scan_period *orig)
{
	bool retry = false;

	/*
	 * atomic_cmpxchg() tries to update kidled_scan_period, shouldn't
	 * retry to avoid endless loop when caller specify a period.
	 */
	if (!orig) {
		orig = &kidled_scan_period;
		retry = true;
	}

	while (true) {
		int new_period_val, old_period_val;
		struct kidled_scan_period new_period;

		old_period_val = atomic_read(&orig->val);
		atomic_set(&new_period.val, old_period_val);
		if (op & KIDLED_OP_INC_SEQ)
			new_period.seq++;
		if (op & KIDLED_OP_SET_DURATION)
			new_period.duration = duration;
		new_period_val = atomic_read(&new_period.val);

		if (atomic_cmpxchg(&kidled_scan_period.val,
				   old_period_val,
				   new_period_val) == old_period_val)
			return true;

		if (!retry)
			return false;
	}
}

static inline void kidled_set_scan_duration(u16 duration)
{
	kidled_set_scan_period(KIDLED_OP_INC_SEQ |
			       KIDLED_OP_SET_DURATION,
			       duration, NULL);
}

/*
 * Caller must specify the original scan period, avoid the race between
 * the double operation and user's updates through sysfs interface.
 */
static inline bool kidled_try_double_scan_period(struct kidled_scan_period orig)
{
	u16 duration = orig.duration;

	if (unlikely(duration == KIDLED_MAX_SCAN_DURATION))
		return false;

	duration <<= 1;
	if (duration < orig.duration)
		duration = KIDLED_MAX_SCAN_DURATION;
	return kidled_set_scan_period(KIDLED_OP_INC_SEQ |
				      KIDLED_OP_SET_DURATION,
				      duration,
				      &orig);
}

/*
 * Increase the sequence number while keep duration the same, it's used
 * to start a new period immediately.
 */
static inline void kidled_inc_scan_seq(void)
{
	kidled_set_scan_period(KIDLED_OP_INC_SEQ, 0, NULL);
}

extern const int kidled_default_buckets[NUM_KIDLED_BUCKETS];

bool kidled_use_hierarchy(void);
#ifdef CONFIG_MEMCG
void kidled_mem_cgroup_move_stats(struct mem_cgroup *from,
				  struct mem_cgroup *to,
				  struct page *page,
				  unsigned int nr_pages);
#endif /* CONFIG_MEMCG */

#else  /* !CONFIG_KIDLED */

#ifdef CONFIG_MEMCG
static inline void kidled_mem_cgroup_move_stats(struct mem_cgroup *from,
						struct mem_cgroup *to,
						struct page *page,
						unsigned int nr_pages)
{
}
#endif /* CONFIG_MEMCG */

#endif /* CONFIG_KIDLED */

#endif /* _LINUX_MM_KIDLED_H */
