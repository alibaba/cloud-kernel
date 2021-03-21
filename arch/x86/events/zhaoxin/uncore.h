// SPDX-License-Identifier: GPL-2.0-only
#include <linux/slab.h>
#include <linux/pci.h>
#include <asm/apicdef.h>
#include <linux/io-64-nonatomic-lo-hi.h>

#include <linux/perf_event.h>
#include "../perf_event.h"

#define ZHAOXIN_FAM7_CHX001		0x1b
#define ZHAOXIN_FAM7_CHX002		0x3b

#define UNCORE_PMU_NAME_LEN		32
#define UNCORE_PMU_HRTIMER_INTERVAL	(60LL * NSEC_PER_SEC)
#define UNCORE_CHX_IMC_HRTIMER_INTERVAL (5ULL * NSEC_PER_SEC)


#define UNCORE_FIXED_EVENT              0xff
#define UNCORE_PMC_IDX_MAX_GENERIC      4
#define UNCORE_PMC_IDX_MAX_FIXED        1
#define UNCORE_PMC_IDX_FIXED            UNCORE_PMC_IDX_MAX_GENERIC

#define UNCORE_PMC_IDX_MAX              (UNCORE_PMC_IDX_FIXED + 1)

struct zhaoxin_uncore_ops;
struct zhaoxin_uncore_pmu;
struct zhaoxin_uncore_box;
struct uncore_event_desc;

struct zhaoxin_uncore_type {
	const char *name;
	int num_counters;
	int num_boxes;
	int perf_ctr_bits;
	int fixed_ctr_bits;
	unsigned perf_ctr;
	unsigned event_ctl;
	unsigned event_mask;
	unsigned event_mask_ext;
	unsigned fixed_ctr;
	unsigned fixed_ctl;
	unsigned box_ctl;
	unsigned msr_offset;
	unsigned num_shared_regs:8;
	unsigned single_fixed:1;
	unsigned pair_ctr_ctl:1;
	unsigned *msr_offsets;
	struct event_constraint unconstrainted;
	struct event_constraint *constraints;
	struct zhaoxin_uncore_pmu *pmus;
	struct zhaoxin_uncore_ops *ops;
	struct uncore_event_desc *event_descs;
	const struct attribute_group *attr_groups[4];
	struct pmu *pmu; /* for custom pmu ops */
};

#define pmu_group attr_groups[0]
#define format_group attr_groups[1]
#define events_group attr_groups[2]

struct zhaoxin_uncore_ops {
	void (*init_box)(struct zhaoxin_uncore_box *);
	void (*exit_box)(struct zhaoxin_uncore_box *);
	void (*disable_box)(struct zhaoxin_uncore_box *);
	void (*enable_box)(struct zhaoxin_uncore_box *);
	void (*disable_event)(struct zhaoxin_uncore_box *, struct perf_event *);
	void (*enable_event)(struct zhaoxin_uncore_box *, struct perf_event *);
	u64 (*read_counter)(struct zhaoxin_uncore_box *, struct perf_event *);
	int (*hw_config)(struct zhaoxin_uncore_box *, struct perf_event *);
	struct event_constraint *(*get_constraint)(struct zhaoxin_uncore_box *,
						   struct perf_event *);
	void (*put_constraint)(struct zhaoxin_uncore_box *, struct perf_event *);
};

struct zhaoxin_uncore_pmu {
	struct pmu			pmu;
	char				name[UNCORE_PMU_NAME_LEN];
	int				pmu_idx;
	int				func_id;
	bool				registered;
	atomic_t			activeboxes;
	struct zhaoxin_uncore_type	*type;
	struct zhaoxin_uncore_box	**boxes;
};

struct zhaoxin_uncore_extra_reg {
	raw_spinlock_t lock;
	u64 config, config1, config2;
	atomic_t ref;
};

struct zhaoxin_uncore_box {
	int pci_phys_id;
	int package_id;	/*Package ID */
	int n_active;	/* number of active events */
	int n_events;
	int cpu;	/* cpu to collect events */
	unsigned long flags;
	atomic_t refcnt;
	struct perf_event *events[UNCORE_PMC_IDX_MAX];
	struct perf_event *event_list[UNCORE_PMC_IDX_MAX];
	struct event_constraint *event_constraint[UNCORE_PMC_IDX_MAX];
	unsigned long active_mask[BITS_TO_LONGS(UNCORE_PMC_IDX_MAX)];
	u64 tags[UNCORE_PMC_IDX_MAX];
	struct pci_dev *pci_dev;
	struct zhaoxin_uncore_pmu *pmu;
	u64 hrtimer_duration; /* hrtimer timeout for this box */
	struct hrtimer hrtimer;
	struct list_head list;
	struct list_head active_list;
	void __iomem *io_addr;
	struct zhaoxin_uncore_extra_reg shared_regs[0];
};

#define UNCORE_BOX_FLAG_INITIATED	0

struct uncore_event_desc {
	struct kobj_attribute attr;
	const char *config;
};

ssize_t zx_uncore_event_show(struct kobject *kobj,
			struct kobj_attribute *attr, char *buf);

#define ZHAOXIN_UNCORE_EVENT_DESC(_name, _config)			\
{								\
	.attr	= __ATTR(_name, 0444, zx_uncore_event_show, NULL),	\
	.config	= _config,					\
}

#define DEFINE_UNCORE_FORMAT_ATTR(_var, _name, _format)			\
static ssize_t __uncore_##_var##_show(struct kobject *kobj,		\
				struct kobj_attribute *attr,		\
				char *page)				\
{									\
	BUILD_BUG_ON(sizeof(_format) >= PAGE_SIZE);			\
	return sprintf(page, _format "\n");				\
}									\
static struct kobj_attribute format_attr_##_var =			\
	__ATTR(_name, 0444, __uncore_##_var##_show, NULL)

static inline bool uncore_pmc_fixed(int idx)
{
	return idx == UNCORE_PMC_IDX_FIXED;
}

static inline unsigned uncore_msr_box_offset(struct zhaoxin_uncore_box *box)
{
	struct zhaoxin_uncore_pmu *pmu = box->pmu;

	return pmu->type->msr_offsets ?
		pmu->type->msr_offsets[pmu->pmu_idx] :
		pmu->type->msr_offset * pmu->pmu_idx;
}

static inline unsigned uncore_msr_box_ctl(struct zhaoxin_uncore_box *box)
{
	if (!box->pmu->type->box_ctl)
		return 0;
	return box->pmu->type->box_ctl + uncore_msr_box_offset(box);
}

static inline unsigned uncore_msr_fixed_ctl(struct zhaoxin_uncore_box *box)
{
	if (!box->pmu->type->fixed_ctl)
		return 0;
	return box->pmu->type->fixed_ctl + uncore_msr_box_offset(box);
}

static inline unsigned uncore_msr_fixed_ctr(struct zhaoxin_uncore_box *box)
{
	return box->pmu->type->fixed_ctr + uncore_msr_box_offset(box);
}

static inline
unsigned uncore_msr_event_ctl(struct zhaoxin_uncore_box *box, int idx)
{
	return box->pmu->type->event_ctl +
		(box->pmu->type->pair_ctr_ctl ? 2 * idx : idx) +
		uncore_msr_box_offset(box);
}

static inline
unsigned uncore_msr_perf_ctr(struct zhaoxin_uncore_box *box, int idx)
{
	return box->pmu->type->perf_ctr +
		(box->pmu->type->pair_ctr_ctl ? 2 * idx : idx) +
		uncore_msr_box_offset(box);
}

static inline
unsigned uncore_fixed_ctl(struct zhaoxin_uncore_box *box)
{
	return uncore_msr_fixed_ctl(box);
}

static inline
unsigned uncore_fixed_ctr(struct zhaoxin_uncore_box *box)
{
	return uncore_msr_fixed_ctr(box);
}

static inline
unsigned uncore_event_ctl(struct zhaoxin_uncore_box *box, int idx)
{
	return uncore_msr_event_ctl(box, idx);
}

static inline
unsigned uncore_perf_ctr(struct zhaoxin_uncore_box *box, int idx)
{
	return uncore_msr_perf_ctr(box, idx);
}

static inline int uncore_perf_ctr_bits(struct zhaoxin_uncore_box *box)
{
	return box->pmu->type->perf_ctr_bits;
}

static inline int uncore_fixed_ctr_bits(struct zhaoxin_uncore_box *box)
{
	return box->pmu->type->fixed_ctr_bits;
}

static inline int uncore_num_counters(struct zhaoxin_uncore_box *box)
{
	return box->pmu->type->num_counters;
}

static inline void uncore_disable_box(struct zhaoxin_uncore_box *box)
{
	if (box->pmu->type->ops->disable_box)
		box->pmu->type->ops->disable_box(box);
}

static inline void uncore_enable_box(struct zhaoxin_uncore_box *box)
{
	if (box->pmu->type->ops->enable_box)
		box->pmu->type->ops->enable_box(box);
}

static inline void uncore_disable_event(struct zhaoxin_uncore_box *box,
				struct perf_event *event)
{
	box->pmu->type->ops->disable_event(box, event);
}

static inline void uncore_enable_event(struct zhaoxin_uncore_box *box,
				struct perf_event *event)
{
	box->pmu->type->ops->enable_event(box, event);
}

static inline u64 uncore_read_counter(struct zhaoxin_uncore_box *box,
				struct perf_event *event)
{
	return box->pmu->type->ops->read_counter(box, event);
}

static inline void uncore_box_init(struct zhaoxin_uncore_box *box)
{
	if (!test_and_set_bit(UNCORE_BOX_FLAG_INITIATED, &box->flags)) {
		if (box->pmu->type->ops->init_box)
			box->pmu->type->ops->init_box(box);
	}
}

static inline void uncore_box_exit(struct zhaoxin_uncore_box *box)
{
	if (test_and_clear_bit(UNCORE_BOX_FLAG_INITIATED, &box->flags)) {
		if (box->pmu->type->ops->exit_box)
			box->pmu->type->ops->exit_box(box);
	}
}

static inline bool uncore_box_is_fake(struct zhaoxin_uncore_box *box)
{
	return (box->package_id < 0);
}

static inline struct zhaoxin_uncore_pmu *uncore_event_to_pmu(struct perf_event *event)
{
	return container_of(event->pmu, struct zhaoxin_uncore_pmu, pmu);
}

static inline struct zhaoxin_uncore_box *uncore_event_to_box(struct perf_event *event)
{
	return event->pmu_private;
}


static struct zhaoxin_uncore_box *uncore_pmu_to_box(struct zhaoxin_uncore_pmu *pmu, int cpu);
static u64 uncore_msr_read_counter(struct zhaoxin_uncore_box *box, struct perf_event *event);

static void uncore_pmu_start_hrtimer(struct zhaoxin_uncore_box *box);
static void uncore_pmu_cancel_hrtimer(struct zhaoxin_uncore_box *box);
static void uncore_pmu_event_start(struct perf_event *event, int flags);
static void uncore_pmu_event_stop(struct perf_event *event, int flags);
static int uncore_pmu_event_add(struct perf_event *event, int flags);
static void uncore_pmu_event_del(struct perf_event *event, int flags);
static void uncore_pmu_event_read(struct perf_event *event);
static void uncore_perf_event_update(struct zhaoxin_uncore_box *box, struct perf_event *event);
struct event_constraint *
uncore_get_constraint(struct zhaoxin_uncore_box *box, struct perf_event *event);
void uncore_put_constraint(struct zhaoxin_uncore_box *box, struct perf_event *event);
u64 uncore_shared_reg_config(struct zhaoxin_uncore_box *box, int idx);

void chx_uncore_cpu_init(void);
