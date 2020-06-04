// SPDX-License-Identifier: GPL-2.0
/*
 * Arm Statistical Profiling Extensions (SPE) support
 * Copyright (c) 2017-2018, Arm Ltd.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/log2.h>
#include <time.h>

#include "../../util/cpumap.h"
#include "../../util/evsel.h"
#include "../../util/evlist.h"
#include "../../util/session.h"
#include "../../util/util.h"
#include "../../util/pmu.h"
#include "../../util/debug.h"
#include "../../util/auxtrace.h"
#include "../../util/tsc.h"
#include "../../util/arm-spe.h"

#define KiB(x) ((x) * 1024)
#define MiB(x) ((x) * 1024 * 1024)

struct arm_spe_recording {
	struct auxtrace_record		itr;
	struct perf_pmu			*arm_spe_pmu;
	struct perf_evlist		*evlist;
	int				have_sched_switch;
};

static size_t
arm_spe_info_priv_size(struct auxtrace_record *itr __maybe_unused,
		       struct perf_evlist *evlist __maybe_unused)
{
	return ARM_SPE_AUXTRACE_PRIV_SIZE;
}

static int arm_spe_parse_terms_with_default(struct list_head *formats,
					     const char *str,
					     u64 *config)
{
	struct list_head *terms;
	struct perf_event_attr attr = { .size = 0, };
	int err;

	terms = malloc(sizeof(struct list_head));
	if (!terms)
		return -ENOMEM;

	INIT_LIST_HEAD(terms);

	err = parse_events_terms(terms, str);
	if (err)
		goto out_free;

	attr.config = *config;
	err = perf_pmu__config_terms(formats, &attr, terms, true, NULL);
	if (err)
		goto out_free;

	*config = attr.config;
out_free:
	parse_events_terms__delete(terms);
	return err;
}

static int arm_spe_parse_terms(struct list_head *formats, const char *str,
				u64 *config)
{
	*config = 0;
	return arm_spe_parse_terms_with_default(formats, str, config);
}

static int arm_spe_info_fill(struct auxtrace_record *itr,
			     struct perf_session *session,
			     struct auxtrace_info_event *auxtrace_info,
			     size_t priv_size)
{
	struct arm_spe_recording *sper =
			container_of(itr, struct arm_spe_recording, itr);
	struct perf_pmu *arm_spe_pmu = sper->arm_spe_pmu;
	struct perf_event_mmap_page *pc;
	struct perf_tsc_conversion tc = { .time_mult = 0, };
	bool cap_user_time_zero = false;
	u64 ts_enable;
	int err;

	if (priv_size != ARM_SPE_AUXTRACE_PRIV_SIZE)
		return -EINVAL;

	arm_spe_parse_terms(&arm_spe_pmu->format, "ts_enable", &ts_enable);

	if (!session->evlist->nr_mmaps)
		return -EINVAL;

	pc = session->evlist->mmap[0].base;
	if (pc) {
		err = perf_read_tsc_conversion(pc, &tc);
		if (err) {
			if (err != -EOPNOTSUPP)
				return err;
		} else {
			cap_user_time_zero = tc.time_mult != 0;
		}
		if (!cap_user_time_zero)
			ui__warning("ARM SPE: TSC not available\n");
	}

	auxtrace_info->type = PERF_AUXTRACE_ARM_SPE;
	auxtrace_info->priv[ARM_SPE_PMU_TYPE] = arm_spe_pmu->type;
	auxtrace_info->priv[ARM_SPE_TIME_SHIFT] = tc.time_shift;
	auxtrace_info->priv[ARM_SPE_TIME_MULT] = tc.time_mult;
	auxtrace_info->priv[ARM_SPE_TIME_ZERO] = tc.time_zero;
	auxtrace_info->priv[ARM_SPE_CAP_USER_TIME_ZERO] = cap_user_time_zero;
	auxtrace_info->priv[ARM_SPE_TS_ENABLE] = ts_enable;
	auxtrace_info->priv[ARM_SPE_HAVE_SCHED_SWITCH] =
						sper->have_sched_switch;

	return 0;
}

static int arm_spe_track_switches(struct perf_evlist *evlist)
{
	const char *sched_switch = "sched:sched_switch";
	struct perf_evsel *evsel;
	int err;

	if (!perf_evlist__can_select_event(evlist, sched_switch))
		return -EPERM;

	err = parse_events(evlist, sched_switch, NULL);
	if (err) {
		pr_debug2("%s: failed to parse %s, error %d\n",
			  __func__, sched_switch, err);
		return err;
	}

	evsel = perf_evlist__last(evlist);

	perf_evsel__set_sample_bit(evsel, CPU);
	perf_evsel__set_sample_bit(evsel, TIME);

	evsel->system_wide = true;
	evsel->no_aux_samples = true;
	evsel->immediate = true;

	return 0;
}

static int arm_spe_recording_options(struct auxtrace_record *itr,
				     struct perf_evlist *evlist,
				     struct record_opts *opts)
{
	struct arm_spe_recording *sper =
			container_of(itr, struct arm_spe_recording, itr);
	struct perf_pmu *arm_spe_pmu = sper->arm_spe_pmu;
	bool need_immediate = false;
	struct perf_evsel *evsel, *arm_spe_evsel = NULL;
	const struct cpu_map *cpus = evlist->cpus;
	bool privileged = geteuid() == 0 || perf_event_paranoid() < 0;
	struct perf_evsel *tracking_evsel;
	int err;

	sper->evlist = evlist;

	evlist__for_each_entry(evlist, evsel) {
		if (evsel->attr.type == arm_spe_pmu->type) {
			if (arm_spe_evsel) {
				pr_err("There may be only one " ARM_SPE_PMU_NAME "x event\n");
				return -EINVAL;
			}
			evsel->attr.freq = 0;
			evsel->attr.sample_period = 1;
			arm_spe_evsel = evsel;
			opts->full_auxtrace = true;
		}
	}

	/*
	 * Per-cpu recording needs sched_switch events to distinguish different
	 * threads.
	 */
	if (!cpu_map__empty(cpus)) {
		if (perf_can_record_switch_events()) {
			bool cpu_wide = !target__none(&opts->target) &&
					!target__has_task(&opts->target);

			if (!cpu_wide && perf_can_record_cpu_wide()) {
				struct perf_evsel *switch_evsel;

				err = parse_events(evlist, "dummy:u", NULL);
				if (err)
					return err;

				switch_evsel = perf_evlist__last(evlist);

				switch_evsel->attr.freq = 0;
				switch_evsel->attr.sample_period = 1;
				switch_evsel->attr.context_switch = 1;

				switch_evsel->system_wide = true;
				switch_evsel->no_aux_samples = true;
				switch_evsel->immediate = true;

				perf_evsel__set_sample_bit(switch_evsel, TID);
				perf_evsel__set_sample_bit(switch_evsel, TIME);
				perf_evsel__set_sample_bit(switch_evsel, CPU);
				perf_evsel__reset_sample_bit(switch_evsel,
								BRANCH_STACK);

				opts->record_switch_events = false;
				sper->have_sched_switch = 3;
			} else {
				opts->record_switch_events = true;
				need_immediate = true;
				if (cpu_wide)
					sper->have_sched_switch = 3;
				else
					sper->have_sched_switch = 2;
			}
		} else {
			err = arm_spe_track_switches(evlist);
			if (err == -EPERM)
				pr_debug2("Unable to select "
						"sched:sched_switch\n");
			else {
				if (err)
					return err;
				sper->have_sched_switch = 1;
			}
		}
	}

	if (!opts->full_auxtrace)
		return 0;

	/* We are in full trace mode but '-m,xyz' wasn't specified */
	if (opts->full_auxtrace && !opts->auxtrace_mmap_pages) {
		if (privileged) {
			opts->auxtrace_mmap_pages = MiB(4) / page_size;
		} else {
			opts->auxtrace_mmap_pages = KiB(128) / page_size;
			if (opts->mmap_pages == UINT_MAX)
				opts->mmap_pages = KiB(256) / page_size;
		}
	}

	/* Validate auxtrace_mmap_pages */
	if (opts->auxtrace_mmap_pages) {
		size_t sz = opts->auxtrace_mmap_pages * (size_t)page_size;
		size_t min_sz = KiB(8);

		if (sz < min_sz || !is_power_of_2(sz)) {
			pr_err("Invalid mmap size for ARM SPE: must be at least %zuKiB and a power of 2\n",
			       min_sz / 1024);
			return -EINVAL;
		}
	}

	/*
	 * To obtain the auxtrace buffer file descriptor, the auxtrace event
	 * must come first.
	 */
	perf_evlist__to_front(evlist, arm_spe_evsel);

	perf_evsel__set_sample_bit(arm_spe_evsel, CPU);
	perf_evsel__set_sample_bit(arm_spe_evsel, TIME);
	perf_evsel__set_sample_bit(arm_spe_evsel, TID);

	/* Add dummy event to keep tracking */
	err = parse_events(evlist, "dummy:u", NULL);
	if (err)
		return err;

	tracking_evsel = perf_evlist__last(evlist);
	perf_evlist__set_tracking_event(evlist, tracking_evsel);

	tracking_evsel->attr.freq = 0;
	tracking_evsel->attr.sample_period = 1;
	if (need_immediate)
		tracking_evsel->immediate = true;
	perf_evsel__set_sample_bit(tracking_evsel, TIME);
	perf_evsel__set_sample_bit(tracking_evsel, CPU);
	perf_evsel__reset_sample_bit(tracking_evsel, BRANCH_STACK);

	/*
	 * Warn the user when we do not have enough information to decode i.e.
	 * per-cpu with no sched_switch (except workload-only).
	 */
	if (!sper->have_sched_switch && !cpu_map__empty(cpus) &&
	    !target__none(&opts->target))
		ui__warning("ARM SPE decoding will not be"
				"possible except for kernel tracing!\n");

	return 0;
}

static u64 arm_spe_reference(struct auxtrace_record *itr __maybe_unused)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);

	return ts.tv_sec ^ ts.tv_nsec;
}

static void arm_spe_recording_free(struct auxtrace_record *itr)
{
	struct arm_spe_recording *sper =
			container_of(itr, struct arm_spe_recording, itr);

	free(sper);
}

static int arm_spe_read_finish(struct auxtrace_record *itr, int idx)
{
	struct arm_spe_recording *sper =
			container_of(itr, struct arm_spe_recording, itr);
	struct perf_evsel *evsel;

	evlist__for_each_entry(sper->evlist, evsel) {
		if (evsel->attr.type == sper->arm_spe_pmu->type) {
			if (evsel->terminated)
				return 0;
			else
				return perf_evlist__enable_event_idx(
						sper->evlist, evsel, idx);
		}
	}
	return -EINVAL;
}

struct auxtrace_record *arm_spe_recording_init(int *err,
					       struct perf_pmu *arm_spe_pmu)
{
	struct arm_spe_recording *sper;

	if (!arm_spe_pmu) {
		*err = -ENODEV;
		return NULL;
	}

	sper = zalloc(sizeof(struct arm_spe_recording));
	if (!sper) {
		*err = -ENOMEM;
		return NULL;
	}

	sper->arm_spe_pmu = arm_spe_pmu;
	sper->itr.recording_options = arm_spe_recording_options;
	sper->itr.info_priv_size = arm_spe_info_priv_size;
	sper->itr.info_fill = arm_spe_info_fill;
	sper->itr.free = arm_spe_recording_free;
	sper->itr.reference = arm_spe_reference;
	sper->itr.read_finish = arm_spe_read_finish;
	sper->itr.alignment = 0;

	*err = 0;
	return &sper->itr;
}

struct perf_event_attr
*arm_spe_pmu_default_config(struct perf_pmu *arm_spe_pmu)
{
	struct perf_event_attr *attr;

	attr = zalloc(sizeof(struct perf_event_attr));
	if (!attr) {
		pr_err("arm_spe default config cannot allocate a perf_event_attr\n");
		return NULL;
	}

	/*
	 * If kernel driver doesn't advertise a minimum,
	 * use max allowable by PMSIDR_EL1.INTERVAL
	 */
	if (perf_pmu__scan_file(arm_spe_pmu, "caps/min_interval", "%llu",
				  &attr->sample_period) != 1) {
		pr_debug("arm_spe driver doesn't advertise a min. interval. Using 4096\n");
		attr->sample_period = 4096;
	}

	arm_spe_pmu->selectable = true;
	arm_spe_pmu->is_uncore = false;

	return attr;
}
