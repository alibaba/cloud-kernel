// SPDX-License-Identifier: GPL-2.0
/*
 * Arm Statistical Profiling Extensions (SPE) support
 * Copyright (c) 2017-2018, Arm Ltd.
 */

#include <endian.h>
#include <errno.h>
#include <byteswap.h>
#include <inttypes.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/log2.h>
#include <pthread.h>

#include "cpumap.h"
#include "color.h"
#include "evsel.h"
#include "evlist.h"
#include "machine.h"
#include "session.h"
#include "util.h"
#include "thread.h"
#include "thread-stack.h"
#include "symbol.h"
#include "debug.h"
#include "auxtrace.h"
#include "tsc.h"
#include "arm-spe.h"
#include "arm-spe-decoder/arm-spe-decoder.h"
#include "arm-spe-decoder/arm-spe-pkt-decoder.h"

#define MAX_TIMESTAMP			(~0ULL)
#define IN_CACHELINE			(0x7FULL)

struct arm_spe {
	struct auxtrace			auxtrace;
	struct auxtrace_queues		queues;
	struct auxtrace_heap		heap;
	struct arm_spe_synth_opts	synth_opts;
	u32				auxtrace_type;
	struct perf_session		*session;
	struct machine			*machine;
	u32				pmu_type;

	u8				timeless_decoding;
	u8				data_queued;

	u8				sample_llc_miss;
	u8				sample_tlb_miss;
	u8				sample_branch_miss;
	u8				sample_remote_access;
	u8				sample_c2c_mode;
	u64				llc_miss_id;
	u64				tlb_miss_id;
	u64				branch_miss_id;
	u64				remote_access_id;
	u64				kernel_start;

	unsigned long			num_events;
	int have_sched_switch;
	struct perf_evsel *switch_evsel;
	u64				ts_bit;
	struct perf_tsc_conversion tc;
	bool cap_user_time_zero;
};

struct arm_spe_queue {
	struct arm_spe			*spe;
	unsigned int			queue_nr;
	struct auxtrace_buffer		*buffer;
	struct auxtrace_buffer		*old_buffer;
	union perf_event		*event_buf;
	bool				on_heap;
	bool				done;
	pid_t				pid;
	pid_t				tid;
	int				cpu;
	void				*decoder;
	const struct arm_spe_state	*state;
	u64				time;
	u64				timestamp;
	struct thread			*thread;
	bool				have_sample;
};

struct spe_c2c_sample {
	struct rb_node			rb_node;
	struct spe_c2c_sample		*same_cache;
	struct spe_c2c_sample		*false_share_next;
	pthread_mutex_t			mut;
	bool				accessed;
	struct arm_spe_state		state;
	pid_t				pid;
	pid_t				tid;
	pid_t				*tid_arry;

};

struct spe_c2c_sample_queues {
	struct rb_root			ld_list;
	struct rb_root			st_list;

	struct arm_spe_queue		*speq;
	bool				valid;
	int				cpu;
	uint64_t			ld_num;
	uint64_t			st_num;
};

struct spe_c2c_compare_lists {
	struct rb_root			*listA;
	struct rb_root			*listB;
	struct spe_c2c_sample_queues	*queues;
	struct spe_c2c_sample_queues	*oppoqs;	/* the oppo queues */
	struct spe_c2c_sample		*false_share;
	uint64_t			num;
};

#define SPE_C2C_SAMPLE_Q_MAX		128

int spe_c2c_q_num;
static struct ui_progress prog;

struct spe_c2c_sample_queues spe_c2c_sample_list[SPE_C2C_SAMPLE_Q_MAX];

static void spe_c2c_sample_init(void)
{
	int i;

	for (i = 0; i < SPE_C2C_SAMPLE_Q_MAX; i++) {
		spe_c2c_sample_list[i].ld_list = RB_ROOT;
		spe_c2c_sample_list[i].st_list = RB_ROOT;
		spe_c2c_sample_list[i].valid = false;
		spe_c2c_sample_list[i].cpu = -1;
		spe_c2c_sample_list[i].speq = NULL;
		spe_c2c_sample_list[i].ld_num = 0;
		spe_c2c_sample_list[i].st_num = 0;
	}

	spe_c2c_q_num = 0;
}

static void arm_spe_dump(struct arm_spe *spe __maybe_unused,
			 unsigned char *buf, size_t len)
{
	struct arm_spe_pkt packet;
	size_t pos = 0;
	int ret, pkt_len, i;
	char desc[ARM_SPE_PKT_DESC_MAX];
	const char *color = PERF_COLOR_BLUE;

	color_fprintf(stdout, color,
		      ". ... ARM SPE data: size %zu bytes\n",
		      len);

	while (len) {
		ret = arm_spe_get_packet(buf, len, &packet);
		if (ret > 0)
			pkt_len = ret;
		else
			pkt_len = 1;
		printf(".");
		color_fprintf(stdout, color, "  %08x: ", pos);
		for (i = 0; i < pkt_len; i++)
			color_fprintf(stdout, color, " %02x", buf[i]);
		for (; i < 16; i++)
			color_fprintf(stdout, color, "   ");
		if (ret > 0) {
			ret = arm_spe_pkt_desc(&packet, desc,
					       ARM_SPE_PKT_DESC_MAX);
			if (ret > 0)
				color_fprintf(stdout, color, " %s\n", desc);
		} else {
			color_fprintf(stdout, color, " Bad packet!\n");
		}
		pos += pkt_len;
		buf += pkt_len;
		len -= pkt_len;
	}
}

static void arm_spe_dump_event(struct arm_spe *spe, unsigned char *buf,
			       size_t len)
{
	printf(".\n");
	arm_spe_dump(spe, buf, len);
}

static int arm_spe_get_trace(struct arm_spe_buffer *b, void *data)
{
	struct arm_spe_queue *speq = data;
	struct auxtrace_buffer *buffer = speq->buffer;
	struct auxtrace_buffer *old_buffer = speq->old_buffer;
	struct auxtrace_queue *queue;

	queue = &speq->spe->queues.queue_array[speq->queue_nr];

	buffer = auxtrace_buffer__next(queue, buffer);
	/* If no more data, drop the previous auxtrace_buffer and return */
	if (!buffer) {
		if (old_buffer)
			auxtrace_buffer__drop_data(old_buffer);
		b->len = 0;
		return 0;
	}

	speq->buffer = buffer;

	/* If the aux_buffer doesn't have data associated, try to load it */
	if (!buffer->data) {
		/* get the file desc associated with the perf data file */
		int fd = perf_data__fd(speq->spe->session->data);

		buffer->data = auxtrace_buffer__get_data(buffer, fd);
		if (!buffer->data)
			return -ENOMEM;
	}

	if (buffer->use_data) {
		b->len = buffer->use_size;
		b->buf = buffer->use_data;
	} else {
		b->len = buffer->size;
		b->buf = buffer->data;
	}

	b->ref_timestamp = buffer->reference;

	if (b->len) {
		if (old_buffer)
			auxtrace_buffer__drop_data(old_buffer);
		speq->old_buffer = buffer;
	} else {
		auxtrace_buffer__drop_data(buffer);
		return arm_spe_get_trace(b, data);
	}

	return 0;
}

static struct arm_spe_queue *arm_spe__alloc_queue(struct arm_spe *spe,
		unsigned int queue_nr)
{
	struct arm_spe_params params = { .get_trace = 0, };
	struct arm_spe_queue *speq;

	speq = zalloc(sizeof(*speq));
	if (!speq)
		return NULL;

	speq->event_buf = malloc(PERF_SAMPLE_MAX_SIZE);
	if (!speq->event_buf)
		goto out_free;

	speq->spe = spe;
	speq->queue_nr = queue_nr;
	speq->pid = -1;
	speq->tid = -1;
	speq->cpu = -1;

	/* params set */
	params.get_trace = arm_spe_get_trace;
	params.data = speq;

	/* create new decoder */
	speq->decoder = arm_spe_decoder_new(&params);
	if (!speq->decoder)
		goto out_free;

	return speq;

out_free:
	zfree(&speq->event_buf);
	free(speq);

	return NULL;
}

static inline u8 arm_spe_cpumode(struct arm_spe *spe, uint64_t ip)
{
	return ip >= spe->kernel_start ?
		PERF_RECORD_MISC_KERNEL :
		PERF_RECORD_MISC_USER;
}

static void arm_spe_prep_sample(struct arm_spe *spe,
				 struct arm_spe_queue *speq,
				 union perf_event *event,
				 struct perf_sample *sample)
{
	if (!spe->timeless_decoding)
		sample->time = tsc_to_perf_time(speq->timestamp, &spe->tc);

	sample->ip = speq->state->from_ip;
	sample->cpumode = arm_spe_cpumode(spe, sample->ip);
	sample->pid = speq->pid;
	sample->tid = speq->tid;
	sample->addr = speq->state->addr;
	sample->phys_addr = speq->state->phys_addr;
	sample->period = 1;
	sample->cpu = speq->cpu;

	event->sample.header.type = PERF_RECORD_SAMPLE;
	event->sample.header.misc = sample->cpumode;
	event->sample.header.size = sizeof(struct perf_event_header);
}

static inline int arm_spe_deliver_synth_event(struct arm_spe *spe,
				struct arm_spe_queue *speq __maybe_unused,
				union perf_event *event,
				struct perf_sample *sample)
{
	int ret;

	ret = perf_session__deliver_synth_event(spe->session, event, sample);
	if (ret)
		pr_err("ARM SPE: failed to deliver event, error %d\n", ret);

	return ret;
}

static int arm_spe_synth_spe_events_sample(struct arm_spe_queue *speq, u64 spe_events_id __maybe_unused)
{
	struct arm_spe *spe = speq->spe;
	union perf_event *event = speq->event_buf;
	struct perf_sample sample = { .ip = 0, };

	arm_spe_prep_sample(spe, speq, event, &sample);

	sample.id = spe_events_id;
	sample.stream_id = spe_events_id;

	return arm_spe_deliver_synth_event(spe, speq, event, &sample);
}

static int arm_spe_sample(struct arm_spe_queue *speq)
{
	const struct arm_spe_state *state = speq->state;
	struct arm_spe *spe = speq->spe;
	int err;

	if (!speq->have_sample)
		return 0;

	speq->have_sample = false;

	if (spe->sample_llc_miss && (state->type & ARM_SPE_LLC_MISS)) {
		err = arm_spe_synth_spe_events_sample(speq, spe->llc_miss_id);
		if (err)
			return err;
	}

	if (spe->sample_tlb_miss && (state->type & ARM_SPE_TLB_MISS)) {
		err = arm_spe_synth_spe_events_sample(speq, spe->tlb_miss_id);
		if (err)
			return err;
	}

	if (spe->sample_branch_miss && (state->type & ARM_SPE_BRANCH_MISS)) {
		err = arm_spe_synth_spe_events_sample(speq, spe->branch_miss_id);
		if (err)
			return err;
	}

	if (spe->sample_remote_access && (state->type & ARM_SPE_REMOTE_ACCESS)) {
		err = arm_spe_synth_spe_events_sample(speq, spe->remote_access_id);
		if (err)
			return err;
	}

	return 0;
}

static int spe_sample_insert(struct rb_root *root, struct spe_c2c_sample *data)
{
	struct rb_node **tmp = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*tmp) {
		struct spe_c2c_sample *this = container_of(*tmp,
				struct spe_c2c_sample, rb_node);
		uint64_t data_high = data->state.phys_addr & (uint64_t)~IN_CACHELINE;
		uint64_t data_low  = data->state.phys_addr & (uint64_t)IN_CACHELINE;
		uint64_t this_high = this->state.phys_addr & (uint64_t)~IN_CACHELINE;

		parent = *tmp;
		if (data_high < this_high)
			tmp = &((*tmp)->rb_left);
		else if (data_high > this_high)
			tmp = &((*tmp)->rb_right);
		else {
			if (!this->tid_arry) {
				this->tid_arry = zalloc(2 * (1 + IN_CACHELINE) * sizeof(pid_t));
				this->tid_arry[data_low] = data->tid;
			} else if (this->tid_arry[data_low] != data->tid)
				this->tid_arry[(1 + IN_CACHELINE) + data_low] = data->tid;

			data->same_cache = this->same_cache;
			this->same_cache = data;

			return 0;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->rb_node, parent, tmp);
	rb_insert_color(&data->rb_node, root);

	return 0;
}

static void arm_spe_c2c_queue_store(struct arm_spe_queue *speq,
		       struct spe_c2c_sample_queues *spe_c2cq)
{
	const struct arm_spe_state *state = speq->state;
	struct spe_c2c_sample *sample;
	struct rb_root *root;
	int ret = 0;

	if (!speq->have_sample)
		return;

	speq->have_sample = false;

	if (state->ts && (state->is_ld || state->is_st)) {
		sample = zalloc(sizeof(struct spe_c2c_sample));
		if (!sample) {
			pr_err("spe_c2c: Allocate sample error!\n");
			return;
		}

		root = state->is_ld ? &(spe_c2cq->ld_list) : &(spe_c2cq->st_list);

		memcpy(&(sample->state), state, sizeof(struct arm_spe_state));
		sample->pid = speq->pid;
		sample->tid = speq->tid;

		ret = spe_sample_insert(root, sample);
		if (ret) {
			pr_err("spe_c2c: The %lx(%lx) already exists.",
					state->addr, state->ts);
			free(sample);
			return;
		}

		if (state->is_ld)
			spe_c2cq->ld_num++;
		else
			spe_c2cq->st_num++;
	}
}

static int arm_spe_run_decoder(struct arm_spe_queue *speq, u64 *timestamp,
			       struct spe_c2c_sample_queues *spe_c2cq __maybe_unused)
{
	const struct arm_spe_state *state = speq->state;
	struct arm_spe *spe = speq->spe;
	int err;

	if (!spe->kernel_start)
		spe->kernel_start = machine__kernel_start(spe->machine);

	pr_debug4("queue %u decoding cpu %d pid %d tid %d\n",
		     speq->queue_nr, speq->cpu, speq->pid, speq->tid);
	while (1) {
		if (spe->sample_c2c_mode) {
			if (spe_c2cq)
				arm_spe_c2c_queue_store(speq, spe_c2cq);
		} else {
			err = arm_spe_sample(speq);
			if (err)
				return err;
		}

		state = arm_spe_decode(speq->decoder);
		if (state->err) {
			if (state->err == -ENODATA) {
				pr_debug("No data or all data has been processed.\n");
				return 1;
			}
			continue;
		}

		speq->state = state;
		speq->have_sample = true;

		if (state->timestamp > speq->timestamp) {
			speq->timestamp = state->timestamp;
		}

		if (!spe->timeless_decoding && speq->timestamp >= *timestamp) {
			*timestamp = speq->timestamp;
			return 0;
		}
	}

	return 0;
}

static int arm_spe__setup_queue(struct arm_spe *spe,
			       struct auxtrace_queue *queue,
			       unsigned int queue_nr)
{
	struct arm_spe_queue *speq = queue->priv;

	if (list_empty(&queue->head))
		return 0;

	if (!speq) {
		speq = arm_spe__alloc_queue(spe, queue_nr);
		if (!speq)
			return -ENOMEM;

		queue->priv = speq;

		if (queue->cpu != -1)
			speq->cpu = queue->cpu;
		speq->tid = queue->tid;
	}

	if (!speq->on_heap) {
		const struct arm_spe_state *state;
		int ret;

		if (spe->timeless_decoding)
			return 0;

		pr_debug4("queue %u getting timestamp\n", queue_nr);
		pr_debug4("queue %u decoding cpu %d pid %d tid %d\n",
			     queue_nr, speq->cpu, speq->pid, speq->tid);
		while (1) {
			state = arm_spe_decode(speq->decoder);
			if (state->err) {
				if (state->err == -ENODATA) {
					pr_debug("queue %u has no timestamp\n",
							queue_nr);
					return 0;
				}
				continue;
			}
			if (state->timestamp)
				break;
		}

		speq->timestamp = state->timestamp;
		pr_debug4("queue %u timestamp 0x%" PRIx64 "\n",
			     queue_nr, speq->timestamp);
		speq->state = state;
		speq->have_sample = true;
		ret = auxtrace_heap__add(&spe->heap, queue_nr, speq->timestamp);
		if (ret)
			return ret;
		speq->on_heap = true;
	}

	return 0;
}

static int arm_spe__setup_queues(struct arm_spe *spe)
{
	unsigned int i;
	int ret;

	for (i = 0; i < spe->queues.nr_queues; i++) {
		ret = arm_spe__setup_queue(spe, &spe->queues.queue_array[i], i);
		if (ret)
			return ret;
	}

	return 0;
}

static int arm_spe__update_queues(struct arm_spe *spe)
{
	if (spe->queues.new_data) {
		spe->queues.new_data = false;
		return arm_spe__setup_queues(spe);
	}

	return 0;
}

static bool arm_spe_get_config(struct arm_spe *spe,
				struct perf_event_attr *attr, u64 *config)
{
	if (attr->type == spe->pmu_type) {
		if (config)
			*config = attr->config;
		return true;
	}

	return false;
}

static bool arm_spe_is_timeless_decoding(struct arm_spe *spe)
{
	struct perf_evsel *evsel;
	bool timeless_decoding = true;
	u64 config;

	if (!spe->ts_bit || !spe->cap_user_time_zero)
		return true;

	evlist__for_each_entry(spe->session->evlist, evsel) {
		if (!(evsel->attr.sample_type & PERF_SAMPLE_TIME))
			return true;
		if (arm_spe_get_config(spe, &evsel->attr, &config)) {
			if (config & spe->ts_bit)
				timeless_decoding = false;
			else
				return true;
		}
	}

	return timeless_decoding;
}

static void arm_spe_set_pid_tid_cpu(struct arm_spe *spe,
				    struct auxtrace_queue *queue)
{
	struct arm_spe_queue *speq = queue->priv;

	if (queue->tid == -1 || spe->have_sched_switch) {
		speq->tid = machine__get_current_tid(spe->machine, speq->cpu);
		thread__zput(speq->thread);
	}

	if ((!speq->thread) && (speq->tid != -1)) {
		speq->thread = machine__find_thread(spe->machine, -1,
						    speq->tid);
	}

	if (speq->thread) {
		speq->pid = speq->thread->pid_;
		if (queue->cpu == -1)
			speq->cpu = speq->thread->cpu;
	}
}

static struct spe_c2c_sample_queues*
arm_spe_get_c2c_queue(struct arm_spe_queue *speq)
{
	int i;

	for (i = 0; i < SPE_C2C_SAMPLE_Q_MAX; i++) {
		if (!spe_c2c_sample_list[i].valid) {
			spe_c2c_sample_list[i].valid = true;
			spe_c2c_sample_list[i].cpu = speq->cpu;
			spe_c2c_sample_list[i].speq = speq;
			spe_c2c_q_num++;
			return &spe_c2c_sample_list[i];
		}

		if (spe_c2c_sample_list[i].cpu == speq->cpu)
			return &spe_c2c_sample_list[i];
	}

	pr_warning("spe_c2c: Now only support sample for %u cpus!\n",
			SPE_C2C_SAMPLE_Q_MAX);

	return NULL;
}

static int arm_spe_process_queues(struct arm_spe *spe, u64 timestamp)
{
	struct spe_c2c_sample_queues *spe_c2cq;
	unsigned int queue_nr;
	u64 ts;
	int ret;

	while (1) {
		struct auxtrace_queue *queue;
		struct arm_spe_queue *speq;

		if (!spe->heap.heap_cnt)
			return 0;

		if (spe->heap.heap_array[0].ordinal >= timestamp)
			return 0;

		queue_nr = spe->heap.heap_array[0].queue_nr;
		queue = &spe->queues.queue_array[queue_nr];
		speq = queue->priv;

		pr_debug4("queue %u processing 0x%" PRIx64 " to 0x%" PRIx64 "\n",
			     queue_nr, spe->heap.heap_array[0].ordinal,
			     timestamp);

		auxtrace_heap__pop(&spe->heap);

		if (spe->heap.heap_cnt) {
			ts = spe->heap.heap_array[0].ordinal + 1;
			if (ts > timestamp)
				ts = timestamp;
		} else {
			ts = timestamp;
		}

		arm_spe_set_pid_tid_cpu(spe, queue);

		spe_c2cq = arm_spe_get_c2c_queue(speq);

		ret = arm_spe_run_decoder(speq, &ts, spe_c2cq);
		if (ret < 0) {
			auxtrace_heap__add(&spe->heap, queue_nr, ts);
			return ret;
		}

		if (!ret) {
			ret = auxtrace_heap__add(&spe->heap, queue_nr, ts);
			if (ret < 0)
				return ret;
		} else {
			speq->on_heap = false;
		}
	}

	return 0;
}

static void arm_spe_c2c_sample(struct spe_c2c_sample_queues *c2c_queues,
		struct spe_c2c_sample *c2c_sample)
{
	struct arm_spe_queue *speq = c2c_queues->speq;
	union perf_event *event = speq->event_buf;
	struct perf_sample sample = { .ip = 0, };
	union perf_mem_data_src src, *srcp;
	int ret;
	if (c2c_sample->accessed)
		return;

	srcp = malloc(sizeof(union perf_mem_data_src) * 4);
	c2c_sample->accessed = true;
	memset(&src, 0, sizeof(src));

	if (c2c_sample->state.is_ld) {
		src.mem_op  = PERF_MEM_OP_LOAD;

		if (c2c_sample->state.is_tlb_miss)
			src.mem_dtlb = PERF_MEM_TLB_MISS;
		else
			src.mem_dtlb = PERF_MEM_TLB_HIT;

		if (c2c_sample->state.is_remote) {
			src.mem_snoop = PERF_MEM_SNOOP_HITM;
			src.mem_lvl = PERF_MEM_LVL_REM_CCE2;
		} else {
			if (c2c_sample->state.is_llc_miss) {
				src.mem_snoop = PERF_MEM_SNOOP_HITM;
				src.mem_lvl = PERF_MEM_LVL_HIT | PERF_MEM_LVL_L3;
			} else if (c2c_sample->state.is_llc_access) {
				src.mem_snoop = PERF_MEM_SNOOP_HIT;
				src.mem_lvl = PERF_MEM_LVL_HIT | PERF_MEM_LVL_L3;
			} else if (!c2c_sample->state.is_l1d_access) {
				src.mem_lvl = PERF_MEM_LVL_HIT | PERF_MEM_LVL_LFB;
			} else if (!c2c_sample->state.is_l1d_miss) {
				src.mem_lvl = PERF_MEM_LVL_HIT | PERF_MEM_LVL_L1;
			} else {
				src.mem_lvl = PERF_MEM_LVL_HIT | PERF_MEM_LVL_L2;
			}
		}
	} else if (c2c_sample->state.is_st) {
		src.mem_op  = PERF_MEM_OP_STORE;
		if (c2c_sample->state.is_l1d_miss)
			src.mem_lvl = PERF_MEM_LVL_MISS | PERF_MEM_LVL_L1;
		else
			src.mem_lvl = PERF_MEM_LVL_HIT | PERF_MEM_LVL_L1;
	} else
		return;

	sample.ip = c2c_sample->state.from_ip;
	sample.cpumode = arm_spe_cpumode(speq->spe, sample.ip);
	sample.pid = c2c_sample->pid;
	sample.tid = c2c_sample->tid;
	sample.addr = c2c_sample->state.addr;
	srcp[0] = src;
	srcp[1].val = c2c_sample->state.tot_lat;
	srcp[2].val = c2c_sample->state.issue_lat;
	srcp[3].val = c2c_sample->state.trans_lat;
	sample.data_src = (u64)srcp;
	sample.phys_addr = c2c_sample->state.phys_addr;
	sample.period = 1;
	sample.cpu = c2c_queues->cpu;

	event->sample.header.type = PERF_RECORD_SAMPLE;
	event->sample.header.misc = sample.cpumode;
	event->sample.header.size = sizeof(struct perf_event_header);

	ret = perf_session__deliver_synth_event(speq->spe->session, event, &sample);
	if (ret)
		pr_err("ARM SPE: failed to deliver event, error %d\n", ret);
}

static struct rb_node*
find_false_sharing(uint64_t phys_addr, pid_t tid, struct rb_node *root)
{
	struct spe_c2c_sample *sample;
	unsigned int i;

	if (!root)
		return NULL;
	sample = rb_entry(root, struct spe_c2c_sample, rb_node);

	if (sample->state.phys_addr != phys_addr && sample->tid != tid)
		return root;

	if (!sample->tid_arry)
		return NULL;

	for (i = 0; i <= IN_CACHELINE; i++) {
		if ((phys_addr & IN_CACHELINE) == i)
			continue;
		if (sample->tid_arry[1 + IN_CACHELINE + i])
			return root;
		if (sample->tid_arry[i] != tid)
			return root;
	}
	return NULL;
}

static struct rb_node*
same_cacheline(uint64_t phys_addr, pid_t tid, struct rb_node *root)
{
	struct spe_c2c_sample *sample;
	uint64_t addr, addr_high, phys_addr_high;

	if (!root)
		return NULL;

	sample = rb_entry(root, struct spe_c2c_sample, rb_node);
	addr = sample->state.phys_addr;
	addr_high = addr & (uint64_t)~IN_CACHELINE;
	phys_addr_high = phys_addr & (uint64_t)~IN_CACHELINE;

	if (addr_high == phys_addr_high)
		return root;

	if (addr_high < phys_addr_high)
		return same_cacheline(phys_addr, tid, root->rb_right);

	return same_cacheline(phys_addr, tid, root->rb_left);

}

static void arm_spe_c2c_get_samples(void *arg)
{
	struct spe_c2c_compare_lists *list = arg;
	struct rb_root *listA = ((struct spe_c2c_compare_lists *)arg)->listA;
	struct rb_root *listB = ((struct spe_c2c_compare_lists *)arg)->listB;
	struct rb_node *nodeB, *nodeA;
	struct spe_c2c_sample *sampleA, *sampleB, *sample;
	uint64_t sampleA_paddr;

	if (!listB) {
		ui_progress__update(&prog, 1);
		return;
	}

	for (nodeA = rb_first(listA); nodeA; nodeA = rb_next(nodeA)) {
		sampleA = rb_entry(nodeA, struct spe_c2c_sample, rb_node);
		sampleA_paddr = sampleA->state.phys_addr;
		if (sampleA->false_share_next)
			continue;

		nodeB = same_cacheline(sampleA_paddr, sampleA->tid, listB->rb_node);
		if (nodeB) {
			bool found = false;

			for (sample = sampleA; sample; sample = sample->same_cache) {
				sampleA_paddr = sample->state.phys_addr;
				if (find_false_sharing(sampleA_paddr, sample->tid, nodeB)) {
					found = true;
					break;
				}
			}

			if (found && !pthread_mutex_trylock(&sampleA->mut)) {
				if (!sampleA->false_share_next) {
					sample = sampleA;
					for (; sample; sample = sample->same_cache) {
						sample->false_share_next = list->false_share;
						list->false_share = sample;
						list->num++;
					}
				}
				pthread_mutex_unlock(&sampleA->mut);
			}

			sampleB = rb_entry(nodeB, struct spe_c2c_sample, rb_node);
			if (found && !pthread_mutex_trylock(&sampleB->mut)) {
				if (!sampleB->false_share_next) {
					sample = sampleB;
					for (; sample; sample = sample->same_cache) {
						sample->false_share_next = list->false_share;
						list->false_share = sample;
						list->num++;
					}
				}
				pthread_mutex_unlock(&sampleB->mut);
			}
		}
	}
	ui_progress__update(&prog, 1);
}

static int arm_spe_c2c_process(struct arm_spe *spe __maybe_unused)
{
	int i, j, k, ret, size;
	uint64_t sum = 0;
	int store = spe->synth_opts.c2c_store ? 2 : 0;
	pthread_t *c2c_threads;
	struct spe_c2c_compare_lists *c2c_lists;

	if (spe_c2c_q_num == 0)
		return 0;

	if (spe_c2c_q_num < 2) {
		pr_err("ARM SPE: c2c mode requires data recorded on at least two CPUs!\n");
		return -1;
	}

	k = 0;
	size = (2 + store) * spe_c2c_q_num * (spe_c2c_q_num - 1) / 2;

	c2c_threads = (pthread_t *)zalloc(size * sizeof(pthread_t));
	c2c_lists = (struct spe_c2c_compare_lists *)zalloc(size * sizeof(struct spe_c2c_compare_lists));

	ui_progress__init(&prog, size, "Finding false sharing cacheline...");
	for (i = 0; i < spe_c2c_q_num; i++) {
		for (j = i + 1; j < spe_c2c_q_num; j++) {
			c2c_lists[k].listA = &(spe_c2c_sample_list[i].ld_list);
			c2c_lists[k].listB = &(spe_c2c_sample_list[j].st_list);
			c2c_lists[k].queues = &spe_c2c_sample_list[i];
			c2c_lists[k].oppoqs = &spe_c2c_sample_list[j];
			ret = pthread_create(&c2c_threads[k], NULL, (void *)arm_spe_c2c_get_samples,
					(void *)&c2c_lists[k]);
			if (ret) {
				pr_info("ARM SPE: c2c process thread[ld->st] create failed! ret=%d\n", ret);
				return ret;
			}

			k++;
			c2c_lists[k].listA = &(spe_c2c_sample_list[j].ld_list);
			c2c_lists[k].listB = &(spe_c2c_sample_list[i].st_list);
			c2c_lists[k].queues = &spe_c2c_sample_list[j];
			c2c_lists[k].oppoqs = &spe_c2c_sample_list[i];
			ret = pthread_create(&c2c_threads[k], NULL, (void *)arm_spe_c2c_get_samples,
					(void *)&c2c_lists[k]);
			if (ret) {
				pr_info("ARM SPE: c2c process thread[st->ld] create failed! ret=%d\n", ret);
				return ret;
			}
			if (store) {
				k++;
				c2c_lists[k].listA = &(spe_c2c_sample_list[i].st_list);
				c2c_lists[k].listB = &(spe_c2c_sample_list[j].st_list);
				c2c_lists[k].queues = &spe_c2c_sample_list[i];
				c2c_lists[k].oppoqs = &spe_c2c_sample_list[j];
				ret = pthread_create(&c2c_threads[k], NULL, (void *)arm_spe_c2c_get_samples,
						(void *)&c2c_lists[k]);
				if (ret) {
					pr_info("ARM SPE: c2c process thread[st->st] create failed! ret=%d\n", ret);
					return ret;
				}
				k++;
				c2c_lists[k].listA = &(spe_c2c_sample_list[j].st_list);
				c2c_lists[k].listB = &(spe_c2c_sample_list[i].st_list);
				c2c_lists[k].queues = &spe_c2c_sample_list[j];
				c2c_lists[k].oppoqs = &spe_c2c_sample_list[i];
				ret = pthread_create(&c2c_threads[k], NULL,
					(void *)arm_spe_c2c_get_samples, (void *)&c2c_lists[k]);
				if (ret) {
					pr_info("ARM SPE: c2c process store failed! ret=%d\n", ret);
					return ret;
				}
			}
			k++;
		}
	}

	for (i = 0; i < size; i++) {
		ret = pthread_join(c2c_threads[i], NULL);
		BUG_ON(ret);
	}

	ui_progress__finish();
	for (i = 0; i < size; i++)
		sum += c2c_lists[i].num;

	ui_progress__init(&prog, sum, "Resolving cacheline contention...");
	for (i = 0; i < size; i++) {
		struct spe_c2c_sample *sample = c2c_lists[i].false_share;

		for (; sample; sample = sample->false_share_next) {
			arm_spe_c2c_sample(c2c_lists[i].queues, sample);
			ui_progress__update(&prog, 1);
		}
	}
	ui_progress__finish();

	free(c2c_threads);
	free(c2c_lists);

	spe_c2c_q_num = 0;

	return ret;
}

static int arm_spe_process_switch(struct arm_spe *spe,
				   struct perf_sample *sample)
{
	struct perf_evsel *evsel;
	pid_t tid;
	int cpu;

	evsel = perf_evlist__id2evsel(spe->session->evlist, sample->id);
	if (evsel != spe->switch_evsel)
		return 0;

	tid = perf_evsel__intval(evsel, sample, "next_pid");
	cpu = sample->cpu;

	pr_debug4("sched_switch: cpu %d tid %d time %"PRIu64" tsc %#"PRIx64"\n",
		     cpu, tid, sample->time, perf_time_to_tsc(sample->time,
		     &spe->tc));

	return machine__set_current_tid(spe->machine, cpu, -1, tid);
}

static int arm_spe_context_switch(struct arm_spe *spe, union perf_event *event,
				   struct perf_sample *sample)
{
	bool out = event->header.misc & PERF_RECORD_MISC_SWITCH_OUT;
	pid_t pid, tid;
	int cpu;

	cpu = sample->cpu;

	if (out)
		return 0;
	pid = sample->pid;
	tid = sample->tid;

	if (tid == -1) {
		pr_err("context_switch event has no tid\n");
		return -EINVAL;
	}

	pr_debug4("context_switch: cpu %d pid %d tid %d time %"PRIu64" tsc %#"PRIx64"\n",
		     cpu, pid, tid, sample->time, perf_time_to_tsc(sample->time,
		     &spe->tc));

	return machine__set_current_tid(spe->machine, cpu, pid, tid);
}

static int arm_spe_process_itrace_start(struct arm_spe *spe,
					union perf_event *event,
					struct perf_sample *sample)
{
	pr_debug4("itrace_start: cpu %d pid %d tid %d time %"PRIu64" tsc %#"PRIx64"\n",
		     sample->cpu, event->itrace_start.pid,
		     event->itrace_start.tid, sample->time,
		     perf_time_to_tsc(sample->time, &spe->tc));

	return machine__set_current_tid(spe->machine, sample->cpu,
					event->itrace_start.pid,
					event->itrace_start.tid);
}
static int arm_spe_process_timeless_queues(struct arm_spe *spe, pid_t tid,
					    u64 time_)
{
	struct spe_c2c_sample_queues *spe_c2cq = NULL;
	struct auxtrace_queues *queues = &spe->queues;
	unsigned int i;
	u64 ts = 0;

	for (i = 0; i < queues->nr_queues; i++) {
		struct auxtrace_queue *queue = &spe->queues.queue_array[i];
		struct arm_spe_queue *speq = queue->priv;

		if (speq && (tid == -1 || speq->tid == tid)) {
			speq->time = time_;
			arm_spe_set_pid_tid_cpu(spe, queue);
			arm_spe_run_decoder(speq, &ts, spe_c2cq);
		}
	}
	return 0;
}

static int arm_spe_process_event(struct perf_session *session,
				 union perf_event *event,
				 struct perf_sample *sample,
				 struct perf_tool *tool)
{
	int err = 0;
	u64 timestamp;
	struct arm_spe *spe = container_of(session->auxtrace,
			struct arm_spe, auxtrace);

	if (dump_trace)
		return 0;

	if (!tool->ordered_events) {
		pr_err("ARM SPE requires ordered events\n");
		return -EINVAL;
	}

	if (sample->time && (sample->time != (u64) -1))
		timestamp = perf_time_to_tsc(sample->time, &spe->tc);
	else
		timestamp = 0;

	if (timestamp || spe->timeless_decoding) {
		err = arm_spe__update_queues(spe);
		if (err)
			return err;
	}

	if (spe->timeless_decoding) {
		if (event->header.type == PERF_RECORD_EXIT) {
			err = arm_spe_process_timeless_queues(spe,
					event->fork.tid,
					sample->time);
		}
	} else if (timestamp) {
		err = arm_spe_process_queues(spe, timestamp);
		if (err)
			return err;
	}

	if (spe->switch_evsel && event->header.type == PERF_RECORD_SAMPLE)
		err = arm_spe_process_switch(spe, sample);
	else if (event->header.type == PERF_RECORD_ITRACE_START)
		err = arm_spe_process_itrace_start(spe, event, sample);
	else if (event->header.type == PERF_RECORD_SWITCH ||
		 event->header.type == PERF_RECORD_SWITCH_CPU_WIDE)
		err = arm_spe_context_switch(spe, event, sample);

	pr_debug4("event %s (%u): cpu %d time %"PRIu64" tsc %#"PRIx64"\n",
		     perf_event__name(event->header.type), event->header.type,
		     sample->cpu, sample->time, timestamp);

	return err;
}

static int arm_spe_process_auxtrace_event(struct perf_session *session,
					  union perf_event *event,
					  struct perf_tool *tool __maybe_unused)
{
	struct arm_spe *spe = container_of(session->auxtrace, struct arm_spe,
					     auxtrace);

	if (!spe->data_queued) {
		struct auxtrace_buffer *buffer;
		off_t data_offset;
		int fd = perf_data__fd(session->data);
		int err;

		if (perf_data__is_pipe(session->data)) {
			data_offset = 0;
		} else {
			data_offset = lseek(fd, 0, SEEK_CUR);
			if (data_offset == -1)
				return -errno;
		}

		err = auxtrace_queues__add_event(&spe->queues, session, event,
				data_offset, &buffer);
		if (err)
			return err;

		/* Dump here now we have copied a piped trace out of the pipe */
		if (dump_trace) {
			if (auxtrace_buffer__get_data(buffer, fd)) {
				arm_spe_dump_event(spe, buffer->data,
						buffer->size);
				auxtrace_buffer__put_data(buffer);
			}
		}
	}

	return 0;
}

static int arm_spe_flush(struct perf_session *session __maybe_unused,
			 struct perf_tool *tool __maybe_unused)
{
	struct arm_spe *spe = container_of(session->auxtrace, struct arm_spe,
			auxtrace);
	int ret;

	if (dump_trace)
		return 0;

	if (!tool->ordered_events)
		return -EINVAL;

	ret = arm_spe__update_queues(spe);
	if (ret < 0)
		return ret;

	if (spe->timeless_decoding)
		return arm_spe_process_timeless_queues(spe, -1,
				MAX_TIMESTAMP - 1);

	ret = arm_spe_process_queues(spe, MAX_TIMESTAMP);
	if (ret < 0)
		return ret;

	if (spe->sample_c2c_mode)
		ret = arm_spe_c2c_process(spe);

	return ret;
}

static void arm_spe_free_queue(void *priv)
{
	struct arm_spe_queue *speq = priv;

	if (!speq)
		return;
	thread__zput(speq->thread);
	arm_spe_decoder_free(speq->decoder);
	zfree(&speq->event_buf);
	free(speq);
}

static void arm_spe_free_events(struct perf_session *session)
{
	struct arm_spe *spe = container_of(session->auxtrace, struct arm_spe,
					     auxtrace);
	struct auxtrace_queues *queues = &spe->queues;
	unsigned int i;

	for (i = 0; i < queues->nr_queues; i++) {
		arm_spe_free_queue(queues->queue_array[i].priv);
		queues->queue_array[i].priv = NULL;
	}
	auxtrace_queues__free(queues);
}

static void arm_spe_free(struct perf_session *session)
{
	struct arm_spe *spe = container_of(session->auxtrace, struct arm_spe,
					     auxtrace);

	auxtrace_heap__free(&spe->heap);
	arm_spe_free_events(session);
	session->auxtrace = NULL;
	free(spe);
}

static const char * const arm_spe_info_fmts[] = {
	[ARM_SPE_PMU_TYPE]		= "  PMU Type           %"PRId64"\n",
};

static void arm_spe_print_info(u64 *arr)
{
	if (!dump_trace)
		return;

	fprintf(stdout, arm_spe_info_fmts[ARM_SPE_PMU_TYPE], arr[ARM_SPE_PMU_TYPE]);
}

struct arm_spe_synth {
	struct perf_tool dummy_tool;
	struct perf_session *session;
};

static int arm_spe_event_synth(struct perf_tool *tool,
			       union perf_event *event,
			       struct perf_sample *sample __maybe_unused,
			       struct machine *machine __maybe_unused)
{
	struct arm_spe_synth *arm_spe_synth =
		      container_of(tool, struct arm_spe_synth, dummy_tool);

	return perf_session__deliver_synth_event(arm_spe_synth->session,
						 event, NULL);
}

static int arm_spe_synth_event(struct perf_session *session,
			       struct perf_event_attr *attr, u64 id)
{
	struct arm_spe_synth arm_spe_synth;

	memset(&arm_spe_synth, 0, sizeof(struct arm_spe_synth));
	arm_spe_synth.session = session;

	return perf_event__synthesize_attr(&arm_spe_synth.dummy_tool, attr, 1,
					   &id, arm_spe_event_synth);
}

static void arm_spe_set_event_name(struct perf_evlist *evlist, u64 id,
				    const char *name)
{
	struct perf_evsel *evsel;

	evlist__for_each_entry(evlist, evsel) {
		if (evsel->id && evsel->id[0] == id) {
			if (evsel->name)
				zfree(&evsel->name);
			evsel->name = strdup(name);
			break;
		}
	}
}

static struct perf_evsel *arm_spe_find_sched_switch(struct perf_evlist *evlist)
{
	struct perf_evsel *evsel;

	evlist__for_each_entry_reverse(evlist, evsel) {
		const char *name = perf_evsel__name(evsel);

		if (!strcmp(name, "sched:sched_switch"))
			return evsel;
	}

	return NULL;
}

static bool arm_spe_find_switch(struct perf_evlist *evlist)
{
	struct perf_evsel *evsel;

	evlist__for_each_entry(evlist, evsel) {
		if (evsel->attr.context_switch)
			return true;
	}

	return false;
}

static int arm_spe_synth_events(struct arm_spe *spe, struct perf_session *session)
{
	struct perf_evlist *evlist = session->evlist;
	struct perf_evsel *evsel;
	struct perf_event_attr attr;
	bool found = false;
	u64 id;
	int err;

	evlist__for_each_entry(evlist, evsel) {
		if (evsel->attr.type == spe->pmu_type) {
			found = true;
			break;
		}
	}

	if (!found) {
		pr_debug("No selected events with ARM SPE data\n");
		return 0;
	}

	memset(&attr, 0, sizeof(struct perf_event_attr));
	attr.size = sizeof(struct perf_event_attr);
	attr.type = PERF_TYPE_HARDWARE;
	attr.sample_type = evsel->attr.sample_type & PERF_SAMPLE_MASK;
	attr.sample_type |= PERF_SAMPLE_IP | PERF_SAMPLE_TID |
		PERF_SAMPLE_PERIOD;
	if (spe->timeless_decoding)
		attr.sample_type &= ~(u64)PERF_SAMPLE_TIME;
	else
		attr.sample_type |= PERF_SAMPLE_TIME;

	attr.exclude_user = evsel->attr.exclude_user;
	attr.exclude_kernel = evsel->attr.exclude_kernel;
	attr.exclude_hv = evsel->attr.exclude_hv;
	attr.exclude_host = evsel->attr.exclude_host;
	attr.exclude_guest = evsel->attr.exclude_guest;
	attr.sample_id_all = evsel->attr.sample_id_all;
	attr.read_format = evsel->attr.read_format;

	/* create new id val to be a fixed offset from evsel id */
	id = evsel->id[0] + 1000000000;

	if (!id)
		id = 1;

	/* spe events set */
	if (spe->synth_opts.llc_miss) {
		spe->sample_llc_miss = true;

		/* llc-miss */
		err = arm_spe_synth_event(session, &attr, id);
		if (err)
			return err;
		spe->llc_miss_id = id;
		arm_spe_set_event_name(evlist, id, "llc-miss");
		id += 1;
	}

	if (spe->synth_opts.tlb_miss) {
		spe->sample_tlb_miss = true;

		/* tlb-miss */
		err = arm_spe_synth_event(session, &attr, id);
		if (err)
			return err;
		spe->tlb_miss_id = id;
		arm_spe_set_event_name(evlist, id, "tlb-miss");
		id += 1;
	}

	if (spe->synth_opts.branch_miss) {
		spe->sample_branch_miss = true;

		/* branch-miss */
		err = arm_spe_synth_event(session, &attr, id);
		if (err)
			return err;
		spe->branch_miss_id = id;
		arm_spe_set_event_name(evlist, id, "branch-miss");
		id += 1;
	}

	if (spe->synth_opts.remote_access) {
		spe->sample_remote_access = true;

		/* remote-access */
		err = arm_spe_synth_event(session, &attr, id);
		if (err)
			return err;
		spe->remote_access_id = id;
		arm_spe_set_event_name(evlist, id, "remote-access");
		id += 1;
	}

	return 0;
}

int arm_spe_process_auxtrace_info(union perf_event *event,
				  struct perf_session *session)
{
	struct auxtrace_info_event *auxtrace_info = &event->auxtrace_info;
	size_t min_sz = sizeof(u64) * ARM_SPE_PMU_TYPE;
	struct arm_spe *spe;
	int err;

	if (auxtrace_info->header.size < sizeof(struct auxtrace_info_event) +
					min_sz)
		return -EINVAL;

	spe = zalloc(sizeof(struct arm_spe));
	if (!spe)
		return -ENOMEM;

	err = auxtrace_queues__init(&spe->queues);
	if (err)
		goto err_free;

	spe->session = session;
	spe->machine = &session->machines.host; /* No kvm support */
	spe->auxtrace_type = auxtrace_info->type;
	spe->pmu_type = auxtrace_info->priv[ARM_SPE_PMU_TYPE];
	spe->tc.time_shift = auxtrace_info->priv[ARM_SPE_TIME_SHIFT];
	spe->tc.time_mult = auxtrace_info->priv[ARM_SPE_TIME_MULT];
	spe->tc.time_zero = auxtrace_info->priv[ARM_SPE_TIME_ZERO];
	spe->cap_user_time_zero = auxtrace_info->priv[ARM_SPE_CAP_USER_TIME_ZERO];
	spe->ts_bit = auxtrace_info->priv[ARM_SPE_TS_ENABLE];
	spe->have_sched_switch = auxtrace_info->priv[ARM_SPE_HAVE_SCHED_SWITCH];

	spe->timeless_decoding = arm_spe_is_timeless_decoding(spe);
	spe->auxtrace.process_event = arm_spe_process_event;
	spe->auxtrace.process_auxtrace_event = arm_spe_process_auxtrace_event;
	spe->auxtrace.flush_events = arm_spe_flush;
	spe->auxtrace.free_events = arm_spe_free_events;
	spe->auxtrace.free = arm_spe_free;
	session->auxtrace = &spe->auxtrace;

	arm_spe_print_info(&auxtrace_info->priv[0]);

	if (dump_trace)
		return 0;

	if (spe->have_sched_switch == 1) {
		spe->switch_evsel = arm_spe_find_sched_switch(session->evlist);
		if (!spe->switch_evsel) {
			pr_err("%s: missing sched_switch event\n", __func__);
			err = -EINVAL;
			goto err_free_queues;
		}
	} else if (spe->have_sched_switch == 2 &&
		   !arm_spe_find_switch(session->evlist)) {
		pr_err("%s: missing context_switch attribute flag\n", __func__);
		err = -EINVAL;
		goto err_free_queues;
	}

	if (session->arm_spe_synth_opts && (session->arm_spe_synth_opts->set
				|| session->arm_spe_synth_opts->c2c_mode))
		spe->synth_opts = *session->arm_spe_synth_opts;
	else
		arm_spe_synth_opts__set_default(&spe->synth_opts);

	if (spe->synth_opts.c2c_mode) {
		spe->sample_c2c_mode = true;
		spe_c2c_sample_init();
	} else {
		err = arm_spe_synth_events(spe, session);
		if (err)
			goto err_free_queues;
	}

	err = auxtrace_queues__process_index(&spe->queues, session);
	if (err)
		goto err_free_queues;

	if (spe->queues.populated)
		spe->data_queued = true;

	if (spe->timeless_decoding)
		pr_debug2("ARM SPE decoding without timestamps\n");

	return 0;

err_free_queues:
	auxtrace_queues__free(&spe->queues);
	session->auxtrace = NULL;
err_free:
	free(spe);
	return err;
}
