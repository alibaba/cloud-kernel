// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook

#include <linux/bpf.h>
#include "bpf_helpers.h"

int _version SEC("version") = 1;
char _license[] SEC("license") = "GPL";

struct sample {
	int pid;
	int seq;
	long value;
	char comm[16];
};

struct bpf_map_def SEC("maps") ringbuf = {
	.type = BPF_MAP_TYPE_RINGBUF,
	.max_entries = 1 << 12,
};

struct input {
	/* inputs */
	int pid;
	long value;
	long flags;
};

struct output {
	/* outputs */
	long total;
	long discarded;
	long dropped;

	long avail_data;
	long ring_size;
	long cons_pos;
	long prod_pos;

	/* inner state */
	long seq;
};

struct bpf_map_def SEC("maps") input_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct input),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") output_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct output),
	.max_entries = 1,
};

#define bpf_printk(fmt, ...)				\
({							\
	char ____fmt[] = fmt;				\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			##__VA_ARGS__);			\
})

SEC("tp/syscalls/sys_enter_getpgid")
int test_ringbuf(void *ctx)
{
	int cur_pid = bpf_get_current_pid_tgid() >> 32;
	struct sample *sample;
	int zero = 0;
	struct input *input;
	struct output *output;

	input = bpf_map_lookup_elem(&input_map, &zero);
	if (!input)
		return 0;
	output = bpf_map_lookup_elem(&output_map, &zero);
	if (!output)
		return 0;

	if (cur_pid != input->pid)
		return 0;

	sample = bpf_ringbuf_reserve(&ringbuf, sizeof(*sample), 0);
	if (!sample) {
		__sync_fetch_and_add(&output->dropped, 1);
		return 1;
	}

	sample->pid = input->pid;
	bpf_get_current_comm(sample->comm, sizeof(sample->comm));
	sample->value = input->value;

	sample->seq = (output->seq)++;
	__sync_fetch_and_add(&output->total, 1);

	if (sample->seq & 1) {
		/* copy from reserved sample to a new one... */
		bpf_ringbuf_output(&ringbuf, sample, sizeof(*sample), input->flags);
		/* ...and then discard reserved sample */
		bpf_ringbuf_discard(sample, input->flags);
		__sync_fetch_and_add(&output->discarded, 1);
	} else {
		bpf_ringbuf_submit(sample, input->flags);
	}

	output->avail_data = bpf_ringbuf_query(&ringbuf, BPF_RB_AVAIL_DATA);
	output->ring_size = bpf_ringbuf_query(&ringbuf, BPF_RB_RING_SIZE);
	output->cons_pos = bpf_ringbuf_query(&ringbuf, BPF_RB_CONS_POS);
	output->prod_pos = bpf_ringbuf_query(&ringbuf, BPF_RB_PROD_POS);

	return 0;
}
