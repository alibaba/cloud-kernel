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

struct bpf_map_def SEC("maps") ringbuf1 = {
	.type = BPF_MAP_TYPE_RINGBUF,
	.max_entries = 1 << 12,
};

struct bpf_map_def SEC("maps") ringbuf2 = {
	.type = BPF_MAP_TYPE_RINGBUF,
	.max_entries = 1 << 12,
};

struct input {
	/* inputs */
	int pid;
	int target_ring;
	long value;
};

struct output {
	/* outputs */
	long total;
	long dropped;
	long skipped;
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

SEC("tp/syscalls/sys_enter_getpgid")
int test_ringbuf(void *ctx)
{
	int cur_pid = bpf_get_current_pid_tgid() >> 32;
	struct sample *sample;
	void *rb;
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

	switch (input->target_ring) {
		case 0:
			sample = bpf_ringbuf_reserve(&ringbuf1, sizeof(*sample), 0);
			break;
		case 2:
			sample = bpf_ringbuf_reserve(&ringbuf2, sizeof(*sample), 0);
			break;
		default:
			output->skipped += 1;
			return 1;
	}
	if (!sample) {
		output->dropped += 1;
		return 1;
	}

	sample->pid = input->pid;
	bpf_get_current_comm(sample->comm, sizeof(sample->comm));
	sample->value = input->value;

	sample->seq = output->total;
	output->total += 1;

	bpf_ringbuf_submit(sample, 0);

	return 0;
}
