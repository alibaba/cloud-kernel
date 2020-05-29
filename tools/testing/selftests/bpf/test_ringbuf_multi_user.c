// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <sys/epoll.h>

#define TEST_RINGBUF_MULTI
#include "test_ringbuf.h"

static int duration = 0;

struct sample {
	int pid;
	int seq;
	long value;
	char comm[16];
};

static int process_sample(void *ctx, void *data, size_t len)
{
	int ring = (unsigned long)ctx;
	struct sample *s = data;

	switch (s->seq) {
	case 0:
		CHECK(ring != 1, "sample1_ring", "exp %d, got %d\n", 1, ring);
		CHECK(s->value != 333, "sample1_value", "exp %ld, got %ld\n",
		      333L, s->value);
		break;
	case 1:
		CHECK(ring != 2, "sample2_ring", "exp %d, got %d\n", 2, ring);
		CHECK(s->value != 777, "sample2_value", "exp %ld, got %ld\n",
		      777L, s->value);
		break;
	default:
		CHECK(true, "extra_sample", "unexpected sample seq %d, val %ld\n",
		      s->seq, s->value);
		return -1;
	}

	return 0;
}

void test_ringbuf_multi(void)
{
	struct ring_buffer *ringbuf;
	int err;

	err = populate_progs(BPF_OBJECT_NAME);
	if (CHECK(err < 0, "object_load", "load failed\n"))
		return;

	/* only trigger BPF program for current process */
	input.pid = getpid();
	input_update();

	ringbuf = ring_buffer__new(ringbuf1_fd,
				   process_sample, (void *)(long)1, NULL);
	if (CHECK(!ringbuf, "ringbuf_create", "failed to create ringbuf\n"))
		goto cleanup;

	err = ring_buffer__add(ringbuf, ringbuf2_fd,
			      process_sample, (void *)(long)2);
	if (CHECK(err, "ringbuf_add", "failed to add another ring\n"))
		goto cleanup;

	err = attach_progs();
	if (CHECK(err < 0, "object_attach", "attach failed\n"))
		return;

	/* trigger few samples, some will be skipped */
	input.target_ring = 0;
	input.value = 333;
	input_update();
	syscall(__NR_getpgid);

	/* skipped, no ringbuf in slot 1 */
	input.target_ring = 1;
	input.value = 555;
	input_update();
	syscall(__NR_getpgid);

	input.target_ring = 2;
	input.value = 777;
	input_update();
	syscall(__NR_getpgid);

	/* poll for samples, should get 2 ringbufs back */
	err = ring_buffer__poll(ringbuf, -1);
	if (CHECK(err != 4, "poll_res", "expected 4 records, got %d\n", err))
		goto cleanup;

	/* expect extra polling to return nothing */
	err = ring_buffer__poll(ringbuf, 0);
	if (CHECK(err < 0, "extra_samples", "poll result: %d\n", err))
		goto cleanup;

	output_load();
	CHECK(output.dropped != 0, "err_dropped", "exp %ld, got %ld\n",
	      0L, output.dropped);
	CHECK(output.skipped != 1, "err_skipped", "exp %ld, got %ld\n",
	      1L, output.skipped);
	CHECK(output.total != 2, "err_total", "exp %ld, got %ld\n",
	      2L, output.total);

cleanup:
	ring_buffer__free(ringbuf);
	bpf_object__close(obj);
}

int main()
{
	test_ringbuf_multi();

	return error_cnt ? EXIT_FAILURE : EXIT_SUCCESS;
}
