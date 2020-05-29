// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <linux/compiler.h>
#include <asm/barrier.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <time.h>
#include <sched.h>
#include <signal.h>
#include <pthread.h>
#include <stdlib.h>
#include "test_ringbuf.h"

#define EDONE 7777

static int duration = 0;

struct sample {
	int pid;
	int seq;
	long value;
	char comm[16];
};

static int sample_cnt;

static int process_sample(void *ctx, void *data, size_t len)
{
	struct sample *s = data;

	sample_cnt++;

	switch (s->seq) {
	case 0:
		CHECK(s->value != 333, "sample1_value", "exp %ld, got %ld\n",
		      333L, s->value);
		return 0;
	case 1:
		CHECK(s->value != 777, "sample2_value", "exp %ld, got %ld\n",
		      777L, s->value);
		return -EDONE;
	default:
		/* we don't care about the rest */
		return 0;
	}
}

static struct ring_buffer *ringbuf;

static void trigger_samples()
{
	output_load();
	output.dropped = 0;
	output.total = 0;
	output.discarded = 0;
	output_update();

	/* trigger exactly two samples */
	input.value = 333;
	input_update();
	syscall(__NR_getpgid);
	input.value = 777;
	input_update();
	syscall(__NR_getpgid);
}

static void *poll_thread(void *input)
{
	long timeout = (long)input;

	return (void *)(long)ring_buffer__poll(ringbuf, timeout);
}

void test_ringbuf(void)
{
	const size_t rec_sz = BPF_RINGBUF_HDR_SZ + sizeof(struct sample);
	pthread_t thread;
	long bg_ret = -1;
	int err;

	err = populate_progs(BPF_OBJECT_NAME);
	if (CHECK(err < 0, "object_load", "load failed\n"))
		return;

	err = attach_progs();
	if (CHECK(err < 0, "object_attach", "attach failed\n"))
		return;

	/* only trigger BPF program for current process */
	input.pid = getpid();
	input_update();

	ringbuf = ring_buffer__new(ringbuf_fd,
				   process_sample, NULL, NULL);
	if (CHECK(!ringbuf, "ringbuf_create", "failed to create ringbuf\n"))
		goto cleanup;

	trigger_samples();

	output_load();
	/* 2 submitted + 1 discarded records */
	CHECK(output.avail_data != 3 * rec_sz,
	      "err_avail_size", "exp %ld, got %ld\n",
	      3L * rec_sz, output.avail_data);
	CHECK(output.ring_size != 4096,
	      "err_ring_size", "exp %ld, got %ld\n",
	      4096L, output.ring_size);
	CHECK(output.cons_pos != 0,
	      "err_cons_pos", "exp %ld, got %ld\n",
	      0L, output.cons_pos);
	CHECK(output.prod_pos != 3 * rec_sz,
	      "err_prod_pos", "exp %ld, got %ld\n",
	      3L * rec_sz, output.prod_pos);

	/* poll for samples */
	err = ring_buffer__poll(ringbuf, -1);

	/* -EDONE is used as an indicator that we are done */
	if (CHECK(err != -EDONE, "err_done", "done err: %d\n", err))
		goto cleanup;

	/* we expect extra polling to return nothing */
	err = ring_buffer__poll(ringbuf, 0);
	if (CHECK(err != 0, "extra_samples", "poll result: %d\n", err))
		goto cleanup;

	output_load();
	CHECK(output.dropped != 0, "err_dropped", "exp %ld, got %ld\n",
	      0L, output.dropped);
	CHECK(output.total != 2, "err_total", "exp %ld, got %ld\n",
	      2L, output.total);
	CHECK(output.discarded != 1, "err_discarded", "exp %ld, got %ld\n",
	      1L, output.discarded);

	/* now validate consumer position is updated and returned */
	trigger_samples();
	output_load();
	CHECK(output.cons_pos != 3 * rec_sz,
	      "err_cons_pos", "exp %ld, got %ld\n",
	      3L * rec_sz, output.cons_pos);
	err = ring_buffer__poll(ringbuf, -1);
	CHECK(err <= 0, "poll_err", "err %d\n", err);

	/* start poll in background w/ long timeout */
	err = pthread_create(&thread, NULL, poll_thread, (void *)(long)10000);
	if (CHECK(err, "bg_poll", "pthread_create failed: %d\n", err))
		goto cleanup;

	/* turn off notifications now */
	input.flags = BPF_RB_NO_WAKEUP;
	input_update();

	/* give background thread a bit of a time */
	usleep(50000);
	trigger_samples();
	/* sleeping arbitrarily is bad, but no better way to know that
	 * epoll_wait() **DID NOT** unblock in background thread
	 */
	usleep(50000);
	/* background poll should still be blocked */
	err = pthread_tryjoin_np(thread, (void **)&bg_ret);
	if (CHECK(err != EBUSY, "try_join", "err %d\n", err))
		goto cleanup;

	output_load();
	/* BPF side did everything right */
	CHECK(output.dropped != 0, "err_dropped", "exp %ld, got %ld\n",
	      0L, output.dropped);
	CHECK(output.total != 2, "err_total", "exp %ld, got %ld\n",
	      2L, output.total);
	CHECK(output.discarded != 1, "err_discarded", "exp %ld, got %ld\n",
	      1L, output.discarded);

	/* clear flags to return to "adaptive" notification mode */
	input.flags = 0;
	input_update();

	/* produce new samples, no notification should be triggered, because
	 * consumer is now behind
	 */
	trigger_samples();

	/* background poll should still be blocked */
	err = pthread_tryjoin_np(thread, (void **)&bg_ret);
	if (CHECK(err != EBUSY, "try_join", "err %d\n", err))
		goto cleanup;

	/* now force notifications */
	input.flags = BPF_RB_FORCE_WAKEUP;
	input_update();
	sample_cnt = 0;
	trigger_samples();

	/* now we should get a pending notification */
	usleep(50000);
	err = pthread_tryjoin_np(thread, (void **)&bg_ret);
	if (CHECK(err, "join_bg", "err %d\n", err))
		goto cleanup;

	if (CHECK(bg_ret != 1, "bg_ret", "epoll_wait result: %ld", bg_ret))
		goto cleanup;

	/* 3 rounds, 2 samples each */
	CHECK(sample_cnt != 6, "wrong_sample_cnt",
	      "expected to see %d samples, got %d\n", 6, sample_cnt);

	output_load();
	/* BPF side did everything right */
	CHECK(output.dropped != 0, "err_dropped", "exp %ld, got %ld\n",
	      0L, output.dropped);
	CHECK(output.total != 2, "err_total", "exp %ld, got %ld\n",
	      2L, output.total);
	CHECK(output.discarded != 1, "err_discarded", "exp %ld, got %ld\n",
	      1L, output.discarded);

	bpf_object__unload(obj);
cleanup:
	ring_buffer__free(ringbuf);
	bpf_object__close(obj);
}

int main()
{
	test_ringbuf();

	return error_cnt ? EXIT_FAILURE : EXIT_SUCCESS;
}