/* SPDX-License-Identifier: GPL-2.0
 * Common header for both test_ringbuf_user.c and test_ringbuf_multi_user.c.
 * There are some difference between those two .c files, and these difference is isolated
 * by a macro TEST_RINGBUF_MULTI.
 * test_ringbuf_multi_user.c should define such marco before include this header.
 */
#ifndef TEST_RINGBUF_H
#define TEST_RINGBUF_H

#include <linux/perf_event.h>
#include <libbpf.h>
#include <bpf/bpf.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <errno.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <stdlib.h>

static int error_cnt, pass_cnt;

#define CHECK(condition, tag, format...) ({				\
	int __ret = !!(condition);					\
	if (__ret) {							\
		error_cnt++;						\
		printf("%s:FAIL:%s ", __func__, tag);			\
		printf(format);						\
	} else {							\
		pass_cnt++;						\
		printf("%s:PASS:%s %d nsec\n", __func__, tag, duration);\
	}								\
	__ret;								\
})

#define INPUT_MAP_NAME "input_map"
#define OUTPUT_MAP_NAME "output_map"

#ifdef TEST_RINGBUF_MULTI
#define BPF_OBJECT_NAME "test_ringbuf_multi_kern.o"
#define RINGBUF_MAP_NAME_1 "ringbuf1"
#define RINGBUF_MAP_NAME_2 "ringbuf2"
#else
#define BPF_OBJECT_NAME "test_ringbuf_kern.o"
#define RINGBUF_MAP_NAME "ringbuf"
#endif

#ifdef TEST_RINGBUF_MULTI
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

#else
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
#endif

int input_map_fd, output_map_fd;
struct output output = {};
struct input input = {};

static inline int output_load(void)
{
	int zero = 0;

	return bpf_map_lookup_elem(output_map_fd, &zero, &output);
}

static inline int output_update(void)
{
	int zero = 0;

	return bpf_map_update_elem(output_map_fd, &zero, &output, 0);
}

static inline int input_update(void)
{
	int zero = 0;

	return bpf_map_update_elem(input_map_fd, &zero, &input, 0);
}

struct bpf_object *obj = NULL;

#ifdef TEST_RINGBUF_MULTI
int ringbuf1_fd, ringbuf2_fd;
#else
int ringbuf_fd;
#endif

static int parse_uint_from_file(const char *file, const char *fmt)
{
	int err, ret;
	FILE *f;

	f = fopen(file, "r");
	if (!f) {
		err = -errno;
		fprintf(stderr, "failed to open '%s': %d\n", file, err);
		return err;
	}
	err = fscanf(f, fmt, &ret);
	if (err != 1) {
		err = err == EOF ? -EIO : -errno;
		fprintf(stderr, "failed to parse '%s': %d\n", file, err);
		fclose(f);
		return err;
	}
	fclose(f);
	return ret;
}

#define PATH_MAX 512
static int determine_tracepoint_id(const char *tp_category,
				   const char *tp_name)
{
	char file[PATH_MAX];
	int ret;

	ret = snprintf(file, sizeof(file),
		       "/sys/kernel/debug/tracing/events/%s/%s/id",
		       tp_category, tp_name);
	if (ret < 0)
		return -errno;
	if (ret >= sizeof(file)) {
		fprintf(stderr, "tracepoint %s/%s path is too long\n",
			 tp_category, tp_name);
		return -E2BIG;
	}
	return parse_uint_from_file(file, "%d\n");
}

static int perf_event_open_tracepoint(const char *tp_category,
				      const char *tp_name)
{
	struct perf_event_attr attr = {};
	int tp_id, pfd, err;

	tp_id = determine_tracepoint_id(tp_category, tp_name);
	if (tp_id < 0) {
		fprintf(stderr, "failed to determine tracepoint '%s/%s' perf event ID: %d\n",
			tp_category, tp_name, tp_id);
		return tp_id;
	}

	attr.type = PERF_TYPE_TRACEPOINT;
	attr.size = sizeof(attr);
	attr.config = tp_id;

	pfd = syscall(__NR_perf_event_open, &attr, -1 /* pid */, 0 /* cpu */,
		      -1 /* group_fd */, PERF_FLAG_FD_CLOEXEC);
	if (pfd < 0) {
		err = -errno;
		fprintf(stderr, "tracepoint '%s/%s' perf_event_open() failed: %d\n",
			tp_category, tp_name, err);
		return err;
	}
	return pfd;
}

int bpf_program__attach_tracepoint(struct bpf_program *prog,
						const char *tp_category,
						const char *tp_name)
{
	int pfd, err, prog_fd;
	const char *prog_name = bpf_program__title(prog, false);

	prog_fd = bpf_program__fd(prog);

	pfd = perf_event_open_tracepoint(tp_category, tp_name);
	if (pfd < 0) {
		fprintf(stderr, "prog '%s': failed to create tracepoint '%s/%s' perf event: %d\n",
			prog_name, tp_category, tp_name, pfd);
		return pfd;
	}

	if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) {
		err = -errno;
		fprintf(stderr, "prog '%s': failed to attach to pfd %d: %d\n",
			prog_name, pfd, err);
		close(pfd);
		return err;
	}

	if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
		err = -errno;
		fprintf(stderr, "prog '%s': failed to enable pfd %d: %d\n",
			prog_name, pfd, err);
		close(pfd);
		return err;
	}

	return pfd;
}

static int attach_tp(struct bpf_program *prog)
{
	char *sec_name, *tp_cat, *tp_name;
	int ret;
	char prefix[] = "tp/";

	sec_name = (char *)bpf_program__title(prog, true);
	if (!sec_name)
		return -ENOMEM;

	/* extract "tp/<category>/<name>" */
	tp_cat = sec_name + strlen(prefix);
	tp_name = strchr(tp_cat, '/');
	if (!tp_name) {
		ret = -EINVAL;
		goto out;
	}
	*tp_name = '\0';
	tp_name++;

	ret = bpf_program__attach_tracepoint(prog, tp_cat, tp_name);
out:
	free(sec_name);
	return ret;
}

static int populate_progs(char *bpf_file)
{
	int prog_fd;
	int err;
	struct bpf_map *input_map, *output_map, *ringbuf_map;

	err = bpf_prog_load(bpf_file, BPF_PROG_TYPE_TRACEPOINT, &obj, &prog_fd);
	if (err < 0) {
		printf("Unable to load eBPF objects in file '%s' : %d\n",
		       bpf_file, err);
		return -1;
	}

	input_map = bpf_object__find_map_by_name(obj, INPUT_MAP_NAME);
	if (!input_map) {
		printf("Unable to find input map '%s' in eBPF object in file '%s'\n",
		       INPUT_MAP_NAME, bpf_file);
		return -1;
	}
	input_map_fd = bpf_map__fd(input_map);

	output_map = bpf_object__find_map_by_name(obj, OUTPUT_MAP_NAME);
	if (!output_map) {
		printf("Unable to find output map '%s' in eBPF object in file '%s'\n",
		       OUTPUT_MAP_NAME, bpf_file);
		return -1;
	}
	output_map_fd = bpf_map__fd(output_map);

#ifdef TEST_RINGBUF_MULTI
	ringbuf_map = bpf_object__find_map_by_name(obj, RINGBUF_MAP_NAME_1);
	if (!ringbuf_map) {
        printf("Unable to find ringbuf map '%s' in eBPF object in file '%s'\n",
		       RINGBUF_MAP_NAME_1, bpf_file);
		return -1;
	}
    ringbuf1_fd = bpf_map__fd(ringbuf_map);
	ringbuf_map = bpf_object__find_map_by_name(obj, RINGBUF_MAP_NAME_2);
	if (!ringbuf_map) {
        printf("Unable to find ringbuf map '%s' in eBPF object in file '%s'\n",
		       RINGBUF_MAP_NAME_2, bpf_file);
		return -1;
	}
    ringbuf2_fd = bpf_map__fd(ringbuf_map);
#else
	ringbuf_map = bpf_object__find_map_by_name(obj, RINGBUF_MAP_NAME);
	if (!ringbuf_map) {
        printf("Unable to find ringbuf map '%s' in eBPF object in file '%s'\n",
		       RINGBUF_MAP_NAME, bpf_file);
		return -1;
	}
    ringbuf_fd = bpf_map__fd(ringbuf_map);
#endif

	return 0;
}

static int attach_progs(void)
{
	struct bpf_program *prog;
	int err;

	bpf_object__for_each_program(prog, obj) {
		err = attach_tp(prog);
		if (err < 0) {
			printf("Unable to attach bpf prog %s : %d\n",
			       bpf_program__title(prog, false), err);
			return -1;
		}
	}

	return 0;
}

#endif