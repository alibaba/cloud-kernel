// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <err.h>
#include <elf.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <malloc.h>
#include <unistd.h>
#include <ucontext.h>

#include <linux/futex.h>

#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/shm.h>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/ucontext.h>

#include <x86intrin.h>

#ifndef __x86_64__
# error This test is 64-bit only
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define PAGE_SIZE			(1 << 12)

#define NUM_TILES			8
#define TILE_SIZE			1024
#define XSAVE_SIZE			((NUM_TILES * TILE_SIZE) + PAGE_SIZE)

struct xsave_data {
	u8 area[XSAVE_SIZE];
} __attribute__(aligned(64));

/* Tile configuration associated: */
#define MAX_TILES			16
#define RESERVED_BYTES			14

struct tile_config {
	u8  palette_id;
	u8  start_row;
	u8  reserved[RESERVED_BYTES];
	u16 colsb[MAX_TILES];
	u8  rows[MAX_TILES];
};

struct tile_data {
	u8 data[NUM_TILES * TILE_SIZE];
};

static inline u64 __xgetbv(u32 index)
{
	u32 eax, edx;

	asm volatile("xgetbv;"
		     : "=a" (eax), "=d" (edx)
		     : "c" (index));
	return eax + ((u64)edx << 32);
}

static inline void __cpuid(u32 *eax, u32 *ebx, u32 *ecx, u32 *edx)
{
	asm volatile("cpuid;"
		     : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
		     : "0" (*eax), "2" (*ecx));
}

/* Load tile configuration */
static inline void __ldtilecfg(void *cfg)
{
	asm volatile(".byte 0xc4,0xe2,0x78,0x49,0x00"
		     : : "a"(cfg));
}

/* Load tile data to %tmm0 register only */
static inline void __tileloadd(void *tile)
{
	asm volatile(".byte 0xc4,0xe2,0x7b,0x4b,0x04,0x10"
		     : : "a"(tile), "d"(0));
}

/* Save extended states */
static inline void __xsave(void *buffer, u32 lo, u32 hi)
{
	asm volatile("xsave (%%rdi)"
		     : : "D" (buffer), "a" (lo), "d" (hi)
		     : "memory");
}

/* Restore extended states */
static inline void __xrstor(void *buffer, u32 lo, u32 hi)
{
	asm volatile("xrstor (%%rdi)"
		     : : "D" (buffer), "a" (lo), "d" (hi));
}

/* Release tile states to init values */
static inline void __tilerelease(void)
{
	asm volatile(".byte 0xc4, 0xe2, 0x78, 0x49, 0xc0" ::);
}

static void sethandler(int sig, void (*handler)(int, siginfo_t *, void *),
		       int flags)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO | flags;
	sigemptyset(&sa.sa_mask);
	if (sigaction(sig, &sa, 0))
		err(1, "sigaction");
}

static void clearhandler(int sig)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	if (sigaction(sig, &sa, 0))
		err(1, "sigaction");
}

/* Hardware info check: */

static jmp_buf jmpbuf;
static bool xsave_disabled;

static void handle_sigill(int sig, siginfo_t *si, void *ctx_void)
{
	xsave_disabled = true;
	siglongjmp(jmpbuf, 1);
}

#define XFEATURE_XTILE_CFG      17
#define XFEATURE_XTILE_DATA     18
#define XFEATURE_MASK_XTILE     ((1 << XFEATURE_XTILE_DATA) | \
				 (1 << XFEATURE_XTILE_CFG))

static inline bool check_xsave_supports_xtile(void)
{
	bool supported = false;

	sethandler(SIGILL, handle_sigill, 0);

	if (!sigsetjmp(jmpbuf, 1))
		supported = __xgetbv(0) & XFEATURE_MASK_XTILE;

	clearhandler(SIGILL);
	return supported;
}

struct xtile_hwinfo {
	struct {
		u16 bytes_per_tile;
		u16 bytes_per_row;
		u16 max_names;
		u16 max_rows;
	} spec;

	struct {
		u32 offset;
		u32 size;
	} xsave;
};

static struct xtile_hwinfo xtile;

static bool __enum_xtile_config(void)
{
	u32 eax, ebx, ecx, edx;
	u16 bytes_per_tile;
	bool valid = false;

#define TILE_CPUID			0x1d
#define TILE_PALETTE_CPUID_SUBLEAVE	0x1

	eax = TILE_CPUID;
	ecx = TILE_PALETTE_CPUID_SUBLEAVE;

	__cpuid(&eax, &ebx, &ecx, &edx);
	if (!eax || !ebx || !ecx)
		return valid;

	xtile.spec.max_names = ebx >> 16;
	if (xtile.spec.max_names < NUM_TILES)
		return valid;

	bytes_per_tile = eax >> 16;
	if (bytes_per_tile < TILE_SIZE)
		return valid;

	xtile.spec.bytes_per_row = ebx;
	xtile.spec.max_rows = ecx;
	valid = true;

	return valid;
}

static bool __enum_xsave_tile(void)
{
	u32 eax, ebx, ecx, edx;
	bool valid = false;

#define XSTATE_CPUID			0xd
#define XSTATE_USER_STATE_SUBLEAVE	0x0

	eax = XSTATE_CPUID;
	ecx = XFEATURE_XTILE_DATA;

	__cpuid(&eax, &ebx, &ecx, &edx);
	if (!eax || !ebx)
		return valid;

	xtile.xsave.offset = ebx;
	xtile.xsave.size = eax;
	valid = true;

	return valid;
}

static bool __check_xsave_size(void)
{
	u32 eax, ebx, ecx, edx;
	bool valid = false;

	eax = XSTATE_CPUID;
	ecx = XSTATE_USER_STATE_SUBLEAVE;

	__cpuid(&eax, &ebx, &ecx, &edx);
	if (ebx && ebx <= XSAVE_SIZE)
		valid = true;

	return valid;
}

/*
 * Check the hardware-provided tile state info and cross-check it with the
 * hard-coded values: XSAVE_SIZE, NUM_TILES, and TILE_SIZE.
 */
static int check_xtile_hwinfo(void)
{
	bool success = false;

	if (!__check_xsave_size())
		return success;

	if (!__enum_xsave_tile())
		return success;

	if (!__enum_xtile_config())
		return success;

	if (sizeof(struct tile_data) >= xtile.xsave.size)
		success = true;

	return success;
}

/* The helpers for managing XSAVE buffer and tile states: */

/* Use the uncompacted format without 'init optimization' */
static void save_xdata(void *data)
{
	__xsave(data, -1, -1);
}

static void restore_xdata(void *data)
{
	__xrstor(data, -1, -1);
}

static inline u64 __get_xsave_xstate_bv(void *data)
{
#define XSAVE_HDR_OFFSET	512
	return *(u64 *)(data + XSAVE_HDR_OFFSET);
}

static void set_tilecfg(struct tile_config *cfg)
{
	int i;

	memset(cfg, 0, sizeof(*cfg));
	/* The first implementation has one significant palette with id 1 */
	cfg->palette_id = 1;
	for (i = 0; i < xtile.spec.max_names; i++) {
		cfg->colsb[i] = xtile.spec.bytes_per_row;
		cfg->rows[i] = xtile.spec.max_rows;
	}
}

static void load_tilecfg(struct tile_config *cfg)
{
	__ldtilecfg(cfg);
}

static void make_tiles(void *tiles)
{
	u32 iterations = xtile.xsave.size / sizeof(u32);
	static u32 value = 1;
	u32 *ptr = tiles;
	int i;

	for (i = 0, ptr = tiles; i < iterations; i++, ptr++)
		*ptr  = value;
	value++;
}

/*
 * Initialize the XSAVE buffer:
 *
 * Make sure tile configuration loaded already. Load limited tile data (%tmm0 only)
 * and save all the states. XSAVE buffer is ready to complete tile data.
 */
static void init_xdata(void *data)
{
	struct tile_data tiles;

	make_tiles(&tiles);
	__tileloadd(&tiles);
	__xsave(data, -1, -1);
}

static inline void *__get_xsave_tile_data_addr(void *data)
{
	return data + xtile.xsave.offset;
}

static void copy_tiles_to_xdata(void *xdata, void *tiles)
{
	void *dst = __get_xsave_tile_data_addr(xdata);

	memcpy(dst, tiles, xtile.xsave.size);
}

static int compare_xdata_tiles(void *xdata, void *tiles)
{
	void *tile_data = __get_xsave_tile_data_addr(xdata);

	if (memcmp(tile_data, tiles, xtile.xsave.size))
		return 1;

	return 0;
}

static int nerrs, errs;

/* Testing tile data inheritance */

static void test_tile_data_inheritance(void)
{
	struct xsave_data xdata;
	struct tile_data tiles;
	struct tile_config cfg;
	pid_t child;
	int status;

	set_tilecfg(&cfg);
	load_tilecfg(&cfg);
	init_xdata(&xdata);

	make_tiles(&tiles);
	copy_tiles_to_xdata(&xdata, &tiles);
	restore_xdata(&xdata);

	errs = 0;

	child = fork();
	if (child < 0)
		err(1, "fork");

	if (child == 0) {
		memset(&xdata, 0, sizeof(xdata));
		save_xdata(&xdata);
		if (compare_xdata_tiles(&xdata, &tiles)) {
			printf("[OK]\tchild didn't inherit tile data at fork()\n");
		} else {
			printf("[FAIL]\tchild inherited tile data at fork()\n");
			nerrs++;
		}
		_exit(0);
	}
	wait(&status);
}

static void test_fork(void)
{
	pid_t child;
	int status;

	child = fork();
	if (child < 0)
		err(1, "fork");

	if (child == 0) {
		test_tile_data_inheritance();
		_exit(0);
	}

	wait(&status);
}

/* Context switching test */

#define ITERATIONS			10
#define NUM_THREADS			5

struct futex_info {
	int current;
	int next;
	int *futex;
};

static inline void command_wait(struct futex_info *info, int value)
{
	do {
		sched_yield();
	} while (syscall(SYS_futex, info->futex, FUTEX_WAIT, value, 0, 0, 0));
}

static inline void command_wake(struct futex_info *info, int value)
{
	do {
		*info->futex = value;
		while (!syscall(SYS_futex, info->futex, FUTEX_WAKE, 1, 0, 0, 0))
			sched_yield();
	} while (0);
}

static inline int get_iterative_value(int id)
{
	return ((id << 1) & ~0x1);
}

static inline int get_endpoint_value(int id)
{
	return ((id << 1) | 0x1);
}

static void *check_tiles(void *info)
{
	struct futex_info *finfo = (struct futex_info *)info;
	struct xsave_data xdata;
	struct tile_data tiles;
	struct tile_config cfg;
	int i;

	set_tilecfg(&cfg);
	load_tilecfg(&cfg);
	init_xdata(&xdata);

	make_tiles(&tiles);
	copy_tiles_to_xdata(&xdata, &tiles);
	restore_xdata(&xdata);

	for (i = 0; i < ITERATIONS; i++) {
		command_wait(finfo, get_iterative_value(finfo->current));

		memset(&xdata, 0, sizeof(xdata));
		save_xdata(&xdata);
		errs += compare_xdata_tiles(&xdata, &tiles);

		make_tiles(&tiles);
		copy_tiles_to_xdata(&xdata, &tiles);
		restore_xdata(&xdata);

		command_wake(finfo, get_iterative_value(finfo->next));
	}

	command_wait(finfo, get_endpoint_value(finfo->current));
	__tilerelease();
	return NULL;
}

static int create_children(int num, struct futex_info *finfo)
{
	const int shm_id = shmget(IPC_PRIVATE, sizeof(int), IPC_CREAT | 0666);
	int *futex = shmat(shm_id, NULL, 0);
	pthread_t thread;
	int i;

	for (i = 0; i < num; i++) {
		finfo[i].futex = futex;
		finfo[i].current = i + 1;
		finfo[i].next = (i + 2) % (num + 1);

		if (pthread_create(&thread, NULL, check_tiles, &finfo[i])) {
			err(1, "pthread_create");
			return 1;
		}
	}
	return 0;
}

static void test_context_switch(void)
{
	struct futex_info *finfo;
	cpu_set_t cpuset;
	int i;

	printf("[RUN]\t%u context switches of tile states in %d threads\n",
	       ITERATIONS * NUM_THREADS, NUM_THREADS);

	errs = 0;

	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);
	if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0)
		err(1, "sched_setaffinity to CPU 0");

	finfo = malloc(sizeof(*finfo) * NUM_THREADS);

	if (create_children(NUM_THREADS, finfo))
		return;

	for (i = 0; i < ITERATIONS; i++) {
		command_wake(finfo, get_iterative_value(1));
		command_wait(finfo, get_iterative_value(0));
	}

	for (i = 1; i <= NUM_THREADS; i++)
		command_wake(finfo, get_endpoint_value(i));

	if (errs) {
		printf("[FAIL]\t%u incorrect tile states\n", errs);
		nerrs += errs;
		return;
	}

	printf("[OK]\tall tile states are correct\n");
}

/* Ptrace test */

static inline long get_tile_state(pid_t child, struct iovec *iov)
{
	return ptrace(PTRACE_GETREGSET, child, (u32)NT_X86_XSTATE, iov);
}

static inline long set_tile_state(pid_t child, struct iovec *iov)
{
	return ptrace(PTRACE_SETREGSET, child, (u32)NT_X86_XSTATE, iov);
}

static int write_tile_state(bool load_tile, pid_t child)
{
	struct xsave_data xdata;
	struct tile_data tiles;
	struct iovec iov;

	iov.iov_base = &xdata;
	iov.iov_len = sizeof(xdata);

	if (get_tile_state(child, &iov))
		err(1, "PTRACE_GETREGSET");

	make_tiles(&tiles);
	copy_tiles_to_xdata(&xdata, &tiles);
	if (set_tile_state(child, &iov))
		err(1, "PTRACE_SETREGSET");

	memset(&xdata, 0, sizeof(xdata));
	if (get_tile_state(child, &iov))
		err(1, "PTRACE_GETREGSET");

	if (!load_tile)
		memset(&tiles, 0, sizeof(tiles));

	return compare_xdata_tiles(&xdata, &tiles);
}

static void test_tile_state_write(bool load_tile)
{
	pid_t child;
	int status;

	child = fork();
	if (child < 0)
		err(1, "fork");

	if (child == 0) {
		printf("[RUN]\tPtrace-induced tile state write, ");
		printf("%s tile data loaded\n", load_tile ? "with" : "without");

		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL))
			err(1, "PTRACE_TRACEME");

		if (load_tile) {
			struct tile_config cfg;
			struct tile_data tiles;

			set_tilecfg(&cfg);
			load_tilecfg(&cfg);
			make_tiles(&tiles);
			/* Load only %tmm0 but inducing the #NM */
			__tileloadd(&tiles);
		}

		raise(SIGTRAP);
		_exit(0);
	}

	do {
		wait(&status);
	} while (WSTOPSIG(status) != SIGTRAP);

	errs = write_tile_state(load_tile, child);
	if (errs) {
		nerrs++;
		printf("[FAIL]\t%s write\n", load_tile ? "incorrect" : "unexpected");
	} else {
		printf("[OK]\t%s write\n", load_tile ? "correct" : "no");
	}

	ptrace(PTRACE_DETACH, child, NULL, NULL);
	wait(&status);
}

static void test_ptrace(void)
{
	bool ptracee_loads_tiles;

	ptracee_loads_tiles = true;
	test_tile_state_write(ptracee_loads_tiles);

	ptracee_loads_tiles = false;
	test_tile_state_write(ptracee_loads_tiles);
}

/* Signal handling test */

static int sigtrapped;
struct tile_data sig_tiles, sighdl_tiles;

static void handle_sigtrap(int sig, siginfo_t *info, void *ctx_void)
{
	ucontext_t *uctxt = (ucontext_t *)ctx_void;
	struct xsave_data xdata;
	struct tile_config cfg;
	struct tile_data tiles;
	u64 header;

	header = __get_xsave_xstate_bv((void *)uctxt->uc_mcontext.fpregs);

	if (header & (1 << XFEATURE_XTILE_DATA))
		printf("[FAIL]\ttile data was written in sigframe\n");
	else
		printf("[OK]\ttile data was skipped in sigframe\n");

	set_tilecfg(&cfg);
	load_tilecfg(&cfg);
	init_xdata(&xdata);

	make_tiles(&tiles);
	copy_tiles_to_xdata(&xdata, &tiles);
	restore_xdata(&xdata);

	save_xdata(&xdata);
	if (compare_xdata_tiles(&xdata, &tiles))
		err(1, "tile load file");

	printf("\tsignal handler: load tile data\n");

	sigtrapped = sig;
}

static void test_signal_handling(void)
{
	struct xsave_data xdata = { 0 };
	struct tile_data tiles = { 0 };

	sethandler(SIGTRAP, handle_sigtrap, 0);
	sigtrapped = 0;

	printf("[RUN]\tCheck tile state management in handling signal\n");

	printf("\tbefore signal: initial tile data state\n");

	raise(SIGTRAP);

	if (sigtrapped == 0)
		err(1, "sigtrap");

	save_xdata(&xdata);
	if (compare_xdata_tiles(&xdata, &tiles)) {
		printf("[FAIL]\ttile data was not loaded at sigreturn\n");
		nerrs++;
	} else {
		printf("[OK]\ttile data was re-initialized at sigreturn\n");
	}

	clearhandler(SIGTRAP);
}

int main(void)
{
	/* Check hardware availability at first */

	if (!check_xsave_supports_xtile()) {
		if (xsave_disabled)
			printf("XSAVE disabled.\n");
		else
			printf("Tile data not available.\n");
		return 0;
	}

	if (!check_xtile_hwinfo()) {
		printf("Available tile state size is insufficient to test.\n");
		return 0;
	}

	nerrs = 0;

	test_fork();
	test_context_switch();
	test_ptrace();
	test_signal_handling();

	return nerrs ? 1 : 0;
}
