// SPDX-License-Identifier: GPL-2.0-only
/*
 * xsave/xrstor support.
 *
 * Author: Suresh Siddha <suresh.b.siddha@intel.com>
 */
#include <linux/compat.h>
#include <linux/cpu.h>
#include <linux/mman.h>
#include <linux/pkeys.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>

#include <asm/fpu/api.h>
#include <asm/fpu/internal.h>
#include <asm/fpu/signal.h>
#include <asm/fpu/regset.h>
#include <asm/fpu/xstate.h>

#include <asm/tlbflush.h>
#include <asm/cpufeature.h>
#include <asm/trace/fpu.h>

/*
 * Although we spell it out in here, the Processor Trace
 * xfeature is completely unused.  We use other mechanisms
 * to save/restore PT state in Linux.
 */
static const char *xfeature_names[] =
{
	"x87 floating point registers"	,
	"SSE registers"			,
	"AVX registers"			,
	"MPX bounds registers"		,
	"MPX CSR"			,
	"AVX-512 opmask"		,
	"AVX-512 Hi256"			,
	"AVX-512 ZMM_Hi256"		,
	"Processor Trace (unused)"	,
	"Protection Keys User registers",
	"PASID state",
	"unknown xstate feature"	,
};

struct xfeature_capflag_info {
	int xfeature_idx;
	short cpu_cap;
};

static struct xfeature_capflag_info xfeature_capflags[] __initdata = {
	{ XFEATURE_FP,				X86_FEATURE_FPU },
	{ XFEATURE_SSE,				X86_FEATURE_XMM },
	{ XFEATURE_YMM,				X86_FEATURE_AVX },
	{ XFEATURE_BNDREGS,			X86_FEATURE_MPX },
	{ XFEATURE_BNDCSR,			X86_FEATURE_MPX },
	{ XFEATURE_OPMASK,			X86_FEATURE_AVX512F },
	{ XFEATURE_ZMM_Hi256,			X86_FEATURE_AVX512F },
	{ XFEATURE_Hi16_ZMM,			X86_FEATURE_AVX512F },
	{ XFEATURE_PT_UNIMPLEMENTED_SO_FAR,	X86_FEATURE_INTEL_PT },
	{ XFEATURE_PKRU,			X86_FEATURE_PKU },
	{ XFEATURE_PASID,			X86_FEATURE_ENQCMD },
};

/*
 * This represents the full set of bits that should ever be set in a kernel
 * XSAVE buffer, both supervisor and user xstates.
 */
u64 xfeatures_mask_all __read_mostly;

/*
 * This represents user xstates, a subset of xfeatures_mask_all, saved in a
 * dynamic kernel XSAVE buffer.
 */
u64 xfeatures_mask_user_dynamic __read_mostly;

static unsigned int xstate_offsets[XFEATURE_MAX] = { [ 0 ... XFEATURE_MAX - 1] = -1};
static unsigned int xstate_sizes[XFEATURE_MAX]   = { [ 0 ... XFEATURE_MAX - 1] = -1};
static unsigned int xstate_comp_offsets[XFEATURE_MAX] = { [ 0 ... XFEATURE_MAX - 1] = -1};
static unsigned int xstate_supervisor_only_offsets[XFEATURE_MAX] = { [ 0 ... XFEATURE_MAX - 1] = -1};
/*
 * True if the buffer of the corresponding XFEATURE is located on the next 64
 * byte boundary. Otherwise, it follows the preceding component immediately.
 */
static bool xstate_aligns[XFEATURE_MAX] = { [0 ... XFEATURE_MAX - 1] = false};

/**
 * struct fpu_xstate_buffer_config - xstate per-task buffer configuration
 * @min_size, @max_size:	The size of the kernel buffer. It is variable with the dynamic user
 *				states. Every task has the minimum buffer by default. It can be
 *				expanded to the max size.  The two sizes are the same when using the
 *				standard format.
 * @user_size:			The size of the userspace buffer. The buffer is always in the
 *				standard format. It is used for signal and ptrace frames.
 */
struct fpu_xstate_buffer_config {
	unsigned int min_size, max_size;
	unsigned int user_size;
};

static struct fpu_xstate_buffer_config buffer_config __read_mostly;

unsigned int get_xstate_config(enum xstate_config cfg)
{
	switch (cfg) {
	case XSTATE_MIN_SIZE:
		return buffer_config.min_size;
	case XSTATE_MAX_SIZE:
		return buffer_config.max_size;
	case XSTATE_USER_SIZE:
		return buffer_config.user_size;
	default:
		return 0;
	}
}
EXPORT_SYMBOL_GPL(get_xstate_config);

void set_xstate_config(enum xstate_config cfg, unsigned int value)
{
	switch (cfg) {
	case XSTATE_MIN_SIZE:
		buffer_config.min_size = value;
		break;
	case XSTATE_MAX_SIZE:
		buffer_config.max_size = value;
		break;
	case XSTATE_USER_SIZE:
		buffer_config.user_size = value;
	}
}

/*
 * Return whether the system supports a given xfeature.
 *
 * Also return the name of the (most advanced) feature that the caller requested:
 */
int cpu_has_xfeatures(u64 xfeatures_needed, const char **feature_name)
{
	u64 xfeatures_missing = xfeatures_needed & ~xfeatures_mask_all;

	if (unlikely(feature_name)) {
		long xfeature_idx, max_idx;
		u64 xfeatures_print;
		/*
		 * So we use FLS here to be able to print the most advanced
		 * feature that was requested but is missing. So if a driver
		 * asks about "XFEATURE_MASK_SSE | XFEATURE_MASK_YMM" we'll print the
		 * missing AVX feature - this is the most informative message
		 * to users:
		 */
		if (xfeatures_missing)
			xfeatures_print = xfeatures_missing;
		else
			xfeatures_print = xfeatures_needed;

		xfeature_idx = fls64(xfeatures_print)-1;
		max_idx = ARRAY_SIZE(xfeature_names)-1;
		xfeature_idx = min(xfeature_idx, max_idx);

		*feature_name = xfeature_names[xfeature_idx];
	}

	if (xfeatures_missing)
		return 0;

	return 1;
}
EXPORT_SYMBOL_GPL(cpu_has_xfeatures);

static bool xfeature_is_supervisor(int xfeature_nr)
{
	/*
	 * Extended State Enumeration Sub-leaves (EAX = 0DH, ECX = n, n > 1)
	 * returns ECX[0] set to (1) for a supervisor state, and cleared (0)
	 * for a user state.
	 */
	u32 eax, ebx, ecx, edx;

	cpuid_count(XSTATE_CPUID, xfeature_nr, &eax, &ebx, &ecx, &edx);
	return ecx & 1;
}

static bool xfeature_disable_supported(int xfeature_nr)
{
	u32 eax, ebx, ecx, edx;

	if (!boot_cpu_has(X86_FEATURE_XFD))
		return false;

	/*
	 * If state component 'i' supports xfeature disable (first-use
	 * detection), ECX[2] return 1; otherwise, 0.
	 */
	cpuid_count(XSTATE_CPUID, xfeature_nr, &eax, &ebx, &ecx, &edx);
	return ecx & 4;
}

/**
 * get_xstate_comp_offset() - Find the feature's offset in the compacted format
 * @mask:	This bitmap tells which components reserved in the format.
 * @feature_nr:	The feature number
 *
 * Returns:	The offset value
 */
static unsigned int get_xstate_comp_offset(u64 mask, int feature_nr)
{
	u64 xmask = BIT_ULL(feature_nr + 1) - 1;
	unsigned int next_offset, offset = 0;
	int i;

	if ((mask & xmask) == (xfeatures_mask_all & xmask))
		return xstate_comp_offsets[feature_nr];

	/*
	 * With the given mask, no relevant size is found. Calculate it by summing
	 * up each state size.
	 */

	next_offset = FXSAVE_SIZE + XSAVE_HDR_SIZE;

	for (i = FIRST_EXTENDED_XFEATURE; i <= feature_nr; i++) {
		if (!(mask & BIT_ULL(i)))
			continue;

		offset = xstate_aligns[i] ? ALIGN(next_offset, 64) : next_offset;
		next_offset += xstate_sizes[i];
	}

	return offset;
}

/**
 * get_xstate_size() - calculate an xstate buffer size
 * @mask:	This bitmap tells which components reserved in the buffer.
 *
 * Available once those arrays for the offset, size, and alignment info are set up,
 * by setup_xstate_features().
 *
 * Returns:	The buffer size
 */
unsigned int get_xstate_size(u64 mask)
{
	unsigned int offset;
	int nr;

	if (!mask)
		return 0;

	/*
	 * The minimum buffer size excludes the dynamic user state. When a task
	 * uses the state, the buffer can grow up to the max size.
	 */
	if (mask == (xfeatures_mask_all & ~xfeatures_mask_user_dynamic))
		return get_xstate_config(XSTATE_MIN_SIZE);
	else if (mask == xfeatures_mask_all)
		return get_xstate_config(XSTATE_MAX_SIZE);

	nr = fls64(mask) - 1;

	if (!using_compacted_format())
		return xstate_offsets[nr] + xstate_sizes[nr];

	offset = get_xstate_comp_offset(mask, nr);
	return offset + xstate_sizes[nr];
}

/*
 * When executing XSAVEOPT (or other optimized XSAVE instructions), if
 * a processor implementation detects that an FPU state component is still
 * (or is again) in its initialized state, it may clear the corresponding
 * bit in the header.xfeatures field, and can skip the writeout of registers
 * to the corresponding memory layout.
 *
 * This means that when the bit is zero, the state component might still contain
 * some previous - non-initialized register state.
 *
 * Before writing xstate information to user-space we sanitize those components,
 * to always ensure that the memory layout of a feature will be in the init state
 * if the corresponding header bit is zero. This is to ensure that user-space doesn't
 * see some stale state in the memory layout during signal handling, debugging etc.
 */
void fpstate_sanitize_xstate(struct fpu *fpu)
{
	struct fxregs_state *fx = &fpu->state->fxsave;
	int feature_bit;
	u64 xfeatures;

	if (!use_xsaveopt())
		return;

	xfeatures = fpu->state->xsave.header.xfeatures;

	/*
	 * None of the feature bits are in init state. So nothing else
	 * to do for us, as the memory layout is up to date.
	 */
	if ((xfeatures & xfeatures_mask_all) == xfeatures_mask_all)
		return;

	/*
	 * FP is in init state
	 */
	if (!(xfeatures & XFEATURE_MASK_FP)) {
		fx->cwd = 0x37f;
		fx->swd = 0;
		fx->twd = 0;
		fx->fop = 0;
		fx->rip = 0;
		fx->rdp = 0;
		memset(&fx->st_space[0], 0, 128);
	}

	/*
	 * SSE is in init state
	 */
	if (!(xfeatures & XFEATURE_MASK_SSE))
		memset(&fx->xmm_space[0], 0, 256);

	/*
	 * First two features are FPU and SSE, which above we handled
	 * in a special way already:
	 */
	feature_bit = 0x2;
	xfeatures = (xfeatures_mask_user() & fpu->state_mask & ~xfeatures) >> feature_bit;

	/*
	 * Update all the remaining memory layouts according to their
	 * standard xstate layout, if their header bit is in the init
	 * state:
	 */
	while (xfeatures) {
		if (xfeatures & 0x1) {
			int offset = get_xstate_comp_offset(fpu->state_mask, feature_bit);
			int size = xstate_sizes[feature_bit];

			/*
			 * init_fpstate does not include the dynamic user states
			 * as having initial values with zeros.
			 */
			if (xfeatures_mask_user_dynamic & BIT_ULL(feature_bit))
				memset((void *)fx + offset, 0, size);
			else
				memcpy((void *)fx + offset,
				       (void *)&init_fpstate.xsave + offset,
				       size);
		}

		xfeatures >>= 1;
		feature_bit++;
	}
}

/*
 * Enable the extended processor state save/restore feature.
 * Called once per CPU onlining.
 */
void fpu__init_cpu_xstate(void)
{
	u64 unsup_bits;

	if (!boot_cpu_has(X86_FEATURE_XSAVE) || !xfeatures_mask_all)
		return;
	/*
	 * Unsupported supervisor xstates should not be found in
	 * the xfeatures mask.
	 */
	unsup_bits = xfeatures_mask_all & XFEATURE_MASK_SUPERVISOR_UNSUPPORTED;
	WARN_ONCE(unsup_bits, "x86/fpu: Found unsupported supervisor xstates: 0x%llx\n",
		  unsup_bits);

	xfeatures_mask_all &= ~XFEATURE_MASK_SUPERVISOR_UNSUPPORTED;

	cr4_set_bits(X86_CR4_OSXSAVE);

	/*
	 * XCR_XFEATURE_ENABLED_MASK (aka. XCR0) sets user features
	 * managed by XSAVE{C, OPT, S} and XRSTOR{S}.  Only XSAVE user
	 * states can be set here.
	 */
	xsetbv(XCR_XFEATURE_ENABLED_MASK, xfeatures_mask_user());

	/*
	 * MSR_IA32_XSS sets supervisor states managed by XSAVES.
	 */
	if (boot_cpu_has(X86_FEATURE_XSAVES)) {
		wrmsrl(MSR_IA32_XSS, xfeatures_mask_supervisor() |
				     xfeatures_mask_supervisor_dynamic());
	}

	if (boot_cpu_has(X86_FEATURE_XFD))
		xdisable_setbits(xfirstuse_enabled());
}

static bool xfeature_enabled(enum xfeature xfeature)
{
	return xfeatures_mask_all & BIT_ULL(xfeature);
}

/*
 * Record the offsets and sizes of various xstates contained
 * in the XSAVE state memory layout.
 */
static void __init setup_xstate_features(void)
{
	u32 eax, ebx, ecx, edx, i;
	/* start at the beginnning of the "extended state" */
	unsigned int last_good_offset = offsetof(struct xregs_state,
						 extended_state_area);
	/*
	 * The FP xstates and SSE xstates are legacy states. They are always
	 * in the fixed offsets in the xsave area in either compacted form
	 * or standard form.
	 */
	xstate_offsets[XFEATURE_FP]	= 0;
	xstate_sizes[XFEATURE_FP]	= offsetof(struct fxregs_state,
						   xmm_space);
	xstate_aligns[XFEATURE_FP]	= true;

	xstate_offsets[XFEATURE_SSE]	= xstate_sizes[XFEATURE_FP];
	xstate_sizes[XFEATURE_SSE]	= sizeof_field(struct fxregs_state,
						       xmm_space);
	xstate_aligns[XFEATURE_SSE]	= true;

	for (i = FIRST_EXTENDED_XFEATURE; i < XFEATURE_MAX; i++) {
		if (!xfeature_enabled(i))
			continue;

		cpuid_count(XSTATE_CPUID, i, &eax, &ebx, &ecx, &edx);

		xstate_sizes[i] = eax;

		/*
		 * If an xfeature is supervisor state, the offset in EBX is
		 * invalid, leave it to -1.
		 */
		if (xfeature_is_supervisor(i))
			continue;

		xstate_offsets[i] = ebx;
		xstate_aligns[i] = (ecx & 2) ? true : false;

		/*
		 * In our xstate size checks, we assume that the highest-numbered
		 * xstate feature has the highest offset in the buffer.  Ensure
		 * it does.
		 */
		WARN_ONCE(last_good_offset > xstate_offsets[i],
			  "x86/fpu: misordered xstate at %d\n", last_good_offset);

		last_good_offset = xstate_offsets[i];
	}
}

static void __init print_xstate_feature(u64 xstate_mask)
{
	const char *feature_name;

	if (cpu_has_xfeatures(xstate_mask, &feature_name))
		pr_info("x86/fpu: Supporting XSAVE feature 0x%03Lx: '%s'\n", xstate_mask, feature_name);
}

/*
 * Print out all the supported xstate features:
 */
static void __init print_xstate_features(void)
{
	print_xstate_feature(XFEATURE_MASK_FP);
	print_xstate_feature(XFEATURE_MASK_SSE);
	print_xstate_feature(XFEATURE_MASK_YMM);
	print_xstate_feature(XFEATURE_MASK_BNDREGS);
	print_xstate_feature(XFEATURE_MASK_BNDCSR);
	print_xstate_feature(XFEATURE_MASK_OPMASK);
	print_xstate_feature(XFEATURE_MASK_ZMM_Hi256);
	print_xstate_feature(XFEATURE_MASK_Hi16_ZMM);
	print_xstate_feature(XFEATURE_MASK_PKRU);
	print_xstate_feature(XFEATURE_MASK_PASID);
}

/*
 * This check is important because it is easy to get XSTATE_*
 * confused with XSTATE_BIT_*.
 */
#define CHECK_XFEATURE(nr) do {		\
	WARN_ON(nr < FIRST_EXTENDED_XFEATURE);	\
	WARN_ON(nr >= XFEATURE_MAX);	\
} while (0)

/*
 * We could cache this like xstate_size[], but we only use
 * it here, so it would be a waste of space.
 */
static int xfeature_is_aligned(int xfeature_nr)
{
	u32 eax, ebx, ecx, edx;

	CHECK_XFEATURE(xfeature_nr);

	if (!xfeature_enabled(xfeature_nr)) {
		WARN_ONCE(1, "Checking alignment of disabled xfeature %d\n",
			  xfeature_nr);
		return 0;
	}

	cpuid_count(XSTATE_CPUID, xfeature_nr, &eax, &ebx, &ecx, &edx);
	/*
	 * The value returned by ECX[1] indicates the alignment
	 * of state component 'i' when the compacted format
	 * of the extended region of an XSAVE area is used:
	 */
	return !!(ecx & 2);
}

/*
 * This function sets up offsets and sizes of all extended states in
 * xsave area. This supports both standard format and compacted format
 * of the xsave area.
 */
static void __init setup_xstate_comp_offsets(void)
{
	unsigned int next_offset;
	int i;

	/*
	 * The FP xstates and SSE xstates are legacy states. They are always
	 * in the fixed offsets in the xsave area in either compacted form
	 * or standard form.
	 */
	xstate_comp_offsets[XFEATURE_FP] = 0;
	xstate_comp_offsets[XFEATURE_SSE] = offsetof(struct fxregs_state,
						     xmm_space);

	if (!boot_cpu_has(X86_FEATURE_XSAVES)) {
		for (i = FIRST_EXTENDED_XFEATURE; i < XFEATURE_MAX; i++) {
			if (xfeature_enabled(i))
				xstate_comp_offsets[i] = xstate_offsets[i];
		}
		return;
	}

	next_offset = FXSAVE_SIZE + XSAVE_HDR_SIZE;

	for (i = FIRST_EXTENDED_XFEATURE; i < XFEATURE_MAX; i++) {
		if (!xfeature_enabled(i))
			continue;

		if (xfeature_is_aligned(i))
			next_offset = ALIGN(next_offset, 64);

		xstate_comp_offsets[i] = next_offset;
		next_offset += xstate_sizes[i];
	}
}

/*
 * Setup offsets of a supervisor-state-only XSAVES buffer:
 *
 * The offsets stored in xstate_comp_offsets[] only work for one specific
 * value of the Requested Feature BitMap (RFBM).  In cases where a different
 * RFBM value is used, a different set of offsets is required.  This set of
 * offsets is for when RFBM=xfeatures_mask_supervisor().
 */
static void __init setup_supervisor_only_offsets(void)
{
	unsigned int next_offset;
	int i;

	next_offset = FXSAVE_SIZE + XSAVE_HDR_SIZE;

	for (i = FIRST_EXTENDED_XFEATURE; i < XFEATURE_MAX; i++) {
		if (!xfeature_enabled(i) || !xfeature_is_supervisor(i))
			continue;

		if (xfeature_is_aligned(i))
			next_offset = ALIGN(next_offset, 64);

		xstate_supervisor_only_offsets[i] = next_offset;
		next_offset += xstate_sizes[i];
	}
}

/*
 * Print out xstate component offsets and sizes
 */
static void __init print_xstate_offset_size(void)
{
	int i;

	for (i = FIRST_EXTENDED_XFEATURE; i < XFEATURE_MAX; i++) {
		if (!xfeature_enabled(i))
			continue;
		pr_info("x86/fpu: xstate_offset[%d]: %4d, xstate_sizes[%d]: %4d (%s)\n",
			i, xstate_comp_offsets[i], i, xstate_sizes[i],
			(xfeatures_mask_user_dynamic & BIT_ULL(i)) ? "on-demand" : "default");
	}
}

/*
 * All supported features have either init state all zeros or are
 * handled in setup_init_fpu() individually. This is an explicit
 * feature list and does not use XFEATURE_MASK*SUPPORTED to catch
 * newly added supported features at build time and make people
 * actually look at the init state for the new feature.
 */
#define XFEATURES_INIT_FPSTATE_HANDLED		\
	(XFEATURE_MASK_FP |			\
	 XFEATURE_MASK_SSE |			\
	 XFEATURE_MASK_YMM |			\
	 XFEATURE_MASK_OPMASK |			\
	 XFEATURE_MASK_ZMM_Hi256 |		\
	 XFEATURE_MASK_Hi16_ZMM	 |		\
	 XFEATURE_MASK_PKRU |			\
	 XFEATURE_MASK_BNDREGS |		\
	 XFEATURE_MASK_BNDCSR |			\
	 XFEATURE_MASK_PASID)

/*
 * setup the xstate image representing the init state
 */
static void __init setup_init_fpu_buf(void)
{
	static int on_boot_cpu __initdata = 1;
	u64 mask;

	BUILD_BUG_ON((XFEATURE_MASK_USER_SUPPORTED |
		      XFEATURE_MASK_SUPERVISOR_SUPPORTED) !=
		     XFEATURES_INIT_FPSTATE_HANDLED);

	WARN_ON_FPU(!on_boot_cpu);
	on_boot_cpu = 0;

	if (!boot_cpu_has(X86_FEATURE_XSAVE))
		return;

	setup_xstate_features();
	print_xstate_features();

	/*
	 * Exclude the dynamic user states as they are large but having
	 * initial values with zeros.
	 */
	mask = xfeatures_mask_all & ~xfeatures_mask_user_dynamic;

	if (boot_cpu_has(X86_FEATURE_XSAVES))
		fpstate_init_xstate(&init_fpstate.xsave, mask);

	/*
	 * Init all the features state with header.xfeatures being 0x0
	 */
	copy_kernel_to_xregs_booting(&init_fpstate.xsave);

	/*
	 * All components are now in init state. Read the state back so
	 * that init_fpstate contains all non-zero init state. This only
	 * works with XSAVE, but not with XSAVEOPT and XSAVES because
	 * those use the init optimization which skips writing data for
	 * components in init state.
	 *
	 * XSAVE could be used, but that would require to reshuffle the
	 * data when XSAVES is available because XSAVES uses xstate
	 * compaction. But doing so is a pointless exercise because most
	 * components have an all zeros init state except for the legacy
	 * ones (FP and SSE). Those can be saved with FXSAVE into the
	 * legacy area. Adding new features requires to ensure that init
	 * state is all zeroes or if not to add the necessary handling
	 * here.
	 */
	fxsave(&init_fpstate.fxsave);
}

static int xfeature_uncompacted_offset(int xfeature_nr)
{
	u32 eax, ebx, ecx, edx;

	/*
	 * Only XSAVES supports supervisor states and it uses compacted
	 * format. Checking a supervisor state's uncompacted offset is
	 * an error.
	 */
	if (XFEATURE_MASK_SUPERVISOR_ALL & BIT_ULL(xfeature_nr)) {
		WARN_ONCE(1, "No fixed offset for xstate %d\n", xfeature_nr);
		return -1;
	}

	CHECK_XFEATURE(xfeature_nr);
	cpuid_count(XSTATE_CPUID, xfeature_nr, &eax, &ebx, &ecx, &edx);
	return ebx;
}

int xfeature_size(int xfeature_nr)
{
	u32 eax, ebx, ecx, edx;

	CHECK_XFEATURE(xfeature_nr);
	cpuid_count(XSTATE_CPUID, xfeature_nr, &eax, &ebx, &ecx, &edx);
	return eax;
}

/*
 * 'XSAVES' implies two different things:
 * 1. saving of supervisor/system state
 * 2. using the compacted format
 *
 * Use this function when dealing with the compacted format so
 * that it is obvious which aspect of 'XSAVES' is being handled
 * by the calling code.
 */
int using_compacted_format(void)
{
	return boot_cpu_has(X86_FEATURE_XSAVES);
}

/* Validate an xstate header supplied by userspace (ptrace or sigreturn) */
int validate_user_xstate_header(const struct xstate_header *hdr)
{
	/* No unknown or supervisor features may be set */
	if (hdr->xfeatures & ~xfeatures_mask_user())
		return -EINVAL;

	/* Userspace must use the uncompacted format */
	if (hdr->xcomp_bv)
		return -EINVAL;

	/*
	 * If 'reserved' is shrunken to add a new field, make sure to validate
	 * that new field here!
	 */
	BUILD_BUG_ON(sizeof(hdr->reserved) != 48);

	/* No reserved bits may be set */
	if (memchr_inv(hdr->reserved, 0, sizeof(hdr->reserved)))
		return -EINVAL;

	return 0;
}

static void __xstate_dump_leaves(void)
{
	int i;
	u32 eax, ebx, ecx, edx;
	static int should_dump = 1;

	if (!should_dump)
		return;
	should_dump = 0;
	/*
	 * Dump out a few leaves past the ones that we support
	 * just in case there are some goodies up there
	 */
	for (i = 0; i < XFEATURE_MAX + 10; i++) {
		cpuid_count(XSTATE_CPUID, i, &eax, &ebx, &ecx, &edx);
		pr_warn("CPUID[%02x, %02x]: eax=%08x ebx=%08x ecx=%08x edx=%08x\n",
			XSTATE_CPUID, i, eax, ebx, ecx, edx);
	}
}

#define XSTATE_WARN_ON(x) do {							\
	if (WARN_ONCE(x, "XSAVE consistency problem, dumping leaves")) {	\
		__xstate_dump_leaves();						\
	}									\
} while (0)

#define XCHECK_SZ(sz, nr, nr_macro, __struct) do {			\
	if ((nr == nr_macro) &&						\
	    WARN_ONCE(sz != sizeof(__struct),				\
		"%s: struct is %zu bytes, cpu state %d bytes\n",	\
		__stringify(nr_macro), sizeof(__struct), sz)) {		\
		__xstate_dump_leaves();					\
	}								\
} while (0)

/*
 * We have a C struct for each 'xstate'.  We need to ensure
 * that our software representation matches what the CPU
 * tells us about the state's size.
 */
static void check_xstate_against_struct(int nr)
{
	/*
	 * Ask the CPU for the size of the state.
	 */
	int sz = xfeature_size(nr);
	/*
	 * Match each CPU state with the corresponding software
	 * structure.
	 */
	XCHECK_SZ(sz, nr, XFEATURE_YMM,       struct ymmh_struct);
	XCHECK_SZ(sz, nr, XFEATURE_BNDREGS,   struct mpx_bndreg_state);
	XCHECK_SZ(sz, nr, XFEATURE_BNDCSR,    struct mpx_bndcsr_state);
	XCHECK_SZ(sz, nr, XFEATURE_OPMASK,    struct avx_512_opmask_state);
	XCHECK_SZ(sz, nr, XFEATURE_ZMM_Hi256, struct avx_512_zmm_uppers_state);
	XCHECK_SZ(sz, nr, XFEATURE_Hi16_ZMM,  struct avx_512_hi16_state);
	XCHECK_SZ(sz, nr, XFEATURE_PKRU,      struct pkru_state);
	XCHECK_SZ(sz, nr, XFEATURE_PASID,     struct ia32_pasid_state);

	/*
	 * Make *SURE* to add any feature numbers in below if
	 * there are "holes" in the xsave state component
	 * numbers.
	 */
	if ((nr < XFEATURE_YMM) ||
	    (nr >= XFEATURE_MAX) ||
	    (nr == XFEATURE_PT_UNIMPLEMENTED_SO_FAR) ||
	    ((nr >= XFEATURE_RSRVD_COMP_11) && (nr <= XFEATURE_LBR))) {
		WARN_ONCE(1, "no structure for xstate: %d\n", nr);
		XSTATE_WARN_ON(1);
	}
}

/*
 * Calculate the xstate per-task buffer sizes -- maximum and minimum.
 *
 * And record the minimum. Also double-check the maximum against what
 * the cpu told.
 *
 * Dynamic user states are stored in this buffer. They account for the
 * delta between the maximum and the minimum.
 *
 * Dynamic supervisor XSAVE features allocate their own buffers and are
 * not covered by these checks.
 */
static void calculate_xstate_sizes(void)
{
	int paranoid_min_size = FXSAVE_SIZE + XSAVE_HDR_SIZE;
	int paranoid_max_size = FXSAVE_SIZE + XSAVE_HDR_SIZE;
	int i;

	for (i = FIRST_EXTENDED_XFEATURE; i < XFEATURE_MAX; i++) {
		bool user_dynamic;

		if (!xfeature_enabled(i))
			continue;

		user_dynamic = (xfeatures_mask_user_dynamic & BIT_ULL(i)) ? true : false;

		check_xstate_against_struct(i);
		/*
		 * Supervisor state components can be managed only by
		 * XSAVES, which is compacted-format only.
		 */
		if (!using_compacted_format())
			XSTATE_WARN_ON(xfeature_is_supervisor(i));

		/* Align from the end of the previous feature */
		if (xfeature_is_aligned(i)) {
			paranoid_max_size = ALIGN(paranoid_max_size, 64);
			if (!user_dynamic)
				paranoid_min_size = ALIGN(paranoid_min_size, 64);
		}
		/*
		 * The offset of a given state in the non-compacted
		 * format is given to us in a CPUID leaf.  We check
		 * them for being ordered (increasing offsets) in
		 * setup_xstate_features().
		 */
		if (!using_compacted_format()) {
			paranoid_max_size = xfeature_uncompacted_offset(i);
			if (!user_dynamic)
				paranoid_min_size = xfeature_uncompacted_offset(i);
		}
		/*
		 * The compacted-format offset always depends on where
		 * the previous state ended.
		 */
		paranoid_max_size += xfeature_size(i);
		if (!user_dynamic)
			paranoid_min_size += xfeature_size(i);
	}
	XSTATE_WARN_ON(paranoid_max_size != get_xstate_config(XSTATE_MAX_SIZE));
	set_xstate_config(XSTATE_MIN_SIZE, paranoid_min_size);
}


/*
 * Get total size of enabled xstates in XCR0 | IA32_XSS.
 *
 * Note the SDM's wording here.  "sub-function 0" only enumerates
 * the size of the *user* states.  If we use it to size a buffer
 * that we use 'XSAVES' on, we could potentially overflow the
 * buffer because 'XSAVES' saves system states too.
 */
static unsigned int __init get_xsaves_size(void)
{
	unsigned int eax, ebx, ecx, edx;
	/*
	 * - CPUID function 0DH, sub-function 1:
	 *    EBX enumerates the size (in bytes) required by
	 *    the XSAVES instruction for an XSAVE area
	 *    containing all the state components
	 *    corresponding to bits currently set in
	 *    XCR0 | IA32_XSS.
	 */
	cpuid_count(XSTATE_CPUID, 1, &eax, &ebx, &ecx, &edx);
	return ebx;
}

/*
 * Get the total size of the enabled xstates without the dynamic supervisor
 * features.
 */
static unsigned int __init get_xsaves_size_no_dynamic(void)
{
	u64 mask = xfeatures_mask_supervisor_dynamic();
	unsigned int size;

	if (!mask)
		return get_xsaves_size();

	/* Disable dynamic features. */
	wrmsrl(MSR_IA32_XSS, xfeatures_mask_supervisor());

	/*
	 * Ask the hardware what size is required of the buffer.
	 * This is the size required for the task->fpu buffer.
	 */
	size = get_xsaves_size();

	/* Re-enable dynamic features so XSAVES will work on them again. */
	wrmsrl(MSR_IA32_XSS, xfeatures_mask_supervisor() | mask);

	return size;
}

static unsigned int __init get_xsave_size(void)
{
	unsigned int eax, ebx, ecx, edx;
	/*
	 * - CPUID function 0DH, sub-function 0:
	 *    EBX enumerates the size (in bytes) required by
	 *    the XSAVE instruction for an XSAVE area
	 *    containing all the *user* state components
	 *    corresponding to bits currently set in XCR0.
	 */
	cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);
	return ebx;
}

/*
 * Will the runtime-enumerated 'xstate_size' fit in the init
 * task's statically-allocated buffer?
 */
static bool is_supported_xstate_size(unsigned int test_xstate_size)
{
	if (test_xstate_size <= sizeof(union fpregs_state))
		return true;

	pr_warn("x86/fpu: xstate buffer too small (%zu < %d), disabling xsave\n",
			sizeof(union fpregs_state), test_xstate_size);
	return false;
}

static int __init init_xstate_size(void)
{
	/* Recompute the context size for enabled features: */
	unsigned int possible_xstate_size;
	unsigned int xsave_size;

	xsave_size = get_xsave_size();

	if (boot_cpu_has(X86_FEATURE_XSAVES))
		possible_xstate_size = get_xsaves_size_no_dynamic();
	else
		possible_xstate_size = xsave_size;

	/*
	 * The size accounts for all the possible states reserved in the
	 * per-task buffer.  Set the maximum with this value.
	 */
	set_xstate_config(XSTATE_MAX_SIZE, possible_xstate_size);

	/*
	 * Calculate and double-check the maximum size. Calculate and record
	 * the minimum size.
	 */
	calculate_xstate_sizes();

	/* Ensure the minimum size fits in the statically-alocated buffer: */
	if (!is_supported_xstate_size(get_xstate_config(XSTATE_MIN_SIZE)))
		return -EINVAL;

	/*
	 * User space is always in standard format.
	 */
	set_xstate_config(XSTATE_USER_SIZE, xsave_size);
	return 0;
}

/*
 * We enabled the XSAVE hardware, but something went wrong and
 * we can not use it.  Disable it.
 */
static void fpu__init_disable_system_xstate(void)
{
	xfeatures_mask_all = 0;
	xfeatures_mask_user_dynamic = 0;
	cr4_clear_bits(X86_CR4_OSXSAVE);
	setup_clear_cpu_cap(X86_FEATURE_XSAVE);
}

/*
 * Enable and initialize the xsave feature.
 * Called once per system bootup.
 */
void __init fpu__init_system_xstate(void)
{
	unsigned int eax, ebx, ecx, edx;
	static int on_boot_cpu __initdata = 1;
	int err;
	int i;

	WARN_ON_FPU(!on_boot_cpu);
	on_boot_cpu = 0;

	if (!boot_cpu_has(X86_FEATURE_FPU)) {
		pr_info("x86/fpu: No FPU detected\n");
		return;
	}

	if (!boot_cpu_has(X86_FEATURE_XSAVE)) {
		pr_info("x86/fpu: x87 FPU will use %s\n",
			boot_cpu_has(X86_FEATURE_FXSR) ? "FXSAVE" : "FSAVE");
		return;
	}

	if (boot_cpu_data.cpuid_level < XSTATE_CPUID) {
		WARN_ON_FPU(1);
		return;
	}

	/*
	 * Find user xstates supported by the processor.
	 */
	cpuid_count(XSTATE_CPUID, 0, &eax, &ebx, &ecx, &edx);
	xfeatures_mask_all = eax + ((u64)edx << 32);

	/*
	 * Find supervisor xstates supported by the processor.
	 */
	cpuid_count(XSTATE_CPUID, 1, &eax, &ebx, &ecx, &edx);
	xfeatures_mask_all |= ecx + ((u64)edx << 32);

	if ((xfeatures_mask_user() & XFEATURE_MASK_FPSSE) != XFEATURE_MASK_FPSSE) {
		/*
		 * This indicates that something really unexpected happened
		 * with the enumeration.  Disable XSAVE and try to continue
		 * booting without it.  This is too early to BUG().
		 */
		pr_err("x86/fpu: FP/SSE not present amongst the CPU's xstate features: 0x%llx.\n",
		       xfeatures_mask_all);
		goto out_disable;
	}

	/*
	 * Cross-check XSAVE feature with CPU capability flag. Clear the
	 * mask bit for disabled features.
	 */
	for (i = 0; i < ARRAY_SIZE(xfeature_capflags); i++) {
		short cpu_cap = xfeature_capflags[i].cpu_cap;
		int idx = xfeature_capflags[i].xfeature_idx;

		if (!boot_cpu_has(cpu_cap))
			xfeatures_mask_all &= ~BIT_ULL(idx);
	}

	xfeatures_mask_all &= fpu__get_supported_xfeatures_mask();
	xfeatures_mask_user_dynamic = 0;

	for (i = FIRST_EXTENDED_XFEATURE; i < XFEATURE_MAX; i++) {
		u64 feature_mask = BIT_ULL(i);

		if (!(xfeatures_mask_user() & feature_mask))
			continue;

		if (xfeature_disable_supported(i))
			xfeatures_mask_user_dynamic |= feature_mask;
	}

	/* Enable xstate instructions to be able to continue with initialization: */
	fpu__init_cpu_xstate();
	err = init_xstate_size();
	if (err)
		goto out_disable;

	/* Make sure init_task does not include the dynamic user states. */
	current->thread.fpu.state_mask = (xfeatures_mask_all & ~xfeatures_mask_user_dynamic);

	/*
	 * Update info used for ptrace frames; use standard-format size and no
	 * supervisor xstates:
	 */
	update_regset_xstate_info(get_xstate_config(XSTATE_USER_SIZE), xfeatures_mask_user());

	fpu__init_prepare_fx_sw_frame();
	setup_init_fpu_buf();
	setup_xstate_comp_offsets();
	setup_supervisor_only_offsets();
	print_xstate_offset_size();

	pr_info("x86/fpu: Enabled xstate features 0x%llx, context size is %d bytes, using '%s' format.\n",
		xfeatures_mask_all,
		get_xstate_config(XSTATE_MAX_SIZE),
		boot_cpu_has(X86_FEATURE_XSAVES) ? "compacted" : "standard");
	return;

out_disable:
	/* something went wrong, try to boot without any XSAVE support */
	fpu__init_disable_system_xstate();
}

/*
 * Restore minimal FPU state after suspend:
 */
void fpu__resume_cpu(void)
{
	/*
	 * Restore XCR0 on xsave capable CPUs:
	 */
	if (boot_cpu_has(X86_FEATURE_XSAVE))
		xsetbv(XCR_XFEATURE_ENABLED_MASK, xfeatures_mask_user());

	/*
	 * Restore IA32_XSS. The same CPUID bit enumerates support
	 * of XSAVES and MSR_IA32_XSS.
	 */
	if (boot_cpu_has(X86_FEATURE_XSAVES)) {
		wrmsrl(MSR_IA32_XSS, xfeatures_mask_supervisor()  |
				     xfeatures_mask_supervisor_dynamic());
	}

	if (boot_cpu_has(X86_FEATURE_XFD))
		xdisable_setbits(xfirstuse_not_detected(&current->thread.fpu));
}

/*
 * Given an xstate feature nr, calculate where in the xsave
 * buffer the state is.  Callers should ensure that the buffer
 * is valid.
 *
 * @fpu: If NULL, use init_fpstate
 */
static void *__raw_xsave_addr(struct fpu *fpu, int xfeature_nr)
{
	void *xsave;

	if (!xfeature_enabled(xfeature_nr))
		goto not_found;
	else if (!fpu)
		xsave = &init_fpstate.xsave;
	else if (!(fpu->state_mask & BIT_ULL(xfeature_nr)))
		goto not_found;
	else
		xsave = &fpu->state->xsave;

	return xsave + get_xstate_comp_offset(fpu->state_mask, xfeature_nr);

not_found:
	WARN_ON_FPU(1);
	return NULL;
}
/*
 * Given the xsave area and a state inside, this function returns the
 * address of the state.
 *
 * This is the API that is called to get xstate address in either
 * standard format or compacted format of xsave area.
 *
 * Note that if there is no data for the field in the xsave buffer
 * this will return NULL.
 *
 * Inputs:
 *	fpu: the thread's FPU data to reference xstate buffer(s).
 *	     (A null pointer parameter indicates init_fpstate.)
 *	xfeature_nr: state which is defined in xsave.h (e.g. XFEATURE_FP,
 *	XFEATURE_SSE, etc...)
 * Output:
 *	address of the state in the xsave area, or NULL if the
 *	field is not present in the xsave buffer.
 */
void *get_xsave_addr(struct fpu *fpu, int xfeature_nr)
{
	struct xregs_state *xsave;

	/*
	 * Do we even *have* xsave state?
	 */
	if (!boot_cpu_has(X86_FEATURE_XSAVE))
		return NULL;

	/*
	 * We should not ever be requesting features that we
	 * have not enabled.
	 */
	WARN_ONCE(!(xfeatures_mask_all & BIT_ULL(xfeature_nr)),
		  "get of unsupported state");

	if (fpu)
		xsave = &fpu->state->xsave;
	else
		xsave = &init_fpstate.xsave;

	/*
	 * This assumes the last 'xsave*' instruction to
	 * have requested that 'xfeature_nr' be saved.
	 * If it did not, we might be seeing and old value
	 * of the field in the buffer.
	 *
	 * This can happen because the last 'xsave' did not
	 * request that this feature be saved (unlikely)
	 * or because the "init optimization" caused it
	 * to not be saved.
	 */
	if (!(xsave->header.xfeatures & BIT_ULL(xfeature_nr)))
		return NULL;

	return __raw_xsave_addr(fpu, xfeature_nr);
}
EXPORT_SYMBOL_GPL(get_xsave_addr);

/*
 * This wraps up the common operations that need to occur when retrieving
 * data from xsave state.  It first ensures that the current task was
 * using the FPU and retrieves the data in to a buffer.  It then calculates
 * the offset of the requested field in the buffer.
 *
 * This function is safe to call whether the FPU is in use or not.
 *
 * Note that this only works on the current task.
 *
 * Inputs:
 *	@xfeature_nr: state which is defined in xsave.h (e.g. XFEATURE_FP,
 *	XFEATURE_SSE, etc...)
 * Output:
 *	address of the state in the xsave area or NULL if the state
 *	is not present or is in its 'init state'.
 */
const void *get_xsave_field_ptr(int xfeature_nr)
{
	struct fpu *fpu = &current->thread.fpu;

	/*
	 * fpu__save() takes the CPU's xstate registers
	 * and saves them off to the 'fpu memory buffer.
	 */
	fpu__save(fpu);

	return get_xsave_addr(fpu, xfeature_nr);
}

#ifdef CONFIG_ARCH_HAS_PKEYS

/*
 * This will go out and modify PKRU register to set the access
 * rights for @pkey to @init_val.
 */
int arch_set_user_pkey_access(struct task_struct *tsk, int pkey,
		unsigned long init_val)
{
	u32 old_pkru;
	int pkey_shift = (pkey * PKRU_BITS_PER_PKEY);
	u32 new_pkru_bits = 0;

	/*
	 * This check implies XSAVE support.  OSPKE only gets
	 * set if we enable XSAVE and we enable PKU in XCR0.
	 */
	if (!boot_cpu_has(X86_FEATURE_OSPKE))
		return -EINVAL;

	/*
	 * This code should only be called with valid 'pkey'
	 * values originating from in-kernel users.  Complain
	 * if a bad value is observed.
	 */
	WARN_ON_ONCE(pkey >= arch_max_pkey());

	/* Set the bits we need in PKRU:  */
	if (init_val & PKEY_DISABLE_ACCESS)
		new_pkru_bits |= PKRU_AD_BIT;
	if (init_val & PKEY_DISABLE_WRITE)
		new_pkru_bits |= PKRU_WD_BIT;

	/* Shift the bits in to the correct place in PKRU for pkey: */
	new_pkru_bits <<= pkey_shift;

	/* Get old PKRU and mask off any old bits in place: */
	old_pkru = read_pkru();
	old_pkru &= ~((PKRU_AD_BIT|PKRU_WD_BIT) << pkey_shift);

	/* Write old part along with new part: */
	write_pkru(old_pkru | new_pkru_bits);

	return 0;
}
#endif /* ! CONFIG_ARCH_HAS_PKEYS */

/*
 * Weird legacy quirk: SSE and YMM states store information in the
 * MXCSR and MXCSR_FLAGS fields of the FP area. That means if the FP
 * area is marked as unused in the xfeatures header, we need to copy
 * MXCSR and MXCSR_FLAGS if either SSE or YMM are in use.
 */
static inline bool xfeatures_mxcsr_quirk(u64 xfeatures)
{
	if (!(xfeatures & (XFEATURE_MASK_SSE|XFEATURE_MASK_YMM)))
		return false;

	if (xfeatures & XFEATURE_MASK_FP)
		return false;

	return true;
}

void free_xstate_buffer(struct fpu *fpu)
{
	/* Free up only the dynamically-allocated memory. */
	if (fpu->state != &fpu->__default_state)
		vfree(fpu->state);
}

/**
 * alloc_xstate_buffer() - allocate an xstate buffer with the size calculated based on @mask.
 *
 * @fpu:	A struct fpu * pointer
 * @mask:	The bitmap tells which components to be reserved in the new buffer.
 *
 * Use vmalloc() simply here. If the task with a vmalloc()-allocated buffer tends
 * to terminate quickly, vfree()-induced IPIs may be a concern. Caching may be
 * helpful for this. But the task with large state is likely to live longer.
 *
 * Also, this method does not shrink or reclaim the buffer.
 *
 * Returns 0 on success, -ENOMEM on allocation error.
 */
int alloc_xstate_buffer(struct fpu *fpu, u64 mask)
{
	union fpregs_state *state;
	unsigned int oldsz, newsz;
	u64 state_mask;

	state_mask = fpu->state_mask | mask;

	oldsz = get_xstate_size(fpu->state_mask);
	newsz = get_xstate_size(state_mask);

	if (oldsz >= newsz)
		return 0;

	state = vzalloc(newsz);
	if (!state) {
		/*
		 * When allocation requested from #NM, the error code may not be
		 * populated well. Then, this tracepoint is useful for providing
		 * the failure context.
		 */
		trace_x86_fpu_xstate_alloc_failed(fpu);
		return -ENOMEM;
	}

	if (using_compacted_format())
		fpstate_init_xstate(&state->xsave, state_mask);

	/*
	 * As long as the register state is intact, save the xstate in the new buffer
	 * at the next context copy/switch or potentially ptrace-driven xstate writing.
	 */

	free_xstate_buffer(fpu);
	fpu->state = state;
	fpu->state_mask = state_mask;
	return 0;
}

static void fill_gap(struct membuf *to, unsigned *last, unsigned offset)
{
	if (*last >= offset)
		return;

	/*
	 * Copy initial data.
	 *
	 * init_fpstate buffer has the minimum size as excluding the dynamic user
	 * states. But their initial values are zeros.
	 */
	if (offset <= get_xstate_config(XSTATE_MIN_SIZE))
		membuf_write(to, (void *)&init_fpstate.xsave + *last, offset - *last);
	else
		membuf_zero(to, offset - *last);
	*last = offset;
}

/*
 * @from: If NULL, copy zeros.
 */
static void copy_part(struct membuf *to, unsigned *last, unsigned offset,
		      unsigned size, void *from)
{
	fill_gap(to, last, offset);
	if (from)
		membuf_write(to, from, size);
	else
		membuf_zero(to, size);
	*last = offset + size;
}

/*
 * Convert from kernel XSAVES compacted format to standard format and copy
 * to a kernel-space ptrace buffer.
 *
 * It supports partial copy but pos always starts from zero. This is called
 * from xstateregs_get() and there we check the CPU has XSAVES.
 */
void copy_xstate_to_kernel(struct membuf to, struct fpu *fpu)
{
	struct xstate_header header;
	const unsigned off_mxcsr = offsetof(struct fxregs_state, mxcsr);
	struct xregs_state *xsave;
	unsigned size = to.left;
	unsigned last = 0;
	int i;

	xsave = &fpu->state->xsave;

	/*
	 * The destination is a ptrace buffer; we put in only user xstates:
	 */
	memset(&header, 0, sizeof(header));
	header.xfeatures = xsave->header.xfeatures;
	header.xfeatures &= xfeatures_mask_user();

	if (header.xfeatures & XFEATURE_MASK_FP)
		copy_part(&to, &last, 0, off_mxcsr, &xsave->i387);
	if (header.xfeatures & (XFEATURE_MASK_SSE | XFEATURE_MASK_YMM))
		copy_part(&to, &last, off_mxcsr,
			  MXCSR_AND_FLAGS_SIZE, &xsave->i387.mxcsr);
	if (header.xfeatures & XFEATURE_MASK_FP)
		copy_part(&to, &last, offsetof(struct fxregs_state, st_space),
			  128, &xsave->i387.st_space);
	if (header.xfeatures & XFEATURE_MASK_SSE)
		copy_part(&to, &last, xstate_offsets[XFEATURE_SSE],
			  256, &xsave->i387.xmm_space);
	/*
	 * Fill xsave->i387.sw_reserved value for ptrace frame:
	 */
	copy_part(&to, &last, offsetof(struct fxregs_state, sw_reserved),
		  48, xstate_fx_sw_bytes);
	/*
	 * Copy xregs_state->header:
	 */
	copy_part(&to, &last, offsetof(struct xregs_state, header),
		  sizeof(header), &header);

	for (i = FIRST_EXTENDED_XFEATURE; i < XFEATURE_MAX; i++) {
		u64 mask = BIT_ULL(i);
		void *src;

		if (!(xfeatures_mask_user() & mask))
			continue;

		/*
		 * Copy states if used. Otherwise, copy the initial data.
		 */

		if (header.xfeatures & mask)
			src = __raw_xsave_addr(fpu, i);
		else
			/*
			 * init_fpstate buffer does not include the dynamic
			 * user state data as having initial values with zeros.
			 */
			src = (xfeatures_mask_user_dynamic & mask) ?
			      NULL : (void *)&init_fpstate.xsave + last;

		copy_part(&to, &last, xstate_offsets[i], xstate_sizes[i], src);

	}
	fill_gap(&to, &last, size);
}

/*
 * Convert from a ptrace standard-format kernel buffer to kernel XSAVES format
 * and copy to the target thread. This is called from xstateregs_set().
 */
int copy_kernel_to_xstate(struct fpu *fpu, const void *kbuf)
{
	struct xregs_state *xsave;
	unsigned int offset, size;
	int i;
	struct xstate_header hdr;

	offset = offsetof(struct xregs_state, header);
	size = sizeof(hdr);

	memcpy(&hdr, kbuf + offset, size);

	if (validate_user_xstate_header(&hdr))
		return -EINVAL;

	xsave = &fpu->state->xsave;

	for (i = 0; i < XFEATURE_MAX; i++) {
		u64 mask = ((u64)1 << i);

		if (hdr.xfeatures & mask) {
			void *dst = __raw_xsave_addr(fpu, i);

			if (!dst)
				continue;

			offset = xstate_offsets[i];
			size = xstate_sizes[i];

			memcpy(dst, kbuf + offset, size);
		}
	}

	if (xfeatures_mxcsr_quirk(hdr.xfeatures)) {
		offset = offsetof(struct fxregs_state, mxcsr);
		size = MXCSR_AND_FLAGS_SIZE;
		memcpy(&xsave->i387.mxcsr, kbuf + offset, size);
	}

	/*
	 * The state that came in from userspace was user-state only.
	 * Mask all the user states out of 'xfeatures':
	 */
	xsave->header.xfeatures &= XFEATURE_MASK_SUPERVISOR_ALL;

	/*
	 * Add back in the features that came in from userspace:
	 */
	xsave->header.xfeatures |= hdr.xfeatures;

	return 0;
}

/*
 * Convert from a ptrace or sigreturn standard-format user-space buffer to
 * kernel XSAVES format and copy to the target thread. This is called from
 * xstateregs_set(), as well as potentially from the sigreturn() and
 * rt_sigreturn() system calls.
 */
int copy_user_to_xstate(struct fpu *fpu, const void __user *ubuf)
{
	struct xregs_state *xsave;
	unsigned int offset, size;
	int i;
	struct xstate_header hdr;

	offset = offsetof(struct xregs_state, header);
	size = sizeof(hdr);

	if (__copy_from_user(&hdr, ubuf + offset, size))
		return -EFAULT;

	if (validate_user_xstate_header(&hdr))
		return -EINVAL;

	xsave = &fpu->state->xsave;

	for (i = 0; i < XFEATURE_MAX; i++) {
		u64 mask = ((u64)1 << i);

		if (hdr.xfeatures & mask) {
			void *dst = __raw_xsave_addr(fpu, i);

			if (!dst)
				continue;

			offset = xstate_offsets[i];
			size = xstate_sizes[i];

			if (__copy_from_user(dst, ubuf + offset, size))
				return -EFAULT;
		}
	}

	if (xfeatures_mxcsr_quirk(hdr.xfeatures)) {
		offset = offsetof(struct fxregs_state, mxcsr);
		size = MXCSR_AND_FLAGS_SIZE;
		if (__copy_from_user(&xsave->i387.mxcsr, ubuf + offset, size))
			return -EFAULT;
	}

	/*
	 * The state that came in from userspace was user-state only.
	 * Mask all the user states out of 'xfeatures':
	 */
	xsave->header.xfeatures &= XFEATURE_MASK_SUPERVISOR_ALL;

	/*
	 * Add back in the features that came in from userspace:
	 */
	xsave->header.xfeatures |= hdr.xfeatures;

	return 0;
}

/*
 * Save only supervisor states to the kernel buffer.  This blows away all
 * old states, and is intended to be used only in __fpu__restore_sig(), where
 * user states are restored from the user buffer.
 */
void copy_supervisor_to_kernel(struct fpu *fpu)
{
	struct xstate_header *header;
	struct xregs_state *xstate;
	u64 max_bit, min_bit;
	u32 lmask, hmask;
	int err, i;

	if (WARN_ON(!boot_cpu_has(X86_FEATURE_XSAVES)))
		return;

	if (!xfeatures_mask_supervisor())
		return;

	max_bit = __fls(xfeatures_mask_supervisor());
	min_bit = __ffs(xfeatures_mask_supervisor());

	xstate = &fpu->state->xsave;
	lmask = xfeatures_mask_supervisor();
	hmask = xfeatures_mask_supervisor() >> 32;
	XSTATE_OP(XSAVES, xstate, lmask, hmask, err);

	/* We should never fault when copying to a kernel buffer: */
	if (WARN_ON_FPU(err))
		return;

	/*
	 * At this point, the buffer has only supervisor states and must be
	 * converted back to normal kernel format.
	 */
	header = &xstate->header;
	header->xcomp_bv |= xfeatures_mask_all;

	/*
	 * This only moves states up in the buffer.  Start with
	 * the last state and move backwards so that states are
	 * not overwritten until after they are moved.  Note:
	 * memmove() allows overlapping src/dst buffers.
	 */
	for (i = max_bit; i >= min_bit; i--) {
		u8 *xbuf = (u8 *)xstate;

		if (!((header->xfeatures >> i) & 1))
			continue;

		/* Move xfeature 'i' into its normal location */
		memmove(xbuf + get_xstate_comp_offset(fpu->state_mask, i),
			xbuf + xstate_supervisor_only_offsets[i],
			xstate_sizes[i]);
	}
}

/**
 * copy_dynamic_supervisor_to_kernel() - Save dynamic supervisor states to
 *                                       an xsave area
 * @xstate: A pointer to an xsave area
 * @mask: Represent the dynamic supervisor features saved into the xsave area
 *
 * Only the dynamic supervisor states sets in the mask are saved into the xsave
 * area (See the comment in XFEATURE_MASK_SUPERVISOR_DYNAMIC for the details of
 * dynamic supervisor feature). Besides the dynamic supervisor states, the legacy
 * region and XSAVE header are also saved into the xsave area. The supervisor
 * features in the XFEATURE_MASK_SUPERVISOR_SUPPORTED and
 * XFEATURE_MASK_SUPERVISOR_UNSUPPORTED are not saved.
 *
 * The xsave area must be 64-bytes aligned.
 */
void copy_dynamic_supervisor_to_kernel(struct xregs_state *xstate, u64 mask)
{
	u64 dynamic_mask = xfeatures_mask_supervisor_dynamic() & mask;
	u32 lmask, hmask;
	int err;

	if (WARN_ON_FPU(!boot_cpu_has(X86_FEATURE_XSAVES)))
		return;

	if (WARN_ON_FPU(!dynamic_mask))
		return;

	lmask = dynamic_mask;
	hmask = dynamic_mask >> 32;

	XSTATE_OP(XSAVES, xstate, lmask, hmask, err);

	/* Should never fault when copying to a kernel buffer */
	WARN_ON_FPU(err);
}

/**
 * copy_kernel_to_dynamic_supervisor() - Restore dynamic supervisor states from
 *                                       an xsave area
 * @xstate: A pointer to an xsave area
 * @mask: Represent the dynamic supervisor features restored from the xsave area
 *
 * Only the dynamic supervisor states sets in the mask are restored from the
 * xsave area (See the comment in XFEATURE_MASK_SUPERVISOR_DYNAMIC for the
 * details of dynamic supervisor feature). Besides the dynamic supervisor states,
 * the legacy region and XSAVE header are also restored from the xsave area. The
 * supervisor features in the XFEATURE_MASK_SUPERVISOR_SUPPORTED and
 * XFEATURE_MASK_SUPERVISOR_UNSUPPORTED are not restored.
 *
 * The xsave area must be 64-bytes aligned.
 */
void copy_kernel_to_dynamic_supervisor(struct xregs_state *xstate, u64 mask)
{
	u64 dynamic_mask = xfeatures_mask_supervisor_dynamic() & mask;
	u32 lmask, hmask;
	int err;

	if (WARN_ON_FPU(!boot_cpu_has(X86_FEATURE_XSAVES)))
		return;

	if (WARN_ON_FPU(!dynamic_mask))
		return;

	lmask = dynamic_mask;
	hmask = dynamic_mask >> 32;

	XSTATE_OP(XRSTORS, xstate, lmask, hmask, err);

	/* Should never fault when copying from a kernel buffer */
	WARN_ON_FPU(err);
}

#ifdef CONFIG_PROC_PID_ARCH_STATUS
/*
 * Report the amount of time elapsed in millisecond since last AVX512
 * use in the task.
 */
static void avx512_status(struct seq_file *m, struct task_struct *task)
{
	unsigned long timestamp = READ_ONCE(task->thread.fpu.avx512_timestamp);
	long delta;

	if (!timestamp) {
		/*
		 * Report -1 if no AVX512 usage
		 */
		delta = -1;
	} else {
		delta = (long)(jiffies - timestamp);
		/*
		 * Cap to LONG_MAX if time difference > LONG_MAX
		 */
		if (delta < 0)
			delta = LONG_MAX;
		delta = jiffies_to_msecs(delta);
	}

	seq_put_decimal_ll(m, "AVX512_elapsed_ms:\t", delta);
	seq_putc(m, '\n');
}

/*
 * Report architecture specific information
 */
int proc_pid_arch_status(struct seq_file *m, struct pid_namespace *ns,
			struct pid *pid, struct task_struct *task)
{
	/*
	 * Report AVX512 state if the processor and build option supported.
	 */
	if (cpu_feature_enabled(X86_FEATURE_AVX512F))
		avx512_status(m, task);

	return 0;
}
#endif /* CONFIG_PROC_PID_ARCH_STATUS */
