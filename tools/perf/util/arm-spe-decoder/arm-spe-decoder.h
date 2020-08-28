// SPDX-License-Identifier: GPL-2.0
/*
 * arm_spe_decoder.c: ARM SPE support
 */

#ifndef INCLUDE__ARM_SPE_DECODER_H__
#define INCLUDE__ARM_SPE_DECODER_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

enum arm_spe_events {
	EV_EXCEPTION_GEN,
	EV_RETIRED,
	EV_L1D_ACCESS,
	EV_L1D_REFILL,
	EV_TLB_ACCESS,
	EV_TLB_REFILL,
	EV_NOT_TAKEN,
	EV_MISPRED,
	EV_LLC_ACCESS,
	EV_LLC_REFILL,
	EV_REMOTE_ACCESS,
};

enum arm_spe_sample_type {
	ARM_SPE_LLC_MISS= 1 << 0,
	ARM_SPE_TLB_MISS= 1 << 1,
	ARM_SPE_BRANCH_MISS= 1 << 2,
	ARM_SPE_REMOTE_ACCESS= 1 << 3,
	ARM_SPE_LLC_ACCESS  = 1 << 4,
	ARM_SPE_EX_STOP= 1 << 6,
};

struct arm_spe_state {
	enum arm_spe_sample_type type;
	int err;
	bool is_ld;		/* Is load ? */
	bool is_st;		/* Is store ? */
	bool is_l1d_access;	/* Is l1d access ? */
	bool is_l1d_miss;	/* Is l1d miss ? */
	bool is_l2d_miss;	/* Is l2d miss ? */
	bool is_llc_miss;	/* Is llc miss ? */
	bool is_llc_access;	/* Is llc access ? */
	bool is_tlb_miss;	/* Is tlb miss ? */
	bool is_remote;		/* Is remote access ? */
	uint64_t ts;		/* timestamp */
	uint64_t from_ip;
	uint64_t to_ip;
	uint64_t data_src;
	uint64_t addr;
	uint64_t phys_addr;
	uint64_t timestamp;
	uint64_t tot_lat;
	uint64_t issue_lat;
	uint64_t trans_lat;
};

struct arm_spe_insn;

struct arm_spe_buffer {
	const unsigned char *buf;
	size_t len;
	u64 offset;
	bool consecutive;
	uint64_t ref_timestamp;
	uint64_t trace_nr;
};

struct arm_spe_params {
	int (*get_trace)(struct arm_spe_buffer *buffer, void *data);
	void *data;
};

struct arm_spe_decoder;

struct arm_spe_decoder *arm_spe_decoder_new(struct arm_spe_params *params);
void arm_spe_decoder_free(struct arm_spe_decoder *decoder);

const struct arm_spe_state *arm_spe_decode(struct arm_spe_decoder *decoder);

#endif
