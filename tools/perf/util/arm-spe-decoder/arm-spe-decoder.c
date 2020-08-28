// SPDX-License-Identifier: GPL-2.0
/*
 * arm_spe_decoder.c: ARM SPE support
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <linux/compiler.h>

#include "../util.h"
#include "../debug.h"
#include "../auxtrace.h"

#include "arm-spe-pkt-decoder.h"
#include "arm-spe-decoder.h"

#ifndef BIT
#define BIT(n)(1UL << (n))
#endif

struct arm_spe_decoder {
	int (*get_trace)(struct arm_spe_buffer *buffer, void *data);
	void *data;
	struct arm_spe_state state;
	const unsigned char *buf;
	size_t len;
	uint64_t pos;
	struct arm_spe_pkt packet;
	int pkt_step;
	int pkt_len;
	int last_packet_type;

	uint64_t last_ip;
	uint64_t ip;
	uint64_t timestamp;
	uint64_t sample_timestamp;
	const unsigned char *next_buf;
	size_t next_len;
	unsigned char temp_buf[ARM_SPE_PKT_MAX_SZ];
};

static uint64_t arm_spe_calc_ip(uint64_t ip)
{

	/* fill high 8 bits for kernel virtual address */
	/* In Armv8 Architecture Reference Manual: Xn[55] determines
	 * whether the address lies in the upper or lower address range
	 * for the purpose of determining whether address tagging is
	 * used */
	if (ip & BIT(55))
		ip |= (uint64_t)(0xffULL << 56);

	return ip;
}

struct arm_spe_decoder *arm_spe_decoder_new(struct arm_spe_params *params)
{
	struct arm_spe_decoder *decoder;

	if (!params->get_trace)
		return NULL;

	decoder = zalloc(sizeof(struct arm_spe_decoder));
	if (!decoder)
		return NULL;

	decoder->get_trace          = params->get_trace;
	decoder->data               = params->data;

	return decoder;
}

void arm_spe_decoder_free(struct arm_spe_decoder *decoder)
{
	free(decoder);
}

static int arm_spe_bad_packet(struct arm_spe_decoder *decoder)
{
	decoder->pkt_len = 1;
	decoder->pkt_step = 1;
	pr_debug("ERROR: Bad packet\n");

	return -EBADMSG;
}


static int arm_spe_get_data(struct arm_spe_decoder *decoder)
{
	struct arm_spe_buffer buffer = { .buf = 0, };
	int ret;

	decoder->pkt_step = 0;

	pr_debug("Getting more data\n");
	ret = decoder->get_trace(&buffer, decoder->data);
	if (ret)
		return ret;

	decoder->buf = buffer.buf;
	decoder->len = buffer.len;
	if (!decoder->len) {
		pr_debug("No more data\n");
		return -ENODATA;
	}

	return 0;
}

static int arm_spe_get_next_data(struct arm_spe_decoder *decoder)
{
	return arm_spe_get_data(decoder);
}

static int arm_spe_get_next_packet(struct arm_spe_decoder *decoder)
{
	int ret;

	decoder->last_packet_type = decoder->packet.type;

	do {
		decoder->pos += decoder->pkt_step;
		decoder->buf += decoder->pkt_step;
		decoder->len -= decoder->pkt_step;


		if (!decoder->len) {
			ret = arm_spe_get_next_data(decoder);
			if (ret)
				return ret;
		}

		ret = arm_spe_get_packet(decoder->buf, decoder->len,
				&decoder->packet);
		if (ret <= 0)
			return arm_spe_bad_packet(decoder);

		decoder->pkt_len = ret;
		decoder->pkt_step = ret;
	} while (decoder->packet.type == ARM_SPE_PAD);

	return 0;
}

static int arm_spe_walk_trace(struct arm_spe_decoder *decoder)
{
	int err;
	int idx;
	uint64_t payload;

	while (1) {
		err = arm_spe_get_next_packet(decoder);
		if (err)
			return err;

		idx = decoder->packet.index;
		payload = decoder->packet.payload;

		switch (decoder->packet.type) {
		case ARM_SPE_TIMESTAMP:
			decoder->sample_timestamp = payload;
			decoder->state.ts = payload;
			return 0;
		case ARM_SPE_END:
			decoder->sample_timestamp = 0;
			decoder->state.ts = 0;
			return 0;
		case ARM_SPE_ADDRESS:
			switch (idx) {
			case 0:
			case 1:
				payload &= ~(0xffULL << 56);
				decoder->ip = arm_spe_calc_ip(payload);
				if (idx == 0)
					decoder->state.from_ip = decoder->ip;
				else
					decoder->state.to_ip = decoder->ip;
				break;
			case 2:
				decoder->ip = arm_spe_calc_ip(payload);
				decoder->state.addr = decoder->ip;
				break;
			case 3:
				payload &= ~(0xffULL << 56);
				decoder->state.phys_addr = payload;
				break;
			default:
				break;
			}
			break;
		case ARM_SPE_COUNTER:
			switch (idx) {
			case 0:
				decoder->state.tot_lat = payload;
				break;
			case 1:
				decoder->state.issue_lat = payload;
				break;
			case 2:
				decoder->state.trans_lat = payload;
				break;
			default:
				break;
			}
			break;
		case ARM_SPE_CONTEXT:
			break;
		case ARM_SPE_OP_TYPE:
			if (idx == 0x1) {
				if (payload & 0x1)
					decoder->state.is_st = true;
				else
					decoder->state.is_ld = true;
			}
			break;
		case ARM_SPE_EVENTS:
			if (payload & BIT(EV_TLB_REFILL)) {
				decoder->state.type |= ARM_SPE_TLB_MISS;
				decoder->state.is_tlb_miss = true;
			}
			if (payload & BIT(EV_L1D_ACCESS))
				decoder->state.is_l1d_access = true;
			if (payload & BIT(EV_L1D_REFILL))
				decoder->state.is_l1d_miss = true;
			if (payload & BIT(EV_MISPRED))
				decoder->state.type |= ARM_SPE_BRANCH_MISS;
			if (idx > 1 && (payload & BIT(EV_LLC_REFILL))) {
				decoder->state.type |= ARM_SPE_LLC_MISS;
				decoder->state.is_llc_miss = true;
			}
			if (idx > 1 && (payload & BIT(EV_LLC_ACCESS))) {
				decoder->state.type |= ARM_SPE_LLC_ACCESS;
				decoder->state.is_llc_access = true;
			}
			if (idx > 1 && (payload & BIT(EV_REMOTE_ACCESS))) {
				decoder->state.type |= ARM_SPE_REMOTE_ACCESS;
				decoder->state.is_remote = true;
			}

			break;
		case ARM_SPE_DATA_SOURCE:
			break;
		case ARM_SPE_BAD:
			break;
		case ARM_SPE_PAD:
			break;
		default:
			pr_err("Get Packet Error!\n");
			return -ENOSYS;
		}
	}
}

const struct arm_spe_state *arm_spe_decode(struct arm_spe_decoder *decoder)
{
	int err;

	memset(&(decoder->state), 0, sizeof(struct arm_spe_state));

	err = arm_spe_walk_trace(decoder);
	if (err)
		decoder->state.err = err;

	decoder->state.timestamp = decoder->sample_timestamp;

	return &decoder->state;
}
