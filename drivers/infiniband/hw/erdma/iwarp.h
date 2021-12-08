/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *          Fredy Neeser <nfd@zurich.ibm.com>
 *
 * Copyright (c) 2020 Alibaba Group.
 * Copyright (c) 2008-2016, IBM Corporation
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *   Redistribution and use in source and binary forms, with or
 *   without modification, are permitted provided that the following
 *   conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of IBM nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _IWARP_H
#define _IWARP_H

#include <rdma/rdma_user_cm.h>	/* RDMA_MAX_PRIVATE_DATA */
#include <linux/types.h>
#include <asm/byteorder.h>


#define RDMAP_VERSION		1
#define DDP_VERSION		1
#define MPA_REVISION_1		1
#define MPA_MAX_PRIVDATA	RDMA_MAX_PRIVATE_DATA
#define MPA_KEY_REQ		"MPA ID Req F"
#define MPA_KEY_REP		"MPA ID Rep F"

struct mpa_rr_params {
	__be16	bits;
	__be16	pd_len;
};

/*
 * MPA request/response Hdr bits & fields
 */
enum {
	MPA_RR_FLAG_MARKERS	= __cpu_to_be16(0x8000),
	MPA_RR_FLAG_CRC		= __cpu_to_be16(0x4000),
	MPA_RR_FLAG_REJECT	= __cpu_to_be16(0x2000),
	MPA_RR_DESIRED_CC	= __cpu_to_be16(0x0f00),
	MPA_RR_RESERVED		= __cpu_to_be16(0x1000),
	MPA_RR_MASK_REVISION	= __cpu_to_be16(0x00ff)
};

/*
 * MPA request/reply header
 */
struct mpa_rr {
	__u8	key[16];
	struct mpa_rr_params params;
};

static inline void __mpa_rr_set_cc(__u16 *bits, __u16 cc)
{
	*bits = (*bits & ~MPA_RR_DESIRED_CC)
		| (cc & MPA_RR_DESIRED_CC);
}

static inline __u8 __mpa_rr_cc(__u16 mpa_rr_bits)
{
	__u16 rev = (mpa_rr_bits & MPA_RR_DESIRED_CC);

	return (__u8)rev;
}

static inline void __mpa_rr_set_revision(__u16 *bits, __u8 rev)
{
	*bits = (*bits & ~MPA_RR_MASK_REVISION)
		| (cpu_to_be16(rev) & MPA_RR_MASK_REVISION);
}

static inline __u8 __mpa_rr_revision(__u16 mpa_rr_bits)
{
	__u16 rev = mpa_rr_bits & MPA_RR_MASK_REVISION;

	return (__u8)be16_to_cpu(rev);
}


/*
 * Don't change the layout/size of this struct!
 */
struct mpa_marker {
	__be16	rsvd;
	__be16	fpdu_hmd; /* FPDU header-marker distance (= MPA's FPDUPTR) */
};

#define MPA_MARKER_SPACING	512
#define MPA_HDR_SIZE		2

/*
 * MPA marker size:
 * - Standards-compliant marker insertion: Use sizeof(struct mpa_marker)
 * - "Invisible markers" for testing sender's marker insertion
 *   without affecting receiver: Use 0
 */
#define MPA_MARKER_SIZE		sizeof(struct mpa_marker)


/*
 * maximum MPA trailer
 */
struct mpa_trailer {
	char	pad[4];
	__be32	crc;
};

#define MPA_CRC_SIZE	4

#endif
