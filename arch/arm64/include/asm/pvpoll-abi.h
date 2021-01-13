/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ASM_PV_POLL_CONTROL_ABI_H
#define __ASM_PV_POLL_CONTROL_ABI_H

struct pv_vcpu_poll_ctl {
	__le64 poll_ctl;
	/* Structure must be 64 byte aligned, pad to that size */
	u8 padding[56];
} __packed;

#endif
