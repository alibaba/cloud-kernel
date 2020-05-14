/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Linaro, Ltd. <ard.biesheuvel@linaro.org>
 */

#include <linux/linkage.h>
#include <asm/assembler.h>

ENTRY(do_csum)
	adds		x2, xzr, xzr		// clear x2 and C flag

	// 64 bytes at a time
	lsr		x3, x1, #6
	and		x1, x1, #63
	cbz		x3, 1f

	// Eight 64-bit adds per iteration
0:	ldp		x4, x5, [x0], #64
	ldp		x6, x7, [x0, #-48]
	ldp		x8, x9, [x0, #-32]
	ldp		x10, x11, [x0, #-16]
	adcs		x2, x2, x4
	sub		x3, x3, #1
	adcs		x2, x2, x5
	adcs		x2, x2, x6
	adcs		x2, x2, x7
	adcs		x2, x2, x8
	adcs		x2, x2, x9
	adcs		x2, x2, x10
	adcs		x2, x2, x11
	cbnz		x3, 0b
	adc		x2, x2, xzr

	cbz		x1, 7f
	bic		x3, x1, #1
	add		x12, x0, x1
	add		x0, x0, x3
	neg		x3, x3
	add		x3, x3, #64
	lsl		x3, x3, #3

	// Handle remaining 63 bytes or less using an overlapping 64-byte load
	// and a branchless code path to complete the calculation
	ldp		x4, x5, [x0, #-64]
	ldp		x6, x7, [x0, #-48]
	ldp		x8, x9, [x0, #-32]
	ldp		x10, x11, [x0, #-16]
	ldrb		w12, [x12, #-1]

	.irp		reg, x4, x5, x6, x7, x8, x9, x10, x11
	cmp		x3, #64
	csel		\reg, \reg, xzr, lt
	ccmp		x3, xzr, #0, lt
	csel		x13, x3, xzr, gt
	sub		x3, x3, #64
CPU_LE(	lsr		\reg, \reg, x13		)
CPU_BE(	lsl		\reg, \reg, x13		)
	.endr

	adds		x2, x2, x4
	adcs		x2, x2, x5
	adcs		x2, x2, x6
	adcs		x2, x2, x7
	adcs		x2, x2, x8
	adcs		x2, x2, x9
	adcs		x2, x2, x10
	adcs		x2, x2, x11
	adc		x2, x2, xzr

CPU_LE(	adds		x12, x2, x12		)
CPU_BE(	adds		x12, x2, x12, lsl #8	)
	adc		x12, x12, xzr
	tst		x1, #1
	csel		x2, x2, x12, eq

7:	lsr		x1, x2, #32
	adds		w2, w2, w1
	adc		w2, w2, wzr

	lsr		w1, w2, #16
	uxth		w2, w2
	add		w2, w2, w1

	lsr		w1, w2, #16		// handle the carry by hand
	add		w2, w2, w1

	uxth		w0, w2
	ret

	// Handle 63 bytes or less
1:	tbz		x1, #5, 2f
	ldp		x4, x5, [x0], #32
	ldp		x6, x7, [x0, #-16]
	adds		x2, x2, x4
	adcs		x2, x2, x5
	adcs		x2, x2, x6
	adcs		x2, x2, x7
	adc		x2, x2, xzr

2:	tbz		x1, #4, 3f
	ldp		x4, x5, [x0], #16
	adds		x2, x2, x4
	adcs		x2, x2, x5
	adc		x2, x2, xzr

3:	tbz		x1, #3, 4f
	ldr		x4, [x0], #8
	adds		x2, x2, x4
	adc		x2, x2, xzr

4:	tbz		x1, #2, 5f
	ldr		w4, [x0], #4
	adds		x2, x2, x4
	adc		x2, x2, xzr

5:	tbz		x1, #1, 6f
	ldrh		w4, [x0], #2
	adds		x2, x2, x4
	adc		x2, x2, xzr

6:	tbz		x1, #0, 7b
	ldrb		w4, [x0]
CPU_LE(	adds		x2, x2, x4		)
CPU_BE(	adds		x2, x2, x4, lsl #8	)
	adc		x2, x2, xzr
	b		7b
ENDPROC(do_csum)
