/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (c) 2019 Xunlei Pang <xlpang@linux.alibaba.com>
 */

#ifndef _LINUX_CK_HOTFIX_H
#define _LINUX_CK_HOTFIX_H

#include <linux/compiler.h>

/*
 * CK_HOTFIX_RESERVE* - reserve fields for core structures prone to change
 * CK_HOTFIX_USE*     - use the reserved field in your hotfix
 * CK_HOTFIX_REPLACE  - replacement of _orig with a union of _orig and _new
 */

#define _CK_HOTFIX_REPLACE(_orig, _new)		\
	union {						\
		_new;					\
		struct {				\
			_orig;				\
		} __UNIQUE_ID(ck_hotfix_hide);		\
	}

#define CK_HOTFIX_REPLACE(_orig, _new)	_CK_HOTFIX_REPLACE(_orig, _new);

/*
 * We tried to standardize on ck kernel reserved names. These wrappers leverage
 * those common names making it easier to read and find in the code.
 */
#define _CK_HOTFIX_RESERVE(n)		unsigned long ck_reserved##n
#define _CK_HOTFIX_RESERVE_P(n)	void (*ck_reserved##n)(void)

#define CK_HOTFIX_RESERVE(n)		_CK_HOTFIX_RESERVE(n);
#define CK_HOTFIX_RESERVE_P(n)		_CK_HOTFIX_RESERVE_P(n);

/*
 * Wrappers to replace standard ck kernel reserved elements.
 */
#define CK_HOTFIX_USE(n, _new)				\
	CK_HOTFIX_REPLACE(_CK_HOTFIX_RESERVE(n), _new)
#define CK_HOTFIX_USE_P(n, _new)			\
	CK_HOTFIX_REPLACE(_CK_HOTFIX_RESERVE_P(n), _new)

/*
 * Macros for breaking up a reserved element into two smaller chunks using an
 * anonymous struct inside an anonymous union.
 */
#define CK_HOTFIX_USE2(n, _new1, _new2)		\
	CK_HOTFIX_REPLACE(_CK_HOTFIX_RESERVE(n), struct{ _new1; _new2; })
#define CK_HOTFIX_USE2_P(n, _new1, _new2)		\
	CK_HOTFIX_REPLACE(_CK_HOTFIX_RESERVE_P(n), struct{ _new1; _new2; })

#endif /* _LINUX_CK_HOTFIX_H */
