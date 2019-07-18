/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (c) 2019 Xunlei Pang <xlpang@linux.alibaba.com>
 */

#ifndef _LINUX_ALI_HOTFIX_H
#define _LINUX_ALI_HOTFIX_H

#include <linux/compiler.h>

/*
 * ALI_HOTFIX_RESERVE* - reserve fields for core structures prone to change
 * ALI_HOTFIX_USE*     - use the reserved field in your hotfix
 * ALI_HOTFIX_REPLACE  - replacement of _orig with a union of _orig and _new
 */

#define _ALI_HOTFIX_REPLACE(_orig, _new)		\
	union {						\
		_new;					\
		struct {				\
			_orig;				\
		} __UNIQUE_ID(ali_hotfix_hide);		\
	}

#define ALI_HOTFIX_REPLACE(_orig, _new)	_ALI_HOTFIX_REPLACE(_orig, _new);

/*
 * We tried to standardize on alikernel reserved names.  These wrappers leverage
 * those common names making it easier to read and find in the code.
 */
#define _ALI_HOTFIX_RESERVE(n)		unsigned long ali_reserved##n
#define _ALI_HOTFIX_RESERVE_P(n)	void (*ali_reserved##n)(void)

#define ALI_HOTFIX_RESERVE(n)		_ALI_HOTFIX_RESERVE(n);
#define ALI_HOTFIX_RESERVE_P(n)		_ALI_HOTFIX_RESERVE_P(n);

/*
 * Wrappers to replace standard alikernel reserved elements.
 */
#define ALI_HOTFIX_USE(n, _new)				\
	ALI_HOTFIX_REPLACE(_ALI_HOTFIX_RESERVE(n), _new)
#define ALI_HOTFIX_USE_P(n, _new)			\
	ALI_HOTFIX_REPLACE(_ALI_HOTFIX_RESERVE_P(n), _new)

/*
 * Macros for breaking up a reserved element into two smaller chunks using an
 * anonymous struct inside an anonymous union.
 */
#define ALI_HOTFIX_USE2(n, _new1, _new2)		\
	ALI_HOTFIX_REPLACE(_ALI_HOTFIX_RESERVE(n), struct{ _new1; _new2; })
#define ALI_HOTFIX_USE2_P(n, _new1, _new2)		\
	ALI_HOTFIX_REPLACE(_ALI_HOTFIX_RESERVE_P(n), struct{ _new1; _new2; })

#endif /* _LINUX_ALI_HOTFIX_H */
