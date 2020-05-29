/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * Internal libbpf helpers.
 *
 * Copyright (c) 2019 Facebook
 */

#ifndef __LIBBPF_LIBBPF_INTERNAL_H
#define __LIBBPF_LIBBPF_INTERNAL_H

#include <stdlib.h>
#include <limits.h>

#include "libbpf.h"

#ifndef offsetofend
# define offsetofend(TYPE, FIELD) \
	(offsetof(TYPE, FIELD) + sizeof(((TYPE *)0)->FIELD))
#endif

extern void libbpf_print(enum libbpf_print_level level,
			 const char *format, ...)
	__attribute__((format(printf, 2, 3)));

#define __pr(level, fmt, ...)	\
do {				\
	libbpf_print(level, "libbpf: " fmt, ##__VA_ARGS__);	\
} while (0)

#define pr_warn(fmt, ...)	__pr(LIBBPF_WARN, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)	__pr(LIBBPF_INFO, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...)	__pr(LIBBPF_DEBUG, fmt, ##__VA_ARGS__)
#define pr_warning(fmt, ...)	__pr(LIBBPF_WARN, fmt, ##__VA_ARGS__)

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif
/*
 * Re-implement glibc's reallocarray() for libbpf internal-only use.
 * reallocarray(), unfortunately, is not available in all versions of glibc,
 * so requires extra feature detection and using reallocarray() stub from
 * <tools/libc_compat.h> and COMPAT_NEED_REALLOCARRAY. All this complicates
 * build of libbpf unnecessarily and is just a maintenance burden. Instead,
 * it's trivial to implement libbpf-specific internal version and use it
 * throughout libbpf.
 */
static inline void *libbpf_reallocarray(void *ptr, size_t nmemb, size_t size)
{
	size_t total;

#if __has_builtin(__builtin_mul_overflow)
	if (unlikely(__builtin_mul_overflow(nmemb, size, &total)))
		return NULL;
#else
	if (size == 0 || nmemb > ULONG_MAX / size)
		return NULL;
	total = nmemb * size;
#endif
	return realloc(ptr, total);
}

static inline bool libbpf_validate_opts(const char *opts,
					size_t opts_sz, size_t user_sz,
					const char *type_name)
{
	if (user_sz < sizeof(size_t)) {
		pr_warn("%s size (%zu) is too small\n", type_name, user_sz);
		return false;
	}
	if (user_sz > opts_sz) {
		size_t i;

		for (i = opts_sz; i < user_sz; i++) {
			if (opts[i]) {
				pr_warn("%s has non-zero extra bytes\n",
					type_name);
				return false;
			}
		}
	}
	return true;
}

#define OPTS_VALID(opts, type)						      \
	(!(opts) || libbpf_validate_opts((const char *)opts,		      \
					 offsetofend(struct type,	      \
						     type##__last_field),     \
					 (opts)->sz, #type))
#define OPTS_HAS(opts, field) \
	((opts) && opts->sz >= offsetofend(typeof(*(opts)), field))
#define OPTS_GET(opts, field, fallback_value) \
	(OPTS_HAS(opts, field) ? (opts)->field : fallback_value)
#define OPTS_SET(opts, field, value)		\
	do {					\
		if (OPTS_HAS(opts, field))	\
			(opts)->field = value;	\
	} while (0)

#endif /* __LIBBPF_LIBBPF_INTERNAL_H */