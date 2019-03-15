/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Alibaba Group Holding Limited.  All Rights Reserved.
 *
 *	Changes: Li Yu
 */

#ifndef _LINUX_HOOKER_H_
#define _LINUX_HOOKER_H_

#include <linux/types.h>

struct hooked_place;

struct hooker {
	struct hooked_place *hplace;
	void *func;	/* the installed hooker function pointer */
	struct list_head chain;
};

/*
 * Install the hooker function at specified address.
 * This function may sleep.
 *
 * Parameters:
 *	place - the address that saves function pointer
 *	hooker - the hooker to install, the caller must fill
 *		 its func member first
 *
 * Return:
 *	    0  - All OK, please note that hooker func may be called before
 *		 this return
 *	  < 0 -  any error, e.g. out of memory, existing same installed hooker
 */

extern int hooker_install(const void *place, struct hooker *hooker);

/*
 * Remove the installed hooker function that saved in hooker->func.
 * This function may sleep.
 *
 * Parameters:
 *	place - the address that saves function pointer
 *	hooker - the installed hooker struct
 */

extern void hooker_uninstall(struct hooker *hooker);

#endif
