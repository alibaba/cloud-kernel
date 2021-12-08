/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SMC_PROC_H_
#define _SMC_PROC_H_

#include <linux/module.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include "smc.h"

#define CONN4_HDR ("%4s:%-15s%-15s%-7s%-10s%-19s%-19s%-6s%-19s%-11s%-11s%-9s%-6s%-6s%-7s%-9s%-6s\n")
#define CONN6_HDR ("%4s:%-39s%-39s%-7s%-10s%-19s%-19s%-6s%-19s%-11s%-11s%-9s%-6s%-6s%-7s%-9s%-6s\n")
#define CONN4_ADDR_FM	("%4d:%08X:%04X  %08X:%04X")
#define CONN6_ADDR_FM	("%4d:%08X%08X%08X%08X:%04X  %08X%08X%08X%08X:%04X")
#define CONN_SK_FM	("  %c      %-8X  %pK   %pK   %2d    %-16lu   ")
#define CONN_LGR_FM	("   %c          %-8s %d     %-4X  %-4X   %-8X %-8X\n")

struct smc_proc_private {
	struct	seq_net_private p;
	int num, bucket, offset;
	int protocol;
	loff_t last_pos;
};

struct smc_proc_entry {
	const char *name;
	const struct seq_operations ops;
};

int __init smc_proc_init(void);
void smc_proc_exit(void);

#endif
