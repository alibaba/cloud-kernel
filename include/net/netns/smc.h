/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NETNS_SMC_H__
#define __NETNS_SMC_H__
#include <linux/mutex.h>
#include <linux/percpu.h>

struct smc_stats_rsn;
struct smc_stats;
struct smc_convert {
	int wlist_len;
	struct mutex wlist_lock;
	struct list_head wlist;
	int (*smc_conv_match_rcu)(struct net *net, char *comm);
};

struct netns_smc {
	/* per cpu counters for SMC */
	struct smc_stats __percpu	*smc_stats;
	/* protect fback_rsn */
	struct mutex			mutex_fback_rsn;
	struct smc_stats_rsn		*fback_rsn;
	struct smc_convert		smc_conv;
#ifdef CONFIG_SYSCTL
	struct ctl_table_header		*smc_hdr;
#endif
	int				sysctl_wmem_default;
	int				sysctl_rmem_default;
	int				sysctl_tcp2smc;
	int				sysctl_autocorking;
};

#endif
