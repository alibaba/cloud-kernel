// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <net/sock.h>
#include <net/net_namespace.h>

#include "smc_core.h"

static int min_sndbuf = SMC_BUF_MIN_SIZE;
static int min_rcvbuf = SMC_BUF_MIN_SIZE;

static struct ctl_table smc_table[] = {
	{
		.procname       = "wmem_default",
		.data           = &init_net.smc.sysctl_wmem_default,
		.maxlen         = sizeof(init_net.smc.sysctl_wmem_default),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &min_sndbuf,
	},
	{
		.procname       = "rmem_default",
		.data           = &init_net.smc.sysctl_rmem_default,
		.maxlen         = sizeof(init_net.smc.sysctl_rmem_default),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = &min_rcvbuf,
	},
	{  }
};

static __net_init int smc_sysctl_init_net(struct net *net)
{
	struct ctl_table *table;

	table = smc_table;
	if (!net_eq(net, &init_net)) {
		int i;

		table = kmemdup(table, sizeof(smc_table), GFP_KERNEL);
		if (!table)
			goto err_alloc;

		for (i = 0; i < ARRAY_SIZE(smc_table) - 1; i++)
			table[i].data += (void *)net - (void *)&init_net;
	}

	net->smc.smc_hdr = register_net_sysctl(net, "net/smc", table);
	if (!net->smc.smc_hdr)
		goto err_reg;

	return 0;

err_reg:
	if (!net_eq(net, &init_net))
		kfree(table);
err_alloc:
	return -ENOMEM;
}

static __net_exit void smc_sysctl_exit_net(struct net *net)
{
	unregister_net_sysctl_table(net->smc.smc_hdr);
}

static struct pernet_operations smc_sysctl_ops __net_initdata = {
	.init = smc_sysctl_init_net,
	.exit = smc_sysctl_exit_net,
};

int __init smc_sysctl_init(void)
{
	return register_pernet_subsys(&smc_sysctl_ops);
}

void smc_sysctl_exit(void)
{
	unregister_pernet_subsys(&smc_sysctl_ops);
}
