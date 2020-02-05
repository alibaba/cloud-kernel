// SPDX-License-Identifier: GPL-2.0
#include <net/net_namespace.h>
#include <linux/sysctl.h>
#include <net/bonding.h>

int sysctl_bond_broadcast_arp_or_nd __read_mostly;
EXPORT_SYMBOL(sysctl_bond_broadcast_arp_or_nd);

struct ctl_table_header *bond_broadcast_arp_or_nd_table_header;

static struct ctl_table bond_broadcast_arp_or_nd_table[] = {
	{
		.procname	= "broadcast_arp_or_nd",
		.data		= &sysctl_bond_broadcast_arp_or_nd,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{}
};

void bond_create_sysctl(void)
{
	bond_broadcast_arp_or_nd_table_header =
		register_net_sysctl(&init_net, "net/bonding",
				    bond_broadcast_arp_or_nd_table);
}

void bond_destroy_sysctl(void)
{
	unregister_net_sysctl_table(bond_broadcast_arp_or_nd_table_header);
}
