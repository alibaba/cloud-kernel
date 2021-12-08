/* SPDX-License-Identifier: GPL-2.0 */

#ifndef NET_SMC_SMC_CONV_H_
#define NET_SMC_SMC_CONV_H_
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/list.h>

#define SMC_MAX_WLIST_LEN 32

struct smc_conv_wlist_elem {
	char task_comm[TASK_COMM_LEN];
	struct list_head list;
};

int smc_nl_add_tcp2smc_wlist(struct sk_buff *skb, struct genl_info *info);
int smc_nl_del_tcp2smc_wlist(struct sk_buff *skb, struct genl_info *info);
int smc_nl_get_tcp2smc_wlist(struct sk_buff *skb, struct netlink_callback *cb);
int __init smc_conv_init(void);
void smc_conv_exit(void);

#endif /* NET_SMC_SMC_CONV_H_ */
