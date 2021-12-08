// SPDX-License-Identifier: GPL-2.0-only
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/socket.h>
#include <linux/smc.h>
#include <net/genetlink.h>
#include <net/sock.h>
#include "smc_netlink.h"
#include "smc_conv.h"

int smc_nl_add_tcp2smc_wlist(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = sock_net(skb->sk);
	struct mutex *wlist_lock = &net->smc.smc_conv.wlist_lock;
	struct list_head *wlist = &net->smc.smc_conv.wlist;
	int *wlist_len = &net->smc.smc_conv.wlist_len;
	struct smc_conv_wlist_elem *wlist_elem, *tmp;
	char msg[TASK_COMM_LEN];
	struct nlattr *na;

	na = info->attrs[SMC_CMD_ATTR_TCP2SMC];
	if (!na)
		return -EINVAL;

	nla_strlcpy(msg, na, TASK_COMM_LEN);

	mutex_lock(wlist_lock);
	if (*wlist_len >= SMC_MAX_WLIST_LEN) {
		mutex_unlock(wlist_lock);
		return -EINVAL;
	}

	list_for_each_entry(tmp, wlist, list) {
		if (!strcmp(tmp->task_comm, msg))
			goto out;
	}

	wlist_elem = kmalloc(sizeof(*wlist_elem), GFP_KERNEL);
	if (!wlist_elem) {
		mutex_unlock(wlist_lock);
		return -ENOMEM;
	}

	strcpy(wlist_elem->task_comm, msg);
	list_add_tail_rcu(&wlist_elem->list, wlist);
	++*wlist_len;
out:
	mutex_unlock(wlist_lock);
	return 0;
}

int smc_nl_del_tcp2smc_wlist(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = sock_net(skb->sk);
	struct mutex *wlist_lock = &net->smc.smc_conv.wlist_lock;
	struct list_head *wlist = &net->smc.smc_conv.wlist;
	int *wlist_len = &net->smc.smc_conv.wlist_len;
	struct smc_conv_wlist_elem *tmp, *nxt;
	char msg[TASK_COMM_LEN];
	struct nlattr *na;

	na = info->attrs[SMC_CMD_ATTR_TCP2SMC];
	if (!na)
		return -EINVAL;

	nla_strlcpy(msg, na, TASK_COMM_LEN);

	mutex_lock(wlist_lock);
	list_for_each_entry_safe(tmp, nxt, wlist, list) {
		if (!strcmp(tmp->task_comm, msg)) {
			list_del_rcu(&tmp->list);
			synchronize_rcu();
			kfree(tmp);
			--*wlist_len;
			break;
		}
	}
	mutex_unlock(wlist_lock);
	return 0;
}

int smc_nl_get_tcp2smc_wlist(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	struct list_head *wlist = &net->smc.smc_conv.wlist;
	struct smc_nl_dmp_ctx *cb_ctx = smc_nl_dmp_ctx(cb);
	struct smc_conv_wlist_elem *tmp;
	void *nlh;

	if (cb_ctx->pos[0])
		goto errmsg;

	nlh = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			  &smc_gen_nl_family, NLM_F_MULTI,
			    SMC_NETLINK_GET_TCP2SMC_WLIST);
	if (!nlh)
		goto errmsg;

	rcu_read_lock();
	list_for_each_entry_rcu(tmp, wlist, list) {
		if (nla_put(skb, SMC_CMD_ATTR_TCP2SMC,
			    nla_total_size(strlen(tmp->task_comm) + 1),
			    tmp->task_comm)) {
			rcu_read_unlock();
			goto errattr;
		}
	}
	rcu_read_unlock();

	genlmsg_end(skb, nlh);
	cb_ctx->pos[0] = 1;
	return skb->len;

errattr:
	genlmsg_cancel(skb, nlh);
errmsg:
	return skb->len;
}

static int smc_match_tcp2smc_wlist(struct net *net, char *comm)
{
	struct list_head *wlist = &net->smc.smc_conv.wlist;
	struct smc_conv_wlist_elem *tmp;

	rcu_read_lock();
	list_for_each_entry_rcu(tmp, wlist, list) {
		if (!strcmp(tmp->task_comm, comm)) {
			rcu_read_unlock();
			return 0;
		}
	}
	rcu_read_unlock();
	return -1;
}

static int __net_init smc_net_conv_init(struct net *net)
{
	INIT_LIST_HEAD_RCU(&net->smc.smc_conv.wlist);
	net->smc.smc_conv.wlist_len = 0;

	mutex_init(&net->smc.smc_conv.wlist_lock);

	rcu_assign_pointer(net->smc.smc_conv.smc_conv_match_rcu,
			   smc_match_tcp2smc_wlist);
	return 0;
}

static void __net_exit smc_net_conv_exit(struct net *net)
{
	struct mutex *wlist_lock = &net->smc.smc_conv.wlist_lock;
	struct list_head *wlist = &net->smc.smc_conv.wlist;
	int *wlist_len = &net->smc.smc_conv.wlist_len;
	struct smc_conv_wlist_elem *cur, *nxt;
	struct list_head tmp_list;

	rcu_assign_pointer(net->smc.smc_conv.smc_conv_match_rcu, NULL);
	synchronize_rcu();

	INIT_LIST_HEAD(&tmp_list);

	mutex_lock(wlist_lock);
	list_splice_init_rcu(wlist, &tmp_list, synchronize_rcu);
	*wlist_len = 0;
	mutex_unlock(wlist_lock);

	list_for_each_entry_safe(cur, nxt, &tmp_list, list) {
		list_del(&cur->list);
		kfree(cur);
	}
}

static struct pernet_operations smc_conv_ops = {
	.init = smc_net_conv_init,
	.exit = smc_net_conv_exit,
};

int __init smc_conv_init(void)
{
	return register_pernet_subsys(&smc_conv_ops);
}

void smc_conv_exit(void)
{
	unregister_pernet_subsys(&smc_conv_ops);
}
