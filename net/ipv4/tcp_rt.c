// SPDX-License-Identifier: GPL-2.0

#include <net/tcp.h>
#include <linux/module.h>

static const struct tcp_rt_ops __rcu *tcp_rt;
static DEFINE_SPINLOCK(tcp_rt_lock);

int tcp_register_rt(const struct tcp_rt_ops *rt)
{
	const struct tcp_rt_ops *ort;
	int ret = 0;

	if (!rt->init || !rt->release) {
		pr_err("tcp_rt does not implement required ops\n");
		return -EINVAL;
	}

	spin_lock(&tcp_rt_lock);
	ret = try_module_get(rt->owner);
	if (unlikely(!ret)) {
		ret = -EBUSY;
	} else {
		ort = rcu_dereference_protected(tcp_rt, true);
		if (ort) {
			ret = -EEXIST;
			pr_err("tcp_rt already registered\n");
			module_put(rt->owner);
		} else {
			rcu_assign_pointer(tcp_rt, rt);
			ret = 0;
		}
	}
	spin_unlock(&tcp_rt_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(tcp_register_rt);

void  tcp_unregister_rt(struct tcp_rt_ops *rt)
{
	const struct tcp_rt_ops *ort = NULL;

	spin_lock(&tcp_rt_lock);
	rcu_swap_protected(tcp_rt, ort, true);
	if (ort)
		module_put(ort->owner);
	spin_unlock(&tcp_rt_lock);

	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(tcp_unregister_rt);

void tcp_init_rt(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_rt_ops *ops;

	rcu_read_lock();
	ops = rcu_dereference(tcp_rt);
	if (ops)
		if (unlikely(!try_module_get(ops->owner)))
			ops = NULL;
	icsk->icsk_tcp_rt_ops = ops;
	rcu_read_unlock();

	ops = icsk->icsk_tcp_rt_ops;

	if (!ops)
		return;

	if (ops->init(sk)) {
		module_put(ops->owner);
		icsk->icsk_tcp_rt_ops = NULL;
	}
}

void tcp_cleanup_rt(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_tcp_rt_ops) {
		icsk->icsk_tcp_rt_ops->release(sk);
		module_put(icsk->icsk_tcp_rt_ops->owner);
		icsk->icsk_tcp_rt_ops = NULL;
	}
}
