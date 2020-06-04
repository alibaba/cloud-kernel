// SPDX-License-Identifier: GPL-2.0

#include "tcp_rt.h"

static int lports_number;
static int pports_number;
static int lports_range_number;
static int pports_range_number;

static int lports[PORT_MAX_NUM];
static int pports[PORT_MAX_NUM];
static int lports_range[PORT_MAX_NUM];
static int pports_range[PORT_MAX_NUM];

static int log_buf_num = 8;
static int stats_buf_num = 2;

static int stats;
static int stats_interval = 60;

module_param(stats, int, 0644);
MODULE_PARM_DESC(stats, "stats is enable");

module_param(stats_interval, int, 0644);
MODULE_PARM_DESC(stats_interval, "how many seconds later do stats");

module_param_array(lports, int, &lports_number, 0644);
MODULE_PARM_DESC(lports, "local port array. config: lports=80,3306.");

module_param_array(lports_range, int, &lports_range_number, 0644);
MODULE_PARM_DESC(lports_range, "local port range array. config: lports_range=1000,2000,3500,4000. means: 1000-2000 or 3500-4000");

module_param_array(pports, int, &pports_number, 0644);
MODULE_PARM_DESC(pports, "peer port array. config: pports=80,3306");

module_param_array(pports_range, int, &pports_range_number, 0644);
MODULE_PARM_DESC(pports_range, "peer port range array. config: pports_range=1000,2000,3500,4000. means: 1000-2000 or 3500-4000");

module_param(log_buf_num, int, 0644);
MODULE_PARM_DESC(log_buf_num, "the num of buffers for every cpu log buffer. unit is 256k. just work when module load.");
module_param(stats_buf_num, int, 0644);
MODULE_PARM_DESC(stats_buf_num, "the num of buffers for every cpu stats buffer. unit is 16k. just work when module load.");

struct timer_list tcp_rt_timer;

static void tcp_rt_timer_handler(struct timer_list *t)
{
	if (stats) {
		int i, port;

		for (i = 0; i < lports_number; i++)
			tcp_rt_timer_output(lports[i], "L", true);

		for (i = 0; i < lports_range_number / 2; ++i) {
			for (port = lports_range[i * 2];
			     port <= lports_range[i * 2 + 1]; ++port) {
				tcp_rt_timer_output(port, "L", false);
			}
		}

		for (i = 0; i < pports_number; i++)
			tcp_rt_timer_output(pports[i], "P", true);

		for (i = 0; i < pports_range_number / 2; ++i) {
			for (port = pports_range[i * 2];
			     port <= pports_range[i * 2 + 1]; ++port) {
				tcp_rt_timer_output(port, "P", false);
			}
		}
	}
	mod_timer(&tcp_rt_timer, jiffies + stats_interval * HZ);
}

static void tcp_rt_sk_send_data_peer(const struct sock *sk, struct tcp_rt *rt,
				     const struct tcp_sock *tp)
{
	switch (rt->stage_peer) {
	case TCPRT_STAGE_PEER_RESPONSE:
		tcp_rt_log_printk(sk, LOG_STATUS_P, false, stats);
		/* fall through */

	case TCPRT_STAGE_PEER_NONE:
		ktime_get_real_ts64(&rt->start_time);
		rt->end_time = rt->start_time;
		rt->request_num += 1;
		rt->upload_data = 0;
		rt->stage_peer = TCPRT_STAGE_PEER_REQUEST;

		rt->last_total_retrans = tp->total_retrans;
		break;

	default:
		break;
	}
}

static void tcp_rt_sk_send_data_local(const struct sock *sk, struct tcp_rt *rt,
				      const struct tcp_sock *tp)
{
	u64 this_us;

	switch (rt->stage) {
	case TCPRT_STAGE_REQUEST:
		this_us = tcp_clock_us();

		rt->stage = TCPRT_STAGE_RESPONSE;

		rt->server_time = this_us - rt->lrcvtime_us;
		rt->upload_time = rt->lrcvtime_us - rt->frcvtime_us;
		rt->upload_data = tp->rcv_nxt - rt->start_rcv_nxt;

		/* because recv_data is after rcv_nxt update, so
		 * record the value at here.
		 */
		rt->start_rcv_nxt = tp->rcv_nxt;

		break;

	case TCPRT_STAGE_RESPONSE:
		break;

	case TCPRT_STAGE_NONE:
		break;
	}
}

static void tcp_rt_sk_recv_data_peer(const struct sock *sk, struct tcp_rt *rt,
				     const struct tcp_sock *tp)
{
	switch (rt->stage_peer) {
	case TCPRT_STAGE_PEER_REQUEST:
		rt->stage_peer = TCPRT_STAGE_PEER_RESPONSE;
		rt->upload_data = tp->snd_nxt - rt->start_seq;
		rt->start_seq = tp->snd_nxt;
		ktime_get_real_ts64(&rt->end_time);
		return;

	case TCPRT_STAGE_PEER_RESPONSE:
		ktime_get_real_ts64(&rt->end_time);
		if (!RB_EMPTY_ROOT(&tp->out_of_order_queue))
			rt->rcv_reorder = 1;
		return;

	default:
		break;
	}
}

static void tcp_rt_sk_recv_data_local(const struct sock *sk, struct tcp_rt *rt,
				      const struct tcp_sock *tp)
{
	switch (rt->stage) {
	case TCPRT_STAGE_RESPONSE:
		if (after(tp->snd_nxt, tp->snd_una + 1)) {
			/* there are some bytes not acked.
			 * but new request is coming,
			 * so the skb also be the acked skb for snd_una,
			 * so update the end_time
			 */
			ktime_get_real_ts64(&rt->end_time);
		}
		tcp_rt_log_printk(sk, LOG_STATUS_R, false, stats);

		/* fall through */

	case TCPRT_STAGE_NONE:
		ktime_get_real_ts64(&rt->start_time);
		rt->end_time = rt->start_time;

		rt->frcvtime_us = tcp_clock_us();
		rt->lrcvtime_us = rt->frcvtime_us;

		rt->start_seq =	 tp->snd_nxt;

		rt->last_total_retrans = tp->total_retrans;
		rt->last_update_seq = tp->snd_una;

		rt->server_time = 0;
		rt->upload_time = 0;
		rt->upload_data = 0;

		rt->rcv_reorder = 0;

		rt->stage = TCPRT_STAGE_REQUEST;

		rt->request_num += 1;
		if (!RB_EMPTY_ROOT(&tp->out_of_order_queue))
			rt->rcv_reorder = 1;
		break;

	case TCPRT_STAGE_REQUEST:
		rt->lrcvtime_us = tcp_clock_us();
		if (!RB_EMPTY_ROOT(&tp->out_of_order_queue))
			rt->rcv_reorder = 1;
		break;
	}
}

static void tcp_rt_sk_release_peer(const struct sock *sk, struct tcp_rt *rt,
				   const struct tcp_sock *tp)
{
	switch (rt->stage_peer) {
	case TCPRT_STAGE_PEER_NONE:
	case TCPRT_STAGE_PEER_REQUEST:
		return;

	case TCPRT_STAGE_PEER_RESPONSE:
		tcp_rt_log_printk(sk, LOG_STATUS_P, false, stats);
		return;
	}
}

static void tcp_rt_sk_release_local(const struct sock *sk, struct tcp_rt *rt,
				    const struct tcp_sock *tp)
{
	switch (rt->stage) {
	case TCPRT_TYPE_NONE:
		break;

	case TCPRT_STAGE_REQUEST:
		/* closed when receiving data */
		tcp_rt_log_printk(sk, LOG_STATUS_N, false, stats);
		break;

	case TCPRT_STAGE_RESPONSE:
		if (tp->snd_nxt <= rt->start_seq + 1)
			break;

		if (tp->snd_nxt <= tp->snd_una + 1) {
			if (after(tp->snd_una, rt->last_update_seq + 1))
				ktime_get_real_ts64(&rt->end_time);

			tcp_rt_log_printk(sk, LOG_STATUS_R, true, stats);
		} else {
			/* closed when sending data */
			tcp_rt_log_printk(sk, LOG_STATUS_W, false, stats);
		}

		break;
	}
}

static void tcp_rt_sk_release(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_rt *rt = TCP_SK_RT(sk);

	if (!rt->request_num)
		goto free;

	if (rt->type >= TCPRT_TYPE_PEER_PORT)
		tcp_rt_sk_release_peer(sk, rt, tp);
	else
		tcp_rt_sk_release_local(sk, rt, tp);

	/* closed, 1 record per connection */
	tcp_rt_log_printk(sk, LOG_STATUS_E, false, stats);

free:
	kfree(rt);
}

static void tcp_rt_sk_pkts_acked(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_rt *rt = TCP_SK_RT(sk);

	if (after(tp->snd_una, rt->last_update_seq + 1)) {
		ktime_get_real_ts64(&rt->end_time);
		rt->last_update_seq = tp->snd_una;
	}
}

static void tcp_rt_sk_send_data(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_rt *rt = TCP_SK_RT(sk);

	if (rt->type >= TCPRT_TYPE_PEER_PORT)
		return tcp_rt_sk_send_data_peer(sk, rt, tp);
	else
		return tcp_rt_sk_send_data_local(sk, rt, tp);
}

static void tcp_rt_sk_recv_data(struct sock *sk)
{
	struct tcp_rt *rt = TCP_SK_RT(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if (rt->type >= TCPRT_TYPE_PEER_PORT)
		return tcp_rt_sk_recv_data_peer(sk, rt, tp);
	else
		return tcp_rt_sk_recv_data_local(sk, rt, tp);
}

static int tcp_rt_sk_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	struct tcp_rt *rt = NULL;
	enum tcp_rt_type type = TCPRT_TYPE_NONE;
	int i, port;

	port = ntohs(inet_sk(sk)->inet_sport);

	for (i = 0; i < lports_number; i++) {
		if (port == lports[i]) {
			type = TCPRT_TYPE_LOCAL_PORT;
			goto ok;
		}
	}

	for (i = 0; i < lports_range_number / 2; ++i) {
		if (port < lports_range[i * 2])
			continue;

		if (port > lports_range[i * 2 + 1])
			continue;

		type = TCPRT_TYPE_LOCAL_PORT_RANG;
		goto ok;
	}

	port = ntohs(inet_sk(sk)->inet_dport);

	for (i = 0; i < pports_number; i++) {
		if (port == pports[i]) {
			type = TCPRT_TYPE_PEER_PORT;
			goto ok;
		}
	}

	for (i = 0; i < pports_range_number / 2; ++i) {
		if (port < pports_range[i * 2])
			continue;

		if (port > pports_range[i * 2 + 1])
			continue;

		type = TCPRT_TYPE_PEER_PORT_RANG;
		goto ok;
	}

	return -1;
ok:
	rt = kmalloc(sizeof(*rt), GFP_ATOMIC);
	if (!rt)
		return -1;

	memset(rt, 0, sizeof(*rt));

	icsk->icsk_tcp_rt_priv = (void *)rt;

	rt->type  = type;
	rt->index = i;

	rt->con_start_seq = tp->snd_nxt;
	rt->con_rcv_nxt = tp->rcv_nxt;

	/* because recv_data is after rcv_nxt update, so
	 * record the value at here.
	 */
	rt->start_rcv_nxt = tp->rcv_nxt;
	rt->start_seq = tp->snd_nxt;
	ktime_get_real_ts64(&rt->con_start_time);
	return 0;
}

static struct tcp_rt_ops rt_ops __read_mostly = {
	.owner      = THIS_MODULE,
	.init       = tcp_rt_sk_init,
	.recv_data  = tcp_rt_sk_recv_data,
	.send_data  = tcp_rt_sk_send_data,
	.pkts_acked = tcp_rt_sk_pkts_acked,
	.release    = tcp_rt_sk_release,
};

static ssize_t tcp_rt_deactivate(struct file *file, const char __user *buff,
				 size_t count, loff_t *offset)
{
	pr_info("tcp-rt: deactivate\n");
	tcp_unregister_rt(&rt_ops);
	return count;
}

static const struct file_operations fops = {
	.owner      = THIS_MODULE,
	.write      = tcp_rt_deactivate,
};

static int __init tcp_rt_module_init(void)
{
	int ret;

	ret = tcp_rt_output_init(log_buf_num, stats_buf_num, &fops);
	if (ret)
		return ret;

	ret = tcp_register_rt(&rt_ops);
	if (ret) {
		pr_err("tcp-rt register rt failed!\n");
		tcp_rt_output_released();
		return ret;
	}

	timer_setup(&tcp_rt_timer, tcp_rt_timer_handler, 0);
	tcp_rt_timer.expires = jiffies + 10 * HZ;
	add_timer(&tcp_rt_timer);

	pr_info("tcp-rt: module load success\n");
	return 0;
}

static void __exit tcp_rt_module_fini(void)
{
	del_timer_sync(&tcp_rt_timer);
	tcp_rt_output_released();
	pr_info("tcp-rt: module unloaded\n");
}

module_init(tcp_rt_module_init);
module_exit(tcp_rt_module_fini);

MODULE_AUTHOR("xuanzhuo <xuanzhuo@linux.alibaba.com>");
MODULE_AUTHOR("Cambda Zhu <cambda@linux.alibaba.com>");
MODULE_AUTHOR("Ya Zhao <zhaoya123@linux.alibaba.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP RT");
