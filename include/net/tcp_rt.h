/* SPDX-License-Identifier: GPL-2.0
 *
 * TcpRT        Instrument and Diagnostic Analysis System for Service Quality
 *              of Cloud Databases at Massive Scale in Real-time.
 *
 *              It can also provide information for all request/response
 *              services. Such as HTTP request.
 *
 *              This is the kernel framework, more work needs tcprt module
 *              support.
 */
#ifndef _TCP_RT_H
#define _TCP_RT_H

#ifdef CONFIG_TCP_RT
struct tcp_rt_ops {
	/*
	 * initialize private data (required)
	 *
	 * ret:
	 *    0: success alloc private data for this connection.
	 *   -1: fail alloc private data or not care about this connection.
	 *       Then this connection will not ref to tcp_rt.
	 */
	int (*init)(struct sock *sk);

	/* cleanup private data  (required) */
	void (*release)(struct sock *sk);

	/* recv data */
	void  (*recv_data)(struct sock *sk);

	/* send data */
	void  (*send_data)(struct sock *sk);

	/* hook for packet ack accounting */
	void (*pkts_acked)(struct sock *sk);

	struct module *owner;
};

/*
 * tcp_register_rt() - register tcp_rt ops to kernel
 * @rt: tcp_rt_ops
 *
 * ret:
 *    -EINVAL: init or release of ops not init.
 *    -EBUSY: fail to get the moudle.
 *    -EEXIST: there exists one tcprt.
 *    0: success
 */

int tcp_register_rt(const struct tcp_rt_ops *rt);

/*
 * tcp_unregister_rt() - unregister the tcp_rt ops from kernel.
 *
 * After call this, the new connection will no ref to the tcp_rt, but
 * the old connection still ref to the tcp_rt, you must wait for all
 * old connection been released, then you can try to rmmod module.
 * So, this function cannot been called inside the module_exit.
 * You should call this by such as debugfs. such as:
 *
 * ----
 * static ssize_t tcp_rt_inactive(struct file *file, const char __user *buff,
 *                size_t count, loff_t *offset)
 * {
 *      tcp_unregister_rt(&rt_ops);
 *      return count;
 * }
 *
 * static struct file_operations fops = {
 *      .owner      = THIS_MODULE,
 *      .write      = tcp_rt_inactive,
 * };
 *
 * static int __init rt_register(void)
 * {
 *      if (!debugfs_create_file("tcp-rt-no-active", 0600, NULL, NULL, fops)) {
 *              return -1;
 *      }
 *
 *      ret = tcp_register_rt(&rt_ops);
 *      if (ret) {
 *              pr_err("tcp-rt register rt failed!\n");
 *              tcp_rt_base_released();
 *              return ret;
 *      }
 *
 *      return 0;
 * }
 *
 * static void __exit rt_unregister(void)
 * {
 *      pr_info("tcp-rt: released\n");
 * }
 *
 * module_init(rt_register);
 * module_exit(rt_unregister);
 * ----
 *
 *  run this cmd before you want to rmmod module:
 *  echo 0 > /sys/kernel/debug/tcp-rt-no-active
 *
 */
void tcp_unregister_rt(struct tcp_rt_ops *rt);
void tcp_init_rt(struct sock *sk);
void tcp_cleanup_rt(struct sock *sk);

#define tcp_rt_call(sk, fun)  \
	do {                                                        \
		if (inet_csk(sk)->icsk_tcp_rt_ops &&                \
				inet_csk(sk)->icsk_tcp_rt_ops->fun) \
			inet_csk(sk)->icsk_tcp_rt_ops->fun(sk);     \
	} while (0)
#else
#define tcp_cleanup_rt(sk)
#define tcp_init_rt(sk)
#define tcp_rt_call(sk, fun)
#endif

#endif	/* _TCP_RT_H */
