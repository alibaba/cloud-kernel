// SPDX-License-Identifier: GPL-2.0

#include <linux/relay.h>
#include "tcp_rt.h"

#define CHUNK_SIZE      (4096)
#define PORTS_PER_CHUNK (CHUNK_SIZE / sizeof(struct tcp_rt_stats))
#define PORT_TOTAL_NUM  (U16_MAX + 1)
#define CHUNK_COUNT     (PORT_TOTAL_NUM / PORTS_PER_CHUNK + 1)

static struct rchan *relay_log;
static struct rchan *relay_stats;
static struct dentry *tcprt_dir;

static struct tcp_rt_stats *stats_local[CHUNK_COUNT];
static struct tcp_rt_stats  stats_peer[PORT_MAX_NUM];

#define stats_local_inc(item)      atomic64_inc(&(item))
#define stats_local_add(item, val) atomic64_add(val, &(item))

#define stats_peer_inc(rt, item)      \
	atomic64_inc(&stats_peer[(rt)->index].item)
#define stats_peer_add(rt, item, val) \
	atomic64_add(val, &stats_peer[(rt)->index].item)

#define tcp_rt_get_local_stats_sk(sk) \
	tcp_rt_get_local_stats(ntohs(inet_sk(sk)->inet_sport), true)

static int64_t timespec64_dec(struct timespec64 tv1, struct timespec64 tv2)
{
	return (tv1.tv_sec - tv2.tv_sec) * 1000000 +
		(tv1.tv_nsec - tv2.tv_nsec) / 1000;
}

static int ulong_format(char *buf, unsigned long val)
{
	int idx = 0;
	int i;
	char tmp[80];

	if (val == 0) {
		tmp[idx++] = '0';
	} else {
		while (val != 0) {
			tmp[idx++] = (val % 10) + '0';
			val /= 10;
		}
	}
	for (i = 0; i < idx; i++)
		buf[i] = tmp[idx - i - 1];

	return idx;
}

static int ulong_format2(char *buf, unsigned long val)
{
	int idx = 0;

	idx += ulong_format(buf, val);
	buf[idx++] = ' ';
	return idx;
}

static int ip_format2(char *buf, u32 addr, char end)
{
	unsigned char *s = (unsigned char *)&addr;
	int idx = 0;

	idx += ulong_format(buf + idx, (unsigned long)s[0]);
	buf[idx++] = '.';
	idx += ulong_format(buf + idx, (unsigned long)s[1]);
	buf[idx++] = '.';
	idx += ulong_format(buf + idx, (unsigned long)s[2]);
	buf[idx++] = '.';
	idx += ulong_format(buf + idx, (unsigned long)s[3]);
	buf[idx++] = end;
	return idx;
}

static struct tcp_rt_stats *tcp_rt_get_local_stats(int port, bool alloc)
{
	int chunkid;
	struct tcp_rt_stats *p;

	chunkid = port / PORTS_PER_CHUNK;

	p = stats_local[chunkid];

	if (unlikely(!p)) {
		if (!alloc)
			return NULL;

		p = kmalloc(CHUNK_SIZE, GFP_ATOMIC);
		if (!p)
			return NULL;

		memset(p, 0, CHUNK_SIZE);

		if (cmpxchg(&stats_local[chunkid], NULL, p)) {
			vfree(p);
			p = READ_ONCE(stats_local[chunkid]);
		}
	}

	return p + (port - chunkid * PORTS_PER_CHUNK);
}

#define  bufappend(buf, size, v)  \
	ulong_format2((buf) + (size), (unsigned long)(v))

static int bufheader(char *buf, int size, char flag,
		     const struct sock *sk)
{
	struct tcp_rt *rt = TCP_SK_RT(sk);
	int n = 0;

	buf[n++] = 'V';
	buf[n++] = '6';
	buf[n++] = ' ';
	buf[n++] = flag;
	buf[n++] = ' ';

	n += bufappend(buf, n, rt->start_time.tv_sec);
	n += bufappend(buf, n, rt->start_time.tv_nsec / 1000);
	n += ip_format2(buf + n, (u32)(inet_sk(sk)->inet_daddr), ':');
	n += bufappend(buf, n, ntohs(inet_sk(sk)->inet_dport));
	n += ip_format2(buf + n, (u32)(inet_sk(sk)->inet_saddr), ':');
	n += bufappend(buf, n, ntohs(inet_sk(sk)->inet_sport));

	return n;
}

void tcp_rt_log_printk(const struct sock *sk, char flag, bool fin, bool stats)
{
#define MAX_BUF_SIZE 512

	struct tcp_rt_stats *r;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_rt *rt = TCP_SK_RT(sk);
	char buf[MAX_BUF_SIZE];
	int size = 0;
	u32 t_rt;
	u32 t_seq, t_retrans;
	struct timespec64 now;
	u32 start_time, mrtt;

	mrtt = tcp_min_rtt(tp) >> 10;

	start_time = rt->start_time.tv_sec;

	switch (flag) {
	case LOG_STATUS_R:
		t_rt =	timespec64_dec(rt->end_time, rt->start_time);
		t_seq = tp->snd_nxt - rt->start_seq;

		/* When come from socket closing, the snd_nxt may include fin,
		 * so add this options.
		 * In some cases, there may be no fin, but here is also
		 * reduced by one byte. But one byte has little effect.
		 */
		if (fin)
			--t_seq;

		t_retrans = tp->total_retrans - rt->last_total_retrans;

		size = bufheader(buf, size, flag, sk);

		size += bufappend(buf, size, t_seq);
		size += bufappend(buf, size, t_rt);
		size += bufappend(buf, size, mrtt);
		size += bufappend(buf, size, t_retrans);
		size += bufappend(buf, size, rt->request_num);
		size += bufappend(buf, size, rt->server_time);
		size += bufappend(buf, size, rt->upload_time);
		size += bufappend(buf, size, rt->upload_data);
		size += bufappend(buf, size, rt->rcv_reorder);
		size += bufappend(buf, size, tp->mss_cache);
		buf[size++] = '\n';

		if (stats && t_seq > 0) {
			r = tcp_rt_get_local_stats_sk(sk);
			if (!r)
				break;

			stats_local_inc(r->number);

			stats_local_add(r->rt, t_rt);
			stats_local_add(r->bytes, t_seq);
			stats_local_add(r->drop, t_retrans);
			stats_local_add(r->packets,
					t_seq / tp->mss_cache + 1);
			stats_local_add(r->server_time, rt->server_time);
			stats_local_add(r->upload_time, rt->upload_time);
			stats_local_add(r->upload_data, rt->upload_data);
		}
		break;

	case LOG_STATUS_W:
		ktime_get_real_ts64(&now);
		t_rt =	timespec64_dec(now, rt->start_time);

		size = bufheader(buf, size, flag, sk);

		size += bufappend(buf, size, tp->snd_nxt - rt->start_seq);
		size += bufappend(buf, size, t_rt);
		size += bufappend(buf, size, mrtt);
		size += bufappend(buf, size,
				  tp->total_retrans - rt->last_total_retrans);
		size += bufappend(buf, size, rt->request_num);
		size += bufappend(buf, size, rt->server_time);
		size += bufappend(buf, size, rt->upload_time);
		size += bufappend(buf, size, tp->snd_nxt - tp->snd_una);
		size += bufappend(buf, size, rt->rcv_reorder);
		size += bufappend(buf, size, tp->mss_cache);
		buf[size++] = '\n';

		if (stats && t_rt > HZ / 10) {
			r = tcp_rt_get_local_stats_sk(sk);
			if (!r)
				break;

			stats_local_inc(r->fail);
		}
		break;

	case LOG_STATUS_N:
		ktime_get_real_ts64(&now);
		t_rt = timespec64_dec(now, rt->start_time);

		size = bufheader(buf, size, flag, sk);

		size += bufappend(buf, size, rt->request_num);
		size += bufappend(buf, size, t_rt);
		size += bufappend(buf, size, tp->rcv_nxt - rt->start_rcv_nxt);
		size += bufappend(buf, size, rt->rcv_reorder);
		size += bufappend(buf, size, tp->mss_cache);
		buf[size++] = '\n';
		break;

	case LOG_STATUS_E:
		size = bufheader(buf, size, flag, sk);

		size += bufappend(buf, size, rt->request_num);
		size += bufappend(buf, size, tp->snd_nxt - rt->con_start_seq);
		size += bufappend(buf, size, tp->snd_nxt - tp->snd_una);
		size += bufappend(buf, size, tp->rcv_nxt - rt->con_rcv_nxt);
		size += bufappend(buf, size, tp->total_retrans);
		size += bufappend(buf, size, mrtt);
		buf[size++] = '\n';

		if (mrtt > 0) {
			r = tcp_rt_get_local_stats_sk(sk);
			if (!r)
				break;

			stats_local_inc(r->con_num);
			stats_local_add(r->rtt, mrtt);
		}
		break;

	case LOG_STATUS_P:
		t_seq = rt->upload_data;
		t_retrans = tp->total_retrans - rt->last_total_retrans;

		size = bufheader(buf, size, flag, sk);

		size += bufappend(buf, size, t_seq);
		size += bufappend(buf, size, t_retrans);
		size += bufappend(buf, size, rt->request_num);
		size += bufappend(buf, size, mrtt);
		size += bufappend(buf, size, tp->mss_cache);
		buf[size++] = '\n';

		if (stats) {
			stats_peer_inc(rt, number);
			stats_peer_inc(rt, con_num);
			stats_peer_add(rt, bytes, t_seq);
			stats_peer_add(rt, rtt, mrtt);
			stats_peer_add(rt, packets, t_seq / tp->mss_cache + 1);
			stats_peer_add(rt, drop, t_retrans);
		}
		break;
	}

	if (relay_log)
		relay_write(relay_log, buf, size);
}

void tcp_rt_timer_output(int index, int port, char *flag)
{
	struct tcp_rt_stats *r;
	struct _tcp_rt_stats t;
	struct _tcp_rt_stats avg = {0};
	int size;

	char buf[MAX_BUF_SIZE];

	if (*flag == 'L') {
		if (index == PORT_MAX_NUM)
			r = tcp_rt_get_local_stats(port, false);
		else
			r = tcp_rt_get_local_stats(port, true);

		if (!r)
			return;

		flag = "";
	} else {
		r = stats_peer + index;
	}

	t.number = atomic64_read(&r->number);
	if (!t.number && index == PORT_MAX_NUM)
		return;

	t.rt          = atomic64_read(&r->rt);
	t.bytes       = atomic64_read(&r->bytes);
	t.drop        = atomic64_read(&r->drop);
	t.fail        = atomic64_read(&r->fail);
	t.server_time = atomic64_read(&r->server_time);
	t.packets     = atomic64_read(&r->packets);
	t.con_num     = atomic64_read(&r->con_num);
	t.rtt         = atomic64_read(&r->rtt);
	t.upload_time = atomic64_read(&r->upload_time);
	t.upload_data = atomic64_read(&r->upload_data);

	if (t.number > 0) {
		avg.rt           = t.rt / t.number;
		avg.fail         = 1000 * t.fail / t.number;
		avg.bytes        = t.bytes / t.number;
		avg.server_time  = t.server_time / t.number;
		avg.upload_time  = t.upload_time / t.number;
		avg.upload_data  = t.upload_data / t.number;
		if (t.packets > 0)
			avg.drop = 1000 * t.drop / t.packets;
	}

	if (t.con_num > 0)
		avg.rtt = t.rtt / t.con_num;

	size = snprintf(buf, sizeof(buf),
			"%llu all %s%u %u %u %u %u %u %u %u %u %u\n",
			ktime_get_real_seconds(), flag, port, avg.rt,
			avg.server_time, avg.drop, avg.rtt, avg.fail, avg.bytes,
			avg.upload_time, avg.upload_data, t.number);

	if (relay_stats)
		relay_write(relay_stats, buf, size);

	atomic64_set(&r->rt, 0);
	atomic64_set(&r->number, 0);
	atomic64_set(&r->bytes, 0);
	atomic64_set(&r->drop, 0);
	atomic64_set(&r->fail, 0);
	atomic64_set(&r->server_time, 0);
	atomic64_set(&r->packets, 0);
	atomic64_set(&r->con_num, 0);
	atomic64_set(&r->rtt, 0);
	atomic64_set(&r->upload_time, 0);
	atomic64_set(&r->upload_data, 0);
}

static struct dentry *create_buf_file_handler(const char *filename,
					      struct dentry *parent,
					      umode_t mode,
					      struct rchan_buf *buf,
					      int *is_global)
{
	return debugfs_create_file(filename, mode, tcprt_dir, buf,
				   &relay_file_operations);
}

static int remove_buf_file_handler(struct dentry *dentry)
{
	debugfs_remove(dentry);
	return 0;
}

static struct rchan_callbacks relay_callbacks = {
	.create_buf_file = create_buf_file_handler,
	.remove_buf_file = remove_buf_file_handler,
};

int tcp_rt_output_init(int log_buf_num, int stats_buf_num,
		       const struct file_operations *fops)
{
	tcprt_dir = debugfs_create_dir("tcp-rt", NULL);
	if (!tcprt_dir)
		return -1;

	if (!debugfs_create_file("deactivate", 0600, tcprt_dir, NULL, fops)) {
		debugfs_remove_recursive(tcprt_dir);
		pr_err("tcp-rt: register debugfs deactivate fail!\n");
		return -1;
	}

	relay_log = relay_open("rt-network-log", NULL, LOG_SUBBUF_SIZE,
			       log_buf_num, &relay_callbacks, NULL);
	if (!relay_log) {
		debugfs_remove_recursive(tcprt_dir);
		tcprt_dir = NULL;
		pr_err("tcp-rt: create relay_log failed!\n");
		return -1;
	}
	pr_info("tcp-rt: relay_log ready!\n");

	relay_stats = relay_open("rt-network-real", NULL, STATS_SUBBUF_SIZE,
				 stats_buf_num, &relay_callbacks, NULL);
	if (!relay_stats) {
		relay_close(relay_log);
		relay_log = NULL;
		debugfs_remove_recursive(tcprt_dir);
		tcprt_dir = NULL;
		pr_err("tcp-rt: create relay_stats failed!\n");
		return -1;
	}

	pr_info("tcp_rt: relay_stats ready!\n");
	return 0;
}

void tcp_rt_output_released(void)
{
	int i;

	relay_close(relay_log);
	relay_close(relay_stats);
	debugfs_remove_recursive(tcprt_dir);

	for (i = 0; i < ARRAY_SIZE(stats_local); ++i)
		kfree(stats_local[i]);

	pr_info("tcp-rt: output released\n");
}
