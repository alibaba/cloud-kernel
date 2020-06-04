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
static struct tcp_rt_stats *stats_peer[CHUNK_COUNT];

#define stats_inc(item)      atomic64_inc(&(item))
#define stats_add(item, val) atomic64_add(val, &(item))

#define tcp_rt_get_local_stats_sk(sk) \
	tcp_rt_get_stats(stats_local, ntohs(inet_sk(sk)->inet_sport), true)

#define tcp_rt_get_peer_stats_sk(sk) \
	tcp_rt_get_stats(stats_peer, ntohs(inet_sk(sk)->inet_dport), true)

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

static struct tcp_rt_stats *tcp_rt_get_stats(struct tcp_rt_stats **stats,
					     int port, bool alloc)
{
	int chunkid;
	struct tcp_rt_stats *p;

	chunkid = port / PORTS_PER_CHUNK;

	p = stats[chunkid];

	if (unlikely(!p)) {
		if (!alloc)
			return NULL;

		p = kmalloc(CHUNK_SIZE, GFP_ATOMIC);
		if (!p)
			return NULL;

		memset(p, 0, CHUNK_SIZE);

		if (cmpxchg(&stats[chunkid], NULL, p)) {
			vfree(p);
			p = READ_ONCE(stats[chunkid]);
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

	mrtt = tcp_min_rtt(tp);

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

			stats_inc(r->number);

			stats_add(r->rt,          t_rt);
			stats_add(r->bytes,       t_seq);
			stats_add(r->drop,        t_retrans);
			stats_add(r->packets,     t_seq / tp->mss_cache + 1);
			stats_add(r->server_time, rt->server_time);
			stats_add(r->upload_time, rt->upload_time);
			stats_add(r->upload_data, rt->upload_data);
			stats_add(r->rtt,         mrtt);
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

			stats_inc(r->fail);
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
		break;

	case LOG_STATUS_P:
		t_rt =	timespec64_dec(rt->end_time, rt->start_time);

		t_seq = rt->upload_data;
		t_retrans = tp->total_retrans - rt->last_total_retrans;

		size = bufheader(buf, size, flag, sk);

		size += bufappend(buf, size, t_seq);
		size += bufappend(buf, size, t_rt);
		size += bufappend(buf, size, t_retrans);
		size += bufappend(buf, size, rt->request_num);
		size += bufappend(buf, size, mrtt);
		size += bufappend(buf, size, rt->rcv_reorder);
		size += bufappend(buf, size, tp->mss_cache);
		buf[size++] = '\n';

		if (stats) {
			r = tcp_rt_get_peer_stats_sk(sk);
			if (!r)
				break;

			stats_inc(r->number);

			stats_add(r->bytes,   t_seq);
			stats_add(r->rt,      t_rt);
			stats_add(r->packets, t_seq / tp->mss_cache + 1);
			stats_add(r->drop,    t_retrans);
			stats_add(r->rtt,     mrtt);
		}
		break;
	}

	if (relay_log)
		relay_write(relay_log, buf, size);
}

void tcp_rt_timer_output(int port, char *flag, bool alloc)
{
	struct tcp_rt_stats *r;
	struct tcp_rt_stats **stats;
	struct _tcp_rt_stats t;
	struct _tcp_rt_stats avg = {0};
	int size;

	char buf[MAX_BUF_SIZE];

	if (*flag == 'L') {
		flag = "";
		stats = stats_local;
	} else {
		stats = stats_peer;
	}

	r = tcp_rt_get_stats(stats, port, alloc);

	if (!r)
		return;

	t.number = atomic64_xchg(&r->number, 0);
	if (!t.number && !alloc)
		return;

	t.server_time = atomic64_xchg(&r->server_time, 0);
	t.rt          = atomic64_xchg(&r->rt,          0);
	t.bytes       = atomic64_xchg(&r->bytes,       0);
	t.drop        = atomic64_xchg(&r->drop,        0);
	t.fail        = atomic64_xchg(&r->fail,        0);
	t.packets     = atomic64_xchg(&r->packets,     0);
	t.rtt         = atomic64_xchg(&r->rtt,         0);
	t.upload_time = atomic64_xchg(&r->upload_time, 0);
	t.upload_data = atomic64_xchg(&r->upload_data, 0);

	if (t.number > 0) {
		avg.rt           = t.rt / t.number;
		avg.fail         = 1000 * t.fail / t.number;
		avg.bytes        = t.bytes / t.number;
		avg.server_time  = t.server_time / t.number;
		avg.upload_time  = t.upload_time / t.number;
		avg.upload_data  = t.upload_data / t.number;
		avg.rtt          = t.rtt / t.number;
		if (t.packets > 0)
			avg.drop = 1000 * t.drop / t.packets;
	}

	size = snprintf(buf, sizeof(buf),
			"%llu all %s%u %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
			ktime_get_real_seconds(), flag, port, avg.rt,
			avg.server_time, avg.drop, avg.rtt, avg.fail, avg.bytes,
			avg.upload_time, avg.upload_data, t.number);

	if (relay_stats)
		relay_write(relay_stats, buf, size);
}

static struct dentry *create_buf_file_handler(const char *filename,
					      struct dentry *parent,
					      umode_t mode,
					      struct rchan_buf *buf,
					      int *is_global)
{
	if (buf->chan->private_data) {
		*is_global = 1;
		filename = "rt-network-stats";
	}

	return debugfs_create_file(filename, mode, parent, buf,
				   &relay_file_operations);
}

static int remove_buf_file_handler(struct dentry *dentry)
{
	debugfs_remove(dentry);
	return 0;
}

static int subbuf_start(struct rchan_buf *buf,
			void *subbuf,
			void *prev_subbuf,
			size_t prev_padding)
{
	return 1;
}

static struct rchan_callbacks relay_callbacks = {
	.create_buf_file = create_buf_file_handler,
	.remove_buf_file = remove_buf_file_handler,
	.subbuf_start    = subbuf_start,
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

	relay_log = relay_open("rt-network-log", tcprt_dir, LOG_SUBBUF_SIZE,
			       log_buf_num, &relay_callbacks, NULL);
	if (!relay_log) {
		debugfs_remove_recursive(tcprt_dir);
		tcprt_dir = NULL;
		pr_err("tcp-rt: create relay_log failed!\n");
		return -1;
	}
	pr_info("tcp-rt: relay_log ready!\n");

	relay_stats = relay_open("rt-network-stats", tcprt_dir,
				 STATS_SUBBUF_SIZE, stats_buf_num,
				 &relay_callbacks, (void *)1);
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
