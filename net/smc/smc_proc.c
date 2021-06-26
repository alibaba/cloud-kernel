// SPDX-License-Identifier: GPL-2.0-only
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include "smc.h"
#include "smc_proc.h"
#include "smc_core.h"

static void *smc_get_next(struct seq_file *seq, void *cur)
{
	struct smc_proc_private *sp = seq->private;
	struct smc_hashinfo *smc_hash =
		sp->protocol == SMCPROTO_SMC ?
		smc_proto.h.smc_hash : smc_proto6.h.smc_hash;
	struct net *net = seq_file_net(seq);
	struct hlist_head *head;
	struct sock *sk = cur;

	if (!sk) {
		read_lock(&smc_hash->lock);
get_head:
		head = &smc_hash->ht[sp->bucket];
		sk = sk_head(head);
		sp->offset = 0;
		goto get_sk;
	}
	++sp->num;
	++sp->offset;

	sk = sk_next(sk);
get_sk:
	sk_for_each_from(sk) {
		if (!net_eq(sock_net(sk), net))
			continue;
		return sk;
	}
	sp->offset = 0;
	if (++sp->bucket < SMC_HTABLE_SIZE)
		goto get_head;

	read_unlock(&smc_hash->lock);
	return NULL;
}

static void *smc_seek_last_pos(struct seq_file *seq)
{
	struct smc_proc_private *sp = seq->private;
	int offset = sp->offset;
	int orig_num = sp->num;
	void *rc = NULL;

	if (sp->bucket >= SMC_HTABLE_SIZE)
		goto out;

	rc = smc_get_next(seq, NULL);
	while (offset-- && rc)
		rc = smc_get_next(seq, rc);

	if (rc)
		goto out;

	sp->bucket = 0;
out:
	sp->num = orig_num;
	return rc;
}

static void *smc_get_idx(struct seq_file *seq, loff_t pos)
{
	struct smc_proc_private *sp = seq->private;
	void *rc;

	sp->bucket = 0;
	rc = smc_get_next(seq, NULL);

	while (rc && pos) {
		rc = smc_get_next(seq, rc);
		--pos;
	}
	return rc;
}

static void *_smc_conn_start(struct seq_file *seq, loff_t *pos, int protocol)
{
	struct smc_proc_private *sp = seq->private;
	void *rc;

	if (*pos && *pos == sp->last_pos) {
		rc = smc_seek_last_pos(seq);
		if (rc)
			goto out;
	}

	sp->num = 0;
	sp->bucket = 0;
	sp->offset = 0;
	sp->protocol = protocol;
	rc = *pos ? smc_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;

out:
	sp->last_pos = *pos;
	return rc;
}

static void *smc_conn4_start(struct seq_file *seq, loff_t *pos)
{
	return _smc_conn_start(seq, pos, SMCPROTO_SMC);
}

static void *smc_conn6_start(struct seq_file *seq, loff_t *pos)
{
	return _smc_conn_start(seq, pos, SMCPROTO_SMC6);
}

static void _conn_show(struct seq_file *seq, struct smc_sock *smc, int protocol)
{
	struct smc_proc_private *sp = seq->private;
	const struct in6_addr *dest, *src;
	struct smc_link_group *lgr;
	struct socket *clcsock;
	struct smc_link *lnk;
	struct sock *sk;
	bool fb = false;
	int i;

	fb = smc->use_fallback;
	clcsock = smc->clcsock;
	sk = &smc->sk;

	if (protocol == SMCPROTO_SMC)
		seq_printf(seq, CONN4_ADDR_FM, sp->num,
			   clcsock->sk->sk_rcv_saddr, clcsock->sk->sk_num,
			   clcsock->sk->sk_daddr, ntohs(clcsock->sk->sk_dport));
	else if (protocol == SMCPROTO_SMC6) {
		dest	= &clcsock->sk->sk_v6_daddr;
		src	= &clcsock->sk->sk_v6_rcv_saddr;
		seq_printf(seq, CONN6_ADDR_FM, sp->num,
			   src->s6_addr32[0], src->s6_addr32[1],
			   src->s6_addr32[2], src->s6_addr32[3], clcsock->sk->sk_num,
			   dest->s6_addr32[0], dest->s6_addr32[1],
			   dest->s6_addr32[2], dest->s6_addr32[3], ntohs(clcsock->sk->sk_dport));
	}

	seq_printf(seq, CONN_SK_FM, fb ? 'Y' : 'N', fb ? smc->fallback_rsn : 0,
		   sk, clcsock->sk, fb ? clcsock->sk->sk_state : sk->sk_state, sock_i_ino(sk));

	lgr = smc->conn.lgr;
	lnk = smc->conn.lnk;

	if (!fb && sk->sk_state == SMC_ACTIVE && lgr && lnk) {
		for (i = 0; i < SMC_LGR_ID_SIZE; i++)
			seq_printf(seq, "%02X", lgr->id[i]);

		seq_printf(seq, CONN_LGR_FM, lgr->role == SMC_CLNT ? 'C' : 'S',
			   lnk->ibname, lnk->ibport, lnk->ib_qp->qp_num,
			   lnk->peer_qpn, lnk->wr_tx_cnt, lnk->wr_rx_cnt);
	} else {
		seq_puts(seq, "-          -          -        -     -     -      -        -\n");
	}
}

static int smc_conn_show(struct seq_file *seq, void *v)
{
	struct smc_proc_private *sp = seq->private;
	struct socket *clcsock;
	struct smc_sock *smc;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, sp->protocol == SMCPROTO_SMC ? CONN4_HDR : CONN6_HDR,
			   "sl", "local_addr", "remote_addr", "is_fb", "fb_rsn", "sock",
			   "clc_sock", "st", "inode", "lgr_id", "lgr_role", "dev", "port",
			   "l_qp", "r_qp", "tx_cnt", "rx_cnt");
		goto out;
	}

	smc = smc_sk(v);
	clcsock = smc->clcsock;
	if (!clcsock)
		goto out;

	_conn_show(seq, smc, sp->protocol);
out:
	return 0;
}

static void *smc_conn_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct smc_proc_private *sp = seq->private;
	void *rc = NULL;

	if (v == SEQ_START_TOKEN) {
		rc = smc_get_idx(seq, 0);
		goto out;
	}
	rc = smc_get_next(seq, v);
out:
	++*pos;
	sp->last_pos = *pos;
	return rc;
}

static void smc_conn_stop(struct seq_file *seq, void *v)
{
	struct smc_proc_private *sp = seq->private;
	struct smc_hashinfo *smc_hash =
		sp->protocol == SMCPROTO_SMC ?
		smc_proto.h.smc_hash : smc_proto6.h.smc_hash;

	if (v && v != SEQ_START_TOKEN)
		read_unlock(&smc_hash->lock);
}

static struct smc_proc_entry smc_proc[] = {
	{
		.name	= "smc4",
		.ops = {
			.show	= smc_conn_show,
			.start	= smc_conn4_start,
			.next	= smc_conn_next,
			.stop	= smc_conn_stop,
		},
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.name	= "smc6",
		.ops = {
			.show	= smc_conn_show,
			.start	= smc_conn6_start,
			.next	= smc_conn_next,
			.stop	= smc_conn_stop,
		},
	},
#endif
};

static int __net_init smc_proc_dir_init(struct net *net)
{
	int i, rc = -ENOMEM;

	net->proc_net_smc = proc_net_mkdir(net, "smc", net->proc_net);
	if (!net->proc_net_smc)
		goto err;

	for (i = 0; i < ARRAY_SIZE(smc_proc); i++) {
		if (!proc_create_net_data(smc_proc[i].name, 0444,
					  net->proc_net_smc, &smc_proc[i].ops,
					  sizeof(struct smc_proc_private),
					  NULL))
			goto err_entry;
	}

	return 0;

err_entry:
	for (i -= 1; i >= 0; i--)
		remove_proc_entry(smc_proc[i].name, net->proc_net_smc);

	remove_proc_entry("smc", net->proc_net);
err:
	return rc;
}

static void __net_exit smc_proc_dir_exit(struct net *net)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(smc_proc); i++)
		remove_proc_entry(smc_proc[i].name, net->proc_net_smc);

	remove_proc_entry("smc", net->proc_net);
}

static struct pernet_operations smc_proc_ops = {
	.init = smc_proc_dir_init,
	.exit = smc_proc_dir_exit,
};

int __init smc_proc_init(void)
{
	return register_pernet_subsys(&smc_proc_ops);
}

void smc_proc_exit(void)
{
	unregister_pernet_subsys(&smc_proc_ops);
}
