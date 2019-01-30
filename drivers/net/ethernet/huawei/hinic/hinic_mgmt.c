// SPDX-License-Identifier: GPL-2.0
/* Huawei HiNIC PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/semaphore.h>

#include "ossl_knl.h"
#include "hinic_hw.h"
#include "hinic_hw_mgmt.h"
#include "hinic_hwdev.h"

#include "hinic_hwif.h"
#include "hinic_api_cmd.h"
#include "hinic_mgmt.h"
#include "hinic_eqs.h"

#define BUF_OUT_DEFAULT_SIZE		1
#define SEGMENT_LEN			48

#define MAX_PF_MGMT_BUF_SIZE		2048UL

#define MGMT_MSG_SIZE_MIN		20
#define MGMT_MSG_SIZE_STEP		16
#define	MGMT_MSG_RSVD_FOR_DEV		8

#define MGMT_MSG_TIMEOUT		5000	/* millisecond */

#define SYNC_MSG_ID_MASK		0x1FF
#define ASYNC_MSG_ID_MASK		0x1FF
#define ASYNC_MSG_FLAG			0x200

#define MSG_NO_RESP			0xFFFF

#define MAX_MSG_SZ			2016

#define MSG_SZ_IS_VALID(in_size)	((in_size) <= MAX_MSG_SZ)

#define SYNC_MSG_ID(pf_to_mgmt)	((pf_to_mgmt)->sync_msg_id)

#define SYNC_MSG_ID_INC(pf_to_mgmt)	(SYNC_MSG_ID(pf_to_mgmt) = \
			(SYNC_MSG_ID(pf_to_mgmt) + 1) & SYNC_MSG_ID_MASK)

#define ASYNC_MSG_ID(pf_to_mgmt)	((pf_to_mgmt)->async_msg_id)

#define ASYNC_MSG_ID_INC(pf_to_mgmt)	(ASYNC_MSG_ID(pf_to_mgmt) = \
			((ASYNC_MSG_ID(pf_to_mgmt) + 1) & ASYNC_MSG_ID_MASK) \
			| ASYNC_MSG_FLAG)

static void pf_to_mgmt_send_event_set(struct hinic_msg_pf_to_mgmt *pf_to_mgmt,
				      int event_flag)
{
	down(&pf_to_mgmt->msg_sem);
	pf_to_mgmt->event_flag = event_flag;
	up(&pf_to_mgmt->msg_sem);
}

/**
 * hinic_register_mgmt_msg_cb - register sync msg handler for a module
 * @pf_to_mgmt: PF to MGMT channel
 * @mod: module in the chip that this handler will handle its sync messages
 * @callback: the handler for a sync message that will handle messages
 **/
int hinic_register_mgmt_msg_cb(void *hwdev, enum hinic_mod_type mod,
			       void *pri_handle, hinic_mgmt_msg_cb callback)
{
	struct hinic_msg_pf_to_mgmt *pf_to_mgmt;

	if (mod >= HINIC_MOD_HW_MAX || !hwdev)
		return -EFAULT;

	pf_to_mgmt = ((struct hinic_hwdev *)hwdev)->pf_to_mgmt;
	if (!pf_to_mgmt)
		return -EINVAL;

	pf_to_mgmt->recv_mgmt_msg_cb[mod] = callback;
	pf_to_mgmt->recv_mgmt_msg_data[mod] = pri_handle;

	return 0;
}
EXPORT_SYMBOL(hinic_register_mgmt_msg_cb);

/**
 * hinic_unregister_mgmt_msg_cb - unregister sync msg handler for a module
 * @pf_to_mgmt: PF to MGMT channel
 * @mod: module in the chip that this handler will handle its sync messages
 **/
void hinic_unregister_mgmt_msg_cb(void *hwdev, enum hinic_mod_type mod)
{
	struct hinic_msg_pf_to_mgmt *pf_to_mgmt;

	if (!hwdev)
		return;

	pf_to_mgmt = ((struct hinic_hwdev *)hwdev)->pf_to_mgmt;
	if (!pf_to_mgmt)
		return;

	if (mod < HINIC_MOD_HW_MAX) {
		pf_to_mgmt->recv_mgmt_msg_cb[mod] = NULL;
		pf_to_mgmt->recv_mgmt_msg_data[mod] = NULL;
	}
}
EXPORT_SYMBOL(hinic_unregister_mgmt_msg_cb);

void hinic_comm_recv_mgmt_self_cmd_reg(void *hwdev, u8 cmd,
				       comm_up_self_msg_proc proc)
{
	struct hinic_msg_pf_to_mgmt *pf_to_mgmt;
	u8 cmd_idx;

	if (!hwdev || !proc)
		return;

	pf_to_mgmt = ((struct hinic_hwdev *)hwdev)->pf_to_mgmt;
	if (!pf_to_mgmt)
		return;

	cmd_idx = pf_to_mgmt->proc.cmd_num;
	if (cmd_idx >= HINIC_COMM_SELF_CMD_MAX) {
		sdk_err(pf_to_mgmt->hwdev->dev_hdl,
			"Register recv up process failed(cmd=0x%x)\r\n", cmd);
		return;
	}

	pf_to_mgmt->proc.info[cmd_idx].cmd = cmd;
	pf_to_mgmt->proc.info[cmd_idx].proc = proc;

	pf_to_mgmt->proc.cmd_num++;
}

void hinic_comm_recv_up_self_cmd_unreg(void *hwdev, u8 cmd)
{
	struct hinic_msg_pf_to_mgmt *pf_to_mgmt;
	u8 cmd_idx;

	if (!hwdev)
		return;

	pf_to_mgmt = ((struct hinic_hwdev *)hwdev)->pf_to_mgmt;
	if (!pf_to_mgmt)
		return;

	cmd_idx = pf_to_mgmt->proc.cmd_num;
	if (cmd_idx >= HINIC_COMM_SELF_CMD_MAX) {
		sdk_err(pf_to_mgmt->hwdev->dev_hdl,
			"Unregister recv up process failed(cmd=0x%x)\r\n", cmd);
		return;
	}

	for (cmd_idx = 0; cmd_idx < HINIC_COMM_SELF_CMD_MAX; cmd_idx++) {
		if (cmd == pf_to_mgmt->proc.info[cmd_idx].cmd) {
			pf_to_mgmt->proc.info[cmd_idx].cmd = 0;
			pf_to_mgmt->proc.info[cmd_idx].proc = NULL;
			pf_to_mgmt->proc.cmd_num--;
		}
	}
}

/**
 * mgmt_msg_len - calculate the total message length
 * @msg_data_len: the length of the message data
 * Return: the total message length
 **/
static u16 mgmt_msg_len(u16 msg_data_len)
{
	/* u64 - the size of the header */
	u16 msg_size;

	msg_size = (u16)(MGMT_MSG_RSVD_FOR_DEV + sizeof(u64) + msg_data_len);

	if (msg_size > MGMT_MSG_SIZE_MIN)
		msg_size = MGMT_MSG_SIZE_MIN +
				ALIGN((msg_size - MGMT_MSG_SIZE_MIN),
				      MGMT_MSG_SIZE_STEP);
	else
		msg_size = MGMT_MSG_SIZE_MIN;

	return msg_size;
}

/**
 * prepare_header - prepare the header of the message
 * @pf_to_mgmt: PF to MGMT channel
 * @header: pointer of the header to prepare
 * @msg_len: the length of the message
 * @mod: module in the chip that will get the message
 * @direction: the direction of the original message
 * @msg_id: message id
 **/
static void prepare_header(struct hinic_msg_pf_to_mgmt *pf_to_mgmt,
			   u64 *header, int msg_len, enum hinic_mod_type mod,
			   enum hinic_msg_ack_type ack_type,
			   enum hinic_msg_direction_type direction,
			   enum hinic_mgmt_cmd cmd, u32 msg_id)
{
	struct hinic_hwif *hwif = pf_to_mgmt->hwdev->hwif;

	*header = HINIC_MSG_HEADER_SET(msg_len, MSG_LEN) |
		HINIC_MSG_HEADER_SET(mod, MODULE) |
		HINIC_MSG_HEADER_SET(msg_len, SEG_LEN) |
		HINIC_MSG_HEADER_SET(ack_type, NO_ACK) |
		HINIC_MSG_HEADER_SET(0, ASYNC_MGMT_TO_PF) |
		HINIC_MSG_HEADER_SET(0, SEQID) |
		HINIC_MSG_HEADER_SET(LAST_SEGMENT, LAST) |
		HINIC_MSG_HEADER_SET(direction, DIRECTION) |
		HINIC_MSG_HEADER_SET(cmd, CMD) |
		HINIC_MSG_HEADER_SET(HINIC_PCI_INTF_IDX(hwif), PCI_INTF_IDX) |
		HINIC_MSG_HEADER_SET(hwif->attr.port_to_port_idx, P2P_IDX) |
		HINIC_MSG_HEADER_SET(msg_id, MSG_ID);
}

/**
 * prepare_mgmt_cmd - prepare the mgmt command
 * @mgmt_cmd: pointer to the command to prepare
 * @header: pointer of the header to prepare
 * @msg: the data of the message
 * @msg_len: the length of the message
 **/
static void prepare_mgmt_cmd(u8 *mgmt_cmd, u64 *header, void *msg,
			     int msg_len)
{
	memset(mgmt_cmd, 0, MGMT_MSG_RSVD_FOR_DEV);

	mgmt_cmd += MGMT_MSG_RSVD_FOR_DEV;
	memcpy(mgmt_cmd, header, sizeof(*header));

	mgmt_cmd += sizeof(*header);
	memcpy(mgmt_cmd, msg, msg_len);
}

/**
 * send_msg_to_mgmt_async - send async message
 * @pf_to_mgmt: PF to MGMT channel
 * @mod: module in the chip that will get the message
 * @cmd: command of the message
 * @msg: the data of the message
 * @msg_len: the length of the message
 * @direction: the direction of the original message
 * Return: 0 - success, negative - failure
 **/
static int send_msg_to_mgmt_async(struct hinic_msg_pf_to_mgmt *pf_to_mgmt,
				  enum hinic_mod_type mod, u8 cmd,
				void *msg, u16 msg_len,
				enum hinic_msg_direction_type direction,
				u16 resp_msg_id)
{
	void *mgmt_cmd = pf_to_mgmt->async_msg_buf;
	struct hinic_api_cmd_chain *chain;
	u64 header;
	u16 cmd_size = mgmt_msg_len(msg_len);

	if (!hinic_get_chip_present_flag(pf_to_mgmt->hwdev))
		return -EFAULT;

	if (direction == HINIC_MSG_RESPONSE)
		prepare_header(pf_to_mgmt, &header, msg_len, mod, HINIC_MSG_ACK,
			       direction, cmd, resp_msg_id);
	else
		prepare_header(pf_to_mgmt, &header, msg_len, mod, HINIC_MSG_ACK,
			       direction, cmd, ASYNC_MSG_ID(pf_to_mgmt));

	prepare_mgmt_cmd((u8 *)mgmt_cmd, &header, msg, msg_len);

	chain = pf_to_mgmt->cmd_chain[HINIC_API_CMD_WRITE_ASYNC_TO_MGMT_CPU];

	return hinic_api_cmd_write(chain, HINIC_NODE_ID_MGMT_HOST, mgmt_cmd,
					cmd_size);
}

int hinic_pf_to_mgmt_async(void *hwdev, enum hinic_mod_type mod,
			   u8 cmd, void *buf_in, u16 in_size)
{
	struct hinic_msg_pf_to_mgmt *pf_to_mgmt;
	void *dev = ((struct hinic_hwdev *)hwdev)->dev_hdl;
	int err;

	pf_to_mgmt = ((struct hinic_hwdev *)hwdev)->pf_to_mgmt;

	/* Lock the async_msg_buf */
	spin_lock_bh(&pf_to_mgmt->async_msg_lock);
	ASYNC_MSG_ID_INC(pf_to_mgmt);

	err = send_msg_to_mgmt_async(pf_to_mgmt, mod, cmd, buf_in, in_size,
				     HINIC_MSG_DIRECT_SEND, MSG_NO_RESP);
	spin_unlock_bh(&pf_to_mgmt->async_msg_lock);

	if (err) {
		sdk_err(dev, "Failed to send async mgmt msg\n");
		return err;
	}

	return 0;
}

/**
 * send_msg_to_mgmt_sync - send async message
 * @pf_to_mgmt: PF to MGMT channel
 * @mod: module in the chip that will get the message
 * @cmd: command of the message
 * @msg: the msg data
 * @msg_len: the msg data length
 * @direction: the direction of the original message
 * @resp_msg_id: msg id to response for
 * Return: 0 - success, negative - failure
 **/
static int send_msg_to_mgmt_sync(struct hinic_msg_pf_to_mgmt *pf_to_mgmt,
				 enum hinic_mod_type mod, u8 cmd,
				void *msg, u16 msg_len,
				enum hinic_msg_ack_type ack_type,
				enum hinic_msg_direction_type direction,
				u16 resp_msg_id)
{
	void *mgmt_cmd = pf_to_mgmt->sync_msg_buf;
	struct hinic_api_cmd_chain *chain;
	u64 header;
	u16 cmd_size = mgmt_msg_len(msg_len);

	if (!hinic_get_chip_present_flag(pf_to_mgmt->hwdev))
		return -EFAULT;

	if (direction == HINIC_MSG_RESPONSE)
		prepare_header(pf_to_mgmt, &header, msg_len, mod, ack_type,
			       direction, cmd, resp_msg_id);
	else
		prepare_header(pf_to_mgmt, &header, msg_len, mod, ack_type,
			       direction, cmd, SYNC_MSG_ID_INC(pf_to_mgmt));

	if (ack_type == HINIC_MSG_ACK)
		pf_to_mgmt_send_event_set(pf_to_mgmt, SEND_EVENT_START);

	prepare_mgmt_cmd((u8 *)mgmt_cmd, &header, msg, msg_len);

	chain = pf_to_mgmt->cmd_chain[HINIC_API_CMD_WRITE_TO_MGMT_CPU];

	return hinic_api_cmd_write(chain, HINIC_NODE_ID_MGMT_HOST, mgmt_cmd,
					cmd_size);
}

int hinic_pf_to_mgmt_sync(void *hwdev, enum hinic_mod_type mod, u8 cmd,
			  void *buf_in, u16 in_size, void *buf_out,
				u16 *out_size, u32 timeout)
{
	struct hinic_msg_pf_to_mgmt *pf_to_mgmt;
	void *dev = ((struct hinic_hwdev *)hwdev)->dev_hdl;
	struct hinic_recv_msg *recv_msg;
	struct completion *recv_done;
	ulong timeo;
	int err;
	ulong ret;

	pf_to_mgmt = ((struct hinic_hwdev *)hwdev)->pf_to_mgmt;

	/* Lock the sync_msg_buf */
	down(&pf_to_mgmt->sync_msg_lock);
	recv_msg = &pf_to_mgmt->recv_resp_msg_from_mgmt;
	recv_done = &recv_msg->recv_done;

	init_completion(recv_done);

	err = send_msg_to_mgmt_sync(pf_to_mgmt, mod, cmd, buf_in, in_size,
				    HINIC_MSG_ACK, HINIC_MSG_DIRECT_SEND,
				    MSG_NO_RESP);
	if (err) {
		sdk_err(dev, "Failed to send sync msg to mgmt, sync_msg_id: %d\n",
			pf_to_mgmt->sync_msg_id);
		pf_to_mgmt_send_event_set(pf_to_mgmt, SEND_EVENT_FAIL);
		goto unlock_sync_msg;
	}

	timeo = msecs_to_jiffies(timeout ? timeout : MGMT_MSG_TIMEOUT);

	ret = wait_for_completion_timeout(recv_done, timeo);
	down(&pf_to_mgmt->msg_sem);
	if (!ret) {
		sdk_err(dev, "Mgmt response sync cmd timeout, sync_msg_id: %d\n",
			pf_to_mgmt->sync_msg_id);
		hinic_dump_aeq_info((struct hinic_hwdev *)hwdev);
		err = -ETIMEDOUT;
		pf_to_mgmt->event_flag = SEND_EVENT_TIMEOUT;
		up(&pf_to_mgmt->msg_sem);
		goto unlock_sync_msg;
	}
	pf_to_mgmt->event_flag = SEND_EVENT_END;
	up(&pf_to_mgmt->msg_sem);

	if (!(((struct hinic_hwdev *)hwdev)->chip_present_flag)) {
		destroy_completion(recv_done);
		up(&pf_to_mgmt->sync_msg_lock);
		return -ETIMEDOUT;
	}

	if (buf_out && out_size) {
		if (*out_size < recv_msg->msg_len) {
			sdk_err(dev, "Invalid response message length: %d for mod %d cmd %d from mgmt, should less than: %d\n",
				recv_msg->msg_len, mod, cmd, *out_size);
			err = -EFAULT;
			goto unlock_sync_msg;
		}

		if (recv_msg->msg_len)
			memcpy(buf_out, recv_msg->msg, recv_msg->msg_len);

		*out_size = recv_msg->msg_len;
	}

unlock_sync_msg:
	destroy_completion(recv_done);
	up(&pf_to_mgmt->sync_msg_lock);

	return err;
}

int hinic_msg_to_mgmt_poll_sync(void *hwdev, enum hinic_mod_type mod, u8 cmd,
				void *buf_in, u16 in_size, void *buf_out,
				u16 *out_size, u32 timeout)
{
	return 0;
}

/* This function is only used by txrx flush */
int hinic_pf_to_mgmt_no_ack(void *hwdev, enum hinic_mod_type mod, u8 cmd,
			    void *buf_in, u16 in_size)
{
	struct hinic_msg_pf_to_mgmt *pf_to_mgmt;
	void *dev = ((struct hinic_hwdev *)hwdev)->dev_hdl;
	int err = -EINVAL;

	if (!hinic_is_hwdev_mod_inited(hwdev, HINIC_HWDEV_MGMT_INITED)) {
		sdk_err(dev, "Mgmt module not initialized\n");
		return -EINVAL;
	}

	pf_to_mgmt = ((struct hinic_hwdev *)hwdev)->pf_to_mgmt;

	if (!MSG_SZ_IS_VALID(in_size)) {
		sdk_err(dev, "Mgmt msg buffer size: %d is not valid\n",
			in_size);
		return -EINVAL;
	}

	if (!(((struct hinic_hwdev *)hwdev)->chip_present_flag))
		return -EPERM;

	/* Lock the sync_msg_buf */
	down(&pf_to_mgmt->sync_msg_lock);

	err = send_msg_to_mgmt_sync(pf_to_mgmt, mod, cmd, buf_in, in_size,
				    HINIC_MSG_NO_ACK, HINIC_MSG_DIRECT_SEND,
				    MSG_NO_RESP);

	up(&pf_to_mgmt->sync_msg_lock);

	return err;
}

/**
 * api cmd write or read bypass defaut use poll, if want to use aeq interrupt,
 * please set wb_trigger_aeqe to 1
 **/
int hinic_api_cmd_write_nack(void *hwdev, u8 dest, void *cmd, u16 size)
{
	struct hinic_msg_pf_to_mgmt *pf_to_mgmt;
	struct hinic_api_cmd_chain *chain;

	if (!hwdev || !size || !cmd)
		return -EINVAL;

	if (!hinic_is_hwdev_mod_inited(hwdev, HINIC_HWDEV_MGMT_INITED) ||
	    hinic_get_mgmt_channel_status(hwdev))
		return -EPERM;

	pf_to_mgmt = ((struct hinic_hwdev *)hwdev)->pf_to_mgmt;
	chain = pf_to_mgmt->cmd_chain[HINIC_API_CMD_POLL_WRITE];

	if (!(((struct hinic_hwdev *)hwdev)->chip_present_flag))
		return -EPERM;

	return hinic_api_cmd_write(chain, dest, cmd, size);
}
EXPORT_SYMBOL(hinic_api_cmd_write_nack);

int hinic_api_cmd_read_ack(void *hwdev, u8 dest, void *cmd, u16 size, void *ack,
			   u16 ack_size)
{
	struct hinic_msg_pf_to_mgmt *pf_to_mgmt;
	struct hinic_api_cmd_chain *chain;

	if (!hwdev || !cmd || (ack_size && !ack))
		return -EINVAL;

	if (!hinic_is_hwdev_mod_inited(hwdev, HINIC_HWDEV_MGMT_INITED) ||
	    hinic_get_mgmt_channel_status(hwdev))
		return -EPERM;

	pf_to_mgmt = ((struct hinic_hwdev *)hwdev)->pf_to_mgmt;
	chain = pf_to_mgmt->cmd_chain[HINIC_API_CMD_POLL_READ];

	if (!(((struct hinic_hwdev *)hwdev)->chip_present_flag))
		return -EPERM;

	return hinic_api_cmd_read(chain, dest, cmd, size, ack, ack_size);
}
EXPORT_SYMBOL(hinic_api_cmd_read_ack);

static void __send_mgmt_ack(struct hinic_msg_pf_to_mgmt *pf_to_mgmt,
			    enum hinic_mod_type mod, u8 cmd, void *buf_in,
			    u16 in_size, u16 msg_id)
{
	u16 buf_size;

	if (!in_size)
		buf_size = BUF_OUT_DEFAULT_SIZE;
	else
		buf_size = in_size;

	spin_lock_bh(&pf_to_mgmt->async_msg_lock);
	/* MGMT sent sync msg, send the response */
	send_msg_to_mgmt_async(pf_to_mgmt, mod, cmd,
			       buf_in, buf_size, HINIC_MSG_RESPONSE,
			       msg_id);
	spin_unlock_bh(&pf_to_mgmt->async_msg_lock);
}

/**
 * mgmt_recv_msg_handler - handler for message from mgmt cpu
 * @pf_to_mgmt: PF to MGMT channel
 * @recv_msg: received message details
 **/
static void mgmt_recv_msg_handler(struct hinic_msg_pf_to_mgmt *pf_to_mgmt,
				  enum hinic_mod_type mod, u8 cmd, void *buf_in,
				  u16 in_size, u16 msg_id, int need_resp)
{
	void *dev = pf_to_mgmt->hwdev->dev_hdl;
	void *buf_out = pf_to_mgmt->mgmt_ack_buf;
	enum hinic_mod_type tmp_mod = mod;
	bool ack_first = false;
	u16 out_size = 0;

	memset(buf_out, 0, MAX_PF_MGMT_BUF_SIZE);

	if (mod >= HINIC_MOD_HW_MAX) {
		sdk_warn(dev, "Receive illegal message from mgmt cpu, mod = %d\n",
			 mod);
		goto resp;
	}

	if (!pf_to_mgmt->recv_mgmt_msg_cb[mod]) {
		sdk_warn(dev, "Receive mgmt callback is null, mod = %d\n",
			 mod);
		goto resp;
	}

	ack_first = hinic_mgmt_event_ack_first(mod, cmd);
	if (ack_first && need_resp) {
		/* send ack to mgmt first to avoid command timeout in
		 * mgmt(100ms in mgmt);
		 * mgmt to host command don't need any response data from host,
		 * just need ack from host
		 */
		__send_mgmt_ack(pf_to_mgmt, mod, cmd, buf_out, in_size, msg_id);
	}

	pf_to_mgmt->recv_mgmt_msg_cb[tmp_mod](pf_to_mgmt->hwdev,
					pf_to_mgmt->recv_mgmt_msg_data[tmp_mod],
					cmd, buf_in, in_size,
					buf_out, &out_size);

resp:
	if (!ack_first && need_resp)
		__send_mgmt_ack(pf_to_mgmt, mod, cmd, buf_out, out_size,
				msg_id);
}

/**
 * mgmt_resp_msg_handler - handler for response message from mgmt cpu
 * @pf_to_mgmt: PF to MGMT channel
 * @recv_msg: received message details
 **/
static void mgmt_resp_msg_handler(struct hinic_msg_pf_to_mgmt *pf_to_mgmt,
				  struct hinic_recv_msg *recv_msg)
{
	void *dev = pf_to_mgmt->hwdev->dev_hdl;

	/* delete async msg */
	if (recv_msg->msg_id & ASYNC_MSG_FLAG)
		return;

	down(&pf_to_mgmt->msg_sem);
	if (recv_msg->msg_id == pf_to_mgmt->sync_msg_id &&
	    pf_to_mgmt->event_flag == SEND_EVENT_START) {
		complete(&recv_msg->recv_done);
	} else if (recv_msg->msg_id != pf_to_mgmt->sync_msg_id) {
		sdk_err(dev, "Send msg id(0x%x) recv msg id(0x%x) dismatch, event state=%d\n",
			pf_to_mgmt->sync_msg_id, recv_msg->msg_id,
			pf_to_mgmt->event_flag);
	} else {
		sdk_err(dev, "Wait timeout, send msg id(0x%x) recv msg id(0x%x), event state=%d!\n",
			pf_to_mgmt->sync_msg_id, recv_msg->msg_id,
			pf_to_mgmt->event_flag);
	}
	up(&pf_to_mgmt->msg_sem);
}

static void recv_mgmt_msg_work_handler(struct work_struct *work)
{
	struct hinic_mgmt_msg_handle_work *mgmt_work =
		container_of(work, struct hinic_mgmt_msg_handle_work, work);

	mgmt_recv_msg_handler(mgmt_work->pf_to_mgmt, mgmt_work->mod,
			      mgmt_work->cmd, mgmt_work->msg,
			      mgmt_work->msg_len, mgmt_work->msg_id,
			      !mgmt_work->async_mgmt_to_pf);

	destroy_work(&mgmt_work->work);

	kfree(mgmt_work->msg);
	kfree(mgmt_work);
}

/**
 * recv_mgmt_msg_handler - handler a message from mgmt cpu
 * @pf_to_mgmt: PF to MGMT channel
 * @header: the header of the message
 * @recv_msg: received message details
 **/
static void recv_mgmt_msg_handler(struct hinic_msg_pf_to_mgmt *pf_to_mgmt,
				  u8 *header, struct hinic_recv_msg *recv_msg)
{
	struct hinic_mgmt_msg_handle_work *mgmt_work;
	u64 mbox_header = *((u64 *)header);
	void *msg_body = header + sizeof(mbox_header);
	u32 seq_id, seq_len;
	u64 dir;

	/* Don't need to get anything from hw when cmd is async */
	dir = HINIC_MSG_HEADER_GET(mbox_header, DIRECTION);
	if (dir == HINIC_MSG_RESPONSE &&
	    HINIC_MSG_HEADER_GET(mbox_header, MSG_ID) & ASYNC_MSG_FLAG)
		return;

	seq_len = HINIC_MSG_HEADER_GET(mbox_header, SEG_LEN);
	seq_id  = HINIC_MSG_HEADER_GET(mbox_header, SEQID);
	seq_id  = seq_id * SEGMENT_LEN;

	memcpy((u8 *)recv_msg->msg + seq_id, msg_body, seq_len);

	if (!HINIC_MSG_HEADER_GET(mbox_header, LAST))
		return;

	recv_msg->cmd = HINIC_MSG_HEADER_GET(mbox_header, CMD);
	recv_msg->mod = HINIC_MSG_HEADER_GET(mbox_header, MODULE);
	recv_msg->async_mgmt_to_pf = HINIC_MSG_HEADER_GET(mbox_header,
							  ASYNC_MGMT_TO_PF);
	recv_msg->msg_len = HINIC_MSG_HEADER_GET(mbox_header, MSG_LEN);
	recv_msg->msg_id = HINIC_MSG_HEADER_GET(mbox_header, MSG_ID);

	if (HINIC_MSG_HEADER_GET(mbox_header, DIRECTION) ==
	    HINIC_MSG_RESPONSE) {
		mgmt_resp_msg_handler(pf_to_mgmt, recv_msg);
		return;
	}

	mgmt_work = kzalloc(sizeof(*mgmt_work), GFP_KERNEL);
	if (!mgmt_work) {
		sdk_err(pf_to_mgmt->hwdev->dev_hdl, "Allocate mgmt work memory failed\n");
		return;
	}

	if (recv_msg->msg_len) {
		mgmt_work->msg = kzalloc(recv_msg->msg_len, GFP_KERNEL);
		if (!mgmt_work->msg) {
			sdk_err(pf_to_mgmt->hwdev->dev_hdl, "Allocate mgmt msg memory failed\n");
			kfree(mgmt_work);
			return;
		}
	}

	mgmt_work->pf_to_mgmt = pf_to_mgmt;
	mgmt_work->msg_len = recv_msg->msg_len;
	memcpy(mgmt_work->msg, recv_msg->msg, recv_msg->msg_len);
	mgmt_work->msg_id = recv_msg->msg_id;
	mgmt_work->mod = recv_msg->mod;
	mgmt_work->cmd = recv_msg->cmd;
	mgmt_work->async_mgmt_to_pf = recv_msg->async_mgmt_to_pf;

	INIT_WORK(&mgmt_work->work, recv_mgmt_msg_work_handler);
	queue_work(pf_to_mgmt->workq, &mgmt_work->work);
}

/**
 * hinic_mgmt_msg_aeqe_handler - handler for a mgmt message event
 * @handle: PF to MGMT channel
 * @header: the header of the message
 * @size: unused
 **/
void hinic_mgmt_msg_aeqe_handler(void *hwdev, u8 *header, u8 size)
{
	struct hinic_hwdev *dev = (struct hinic_hwdev *)hwdev;
	struct hinic_msg_pf_to_mgmt *pf_to_mgmt;
	struct hinic_recv_msg *recv_msg;
	bool is_send_dir = false;

	pf_to_mgmt = dev->pf_to_mgmt;

	is_send_dir = (HINIC_MSG_HEADER_GET(*(u64 *)header, DIRECTION) ==
		       HINIC_MSG_DIRECT_SEND) ? true : false;

	/* ignore mgmt initiative report events when function deinit */
	if (test_bit(HINIC_HWDEV_FUNC_DEINIT, &dev->func_state) && is_send_dir)
		return;

	recv_msg = is_send_dir ? &pf_to_mgmt->recv_msg_from_mgmt :
		   &pf_to_mgmt->recv_resp_msg_from_mgmt;

	recv_mgmt_msg_handler(pf_to_mgmt, header, recv_msg);
}

/**
 * alloc_recv_msg - allocate received message memory
 * @recv_msg: pointer that will hold the allocated data
 * Return: 0 - success, negative - failure
 **/
static int alloc_recv_msg(struct hinic_recv_msg *recv_msg)
{
	recv_msg->msg = kzalloc(MAX_PF_MGMT_BUF_SIZE, GFP_KERNEL);
	if (!recv_msg->msg)
		return -ENOMEM;

	return 0;
}

/**
 * free_recv_msg - free received message memory
 * @recv_msg: pointer that holds the allocated data
 **/
static void free_recv_msg(struct hinic_recv_msg *recv_msg)
{
	kfree(recv_msg->msg);
}

/**
 * alloc_msg_buf - allocate all the message buffers of PF to MGMT channel
 * @pf_to_mgmt: PF to MGMT channel
 * Return: 0 - success, negative - failure
 **/
static int alloc_msg_buf(struct hinic_msg_pf_to_mgmt *pf_to_mgmt)
{
	int err;
	void *dev = pf_to_mgmt->hwdev->dev_hdl;

	err = alloc_recv_msg(&pf_to_mgmt->recv_msg_from_mgmt);
	if (err) {
		sdk_err(dev, "Failed to allocate recv msg\n");
		return err;
	}

	err = alloc_recv_msg(&pf_to_mgmt->recv_resp_msg_from_mgmt);
	if (err) {
		sdk_err(dev, "Failed to allocate resp recv msg\n");
		goto alloc_msg_for_resp_err;
	}

	pf_to_mgmt->async_msg_buf = kzalloc(MAX_PF_MGMT_BUF_SIZE, GFP_KERNEL);
	if (!pf_to_mgmt->async_msg_buf)	{
		err = -ENOMEM;
		goto async_msg_buf_err;
	}

	pf_to_mgmt->sync_msg_buf = kzalloc(MAX_PF_MGMT_BUF_SIZE, GFP_KERNEL);
	if (!pf_to_mgmt->sync_msg_buf)	{
		err = -ENOMEM;
		goto sync_msg_buf_err;
	}

	pf_to_mgmt->mgmt_ack_buf = kzalloc(MAX_PF_MGMT_BUF_SIZE, GFP_KERNEL);
	if (!pf_to_mgmt->mgmt_ack_buf)	{
		err = -ENOMEM;
		goto ack_msg_buf_err;
	}

	return 0;

ack_msg_buf_err:
	kfree(pf_to_mgmt->sync_msg_buf);

sync_msg_buf_err:
	kfree(pf_to_mgmt->async_msg_buf);

async_msg_buf_err:
	free_recv_msg(&pf_to_mgmt->recv_resp_msg_from_mgmt);

alloc_msg_for_resp_err:
	free_recv_msg(&pf_to_mgmt->recv_msg_from_mgmt);
	return err;
}

/**
 * free_msg_buf - free all the message buffers of PF to MGMT channel
 * @pf_to_mgmt: PF to MGMT channel
 * Return: 0 - success, negative - failure
 **/
static void free_msg_buf(struct hinic_msg_pf_to_mgmt *pf_to_mgmt)
{
	kfree(pf_to_mgmt->mgmt_ack_buf);
	kfree(pf_to_mgmt->sync_msg_buf);
	kfree(pf_to_mgmt->async_msg_buf);

	free_recv_msg(&pf_to_mgmt->recv_resp_msg_from_mgmt);
	free_recv_msg(&pf_to_mgmt->recv_msg_from_mgmt);
}

/**
 * hinic_pf_to_mgmt_init - initialize PF to MGMT channel
 * @pf_to_mgmt: PF to MGMT channel
 * @hwif: HW interface the PF to MGMT will use for accessing HW
 * Return: 0 - success, negative - failure
 **/
int hinic_pf_to_mgmt_init(struct hinic_hwdev *hwdev)
{
	struct hinic_msg_pf_to_mgmt *pf_to_mgmt;
	void *dev = hwdev->dev_hdl;
	int err;

	pf_to_mgmt = kzalloc(sizeof(*pf_to_mgmt), GFP_KERNEL);
	if (!pf_to_mgmt)
		return -ENOMEM;

	hwdev->pf_to_mgmt = pf_to_mgmt;
	pf_to_mgmt->hwdev = hwdev;
	spin_lock_init(&pf_to_mgmt->async_msg_lock);
	sema_init(&pf_to_mgmt->msg_sem, 1);
	sema_init(&pf_to_mgmt->sync_msg_lock, 1);
	pf_to_mgmt->workq = create_singlethread_workqueue(HINIC_MGMT_WQ_NAME);
	if (!pf_to_mgmt->workq) {
		sdk_err(dev, "Failed to initialize MGMT workqueue\n");
		err = -ENOMEM;
		goto create_mgmt_workq_err;
	}

	err = alloc_msg_buf(pf_to_mgmt);
	if (err) {
		sdk_err(dev, "Failed to allocate msg buffers\n");
		goto alloc_msg_buf_err;
	}

	err = hinic_api_cmd_init(hwdev, pf_to_mgmt->cmd_chain);
	if (err) {
		sdk_err(dev, "Failed to init the api cmd chains\n");
		goto api_cmd_init_err;
	}

	return 0;

api_cmd_init_err:
	free_msg_buf(pf_to_mgmt);

alloc_msg_buf_err:
	destroy_workqueue(pf_to_mgmt->workq);

create_mgmt_workq_err:
	sema_deinit(&pf_to_mgmt->msg_sem);
	spin_lock_deinit(&pf_to_mgmt->async_msg_lock);
	sema_deinit(&pf_to_mgmt->sync_msg_lock);
	kfree(pf_to_mgmt);

	return err;
}

/**
 * hinic_pf_to_mgmt_free - free PF to MGMT channel
 * @pf_to_mgmt: PF to MGMT channel
 **/
void hinic_pf_to_mgmt_free(struct hinic_hwdev *hwdev)
{
	struct hinic_msg_pf_to_mgmt *pf_to_mgmt = hwdev->pf_to_mgmt;

	hinic_api_cmd_free(pf_to_mgmt->cmd_chain);
	free_msg_buf(pf_to_mgmt);
	destroy_workqueue(pf_to_mgmt->workq);
	sema_deinit(&pf_to_mgmt->msg_sem);
	spin_lock_deinit(&pf_to_mgmt->async_msg_lock);
	sema_deinit(&pf_to_mgmt->sync_msg_lock);
	kfree(pf_to_mgmt);
}

void hinic_flush_mgmt_workq(void *hwdev)
{
	struct hinic_hwdev *dev = (struct hinic_hwdev *)hwdev;

	flush_workqueue(dev->aeqs->workq);

	if (hinic_func_type(dev) != TYPE_VF &&
	    hinic_is_hwdev_mod_inited(hwdev, HINIC_HWDEV_MGMT_INITED))
		flush_workqueue(dev->pf_to_mgmt->workq);
}
