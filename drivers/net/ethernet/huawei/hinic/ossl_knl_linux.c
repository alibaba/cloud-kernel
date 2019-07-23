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

#include <linux/pci_regs.h>

#include "ossl_knl_linux.h"

#define OSSL_MINUTE_BASE (60)

sdk_file *file_creat(const char *file_name)
{
	return filp_open(file_name, O_CREAT | O_RDWR | O_APPEND, 0);
}

sdk_file *file_open(const char *file_name)
{
	return filp_open(file_name, O_RDONLY, 0);
}

void file_close(sdk_file *file_handle)
{
	(void)filp_close(file_handle, NULL);
}

u32 get_file_size(sdk_file *file_handle)
{
	struct inode *file_inode;

	file_inode = file_handle->f_inode;

	return (u32)(file_inode->i_size);
}

void set_file_position(sdk_file *file_handle, u32 position)
{
	file_handle->f_pos = position;
}

int file_read(sdk_file *file_handle, char *log_buffer,
	      u32 rd_length, u32 *file_pos)
{
	return (int)file_handle->f_op->read(file_handle, log_buffer,
					    rd_length, &file_handle->f_pos);
}

u32 file_write(sdk_file *file_handle, char *log_buffer, u32 wr_length)
{
	return (u32)file_handle->f_op->write(file_handle, log_buffer,
					     wr_length, &file_handle->f_pos);
}

static int _linux_thread_func(void *thread)
{
	struct sdk_thread_info *info = (struct sdk_thread_info *)thread;

	while (!kthread_should_stop())
		info->thread_fn(info->data);

	return 0;
}

int creat_thread(struct sdk_thread_info *thread_info)
{
	thread_info->thread_obj = kthread_run(_linux_thread_func,
					      thread_info, thread_info->name);
	if (!thread_info->thread_obj)
		return -EFAULT;

	return 0;
}

void stop_thread(struct sdk_thread_info *thread_info)
{
	if (thread_info->thread_obj)
		(void)kthread_stop(thread_info->thread_obj);
}

void utctime_to_localtime(u64 utctime, u64 *localtime)
{
	*localtime = utctime - sys_tz.tz_minuteswest * OSSL_MINUTE_BASE;
}

#ifndef HAVE_TIMER_SETUP
void initialize_timer(void *adapter_hdl, struct timer_list *timer)
{
	if (!adapter_hdl || !timer)
		return;

	init_timer(timer);
}
#endif

void add_to_timer(struct timer_list *timer, long period)
{
	if (!timer)
		return;

	add_timer(timer);
}

void stop_timer(struct timer_list *timer)
{
}

void delete_timer(struct timer_list *timer)
{
	if (!timer)
		return;

	del_timer_sync(timer);
}

int local_atoi(const char *name)
{
	int val = 0;

	for (;; name++) {
		switch (*name) {
		case '0' ... '9':
			val = 10 * val + (*name - '0');
			break;
		default:
			return val;
		}
	}
}
