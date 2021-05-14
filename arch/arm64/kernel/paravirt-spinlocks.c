// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright(c) 2019 Huawei Technologies Co., Ltd
 * Author: Zengruan Ye <yezengruan@huawei.com>
 */

#include <linux/spinlock.h>
#include <asm/paravirt.h>

__visible bool __native_vcpu_is_preempted(int cpu)
{
	return false;
}

bool pv_is_native_spin_unlock(void)
{
	return false;
}
