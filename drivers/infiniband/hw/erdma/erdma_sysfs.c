// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ElasticRDMA driver for Linux
 *
 * Copyright (c) 2020-2021 Alibaba Group.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/sysfs.h>
#include <linux/device.h>
#include <rdma/ib_verbs.h>

#include "erdma.h"

char *cc_method_string[ERDMA_CC_METHODS_NUM] = {
	[ERDMA_CC_NEWRENO]	= "newreno",
	[ERDMA_CC_CUBIC]	= "cubic",
	[ERDMA_CC_HPCC_RTT]	= "hpcc_rtt",
	[ERDMA_CC_HPCC_ECN]	= "hpcc_ecn",
	[ERDMA_CC_HPCC_INT]	= "hpcc_int"
};

static ssize_t cc_method_show(struct device *device,
			     struct device_attribute *attr, char *buf)
{
	struct erdma_dev *edev = rdma_device_to_drv_device(device, struct erdma_dev, ibdev);

	if (edev == NULL)
		return -EINVAL;

	if (edev->cc_method < 0 || edev->cc_method >= ERDMA_CC_METHODS_NUM)
		return -EAGAIN;

	return sprintf(buf, "%s\n", cc_method_string[edev->cc_method]);
}

static ssize_t cc_method_store(struct device *device,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct erdma_dev *edev = rdma_device_to_drv_device(device, struct erdma_dev, ibdev);
	int i;

	if (edev == NULL)
		return -EINVAL;

	for (i = 0; i < ERDMA_CC_METHODS_NUM; i++) {
		if (strlen(cc_method_string[i]) == (count - 1) &&
			!memcmp(buf, cc_method_string[i], count - 1)) {
			edev->cc_method = i;
			return count;
		}
	}

	return -EINVAL;
}
static DEVICE_ATTR_RW(cc_method);

static ssize_t cc_available_show(struct device *device,
			     struct device_attribute *attr, char *buf)
{
	struct erdma_dev *edev = rdma_device_to_drv_device(device, struct erdma_dev, ibdev);
	int i;
	int sum = 0;

	if (edev == NULL)
		return -EINVAL;

	if (edev->cc_method < 0 || edev->cc_method >= ERDMA_CC_METHODS_NUM)
		return -EAGAIN;

	for (i = 0; i < ERDMA_CC_METHODS_NUM; i++)
		sum += sprintf(buf + sum, "%s\n", cc_method_string[i]);

	return sum;
}
static DEVICE_ATTR_RO(cc_available);

static struct attribute *erdma_class_attributes[] = {
	&dev_attr_cc_method.attr,
	&dev_attr_cc_available.attr
};

const struct attribute_group erdma_attr_group = {
	.attrs = erdma_class_attributes,
};
