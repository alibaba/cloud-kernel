/* SPDX-License-Identifier: GPL-2.0*/
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

#ifndef HINIC_DCB_H_
#define HINIC_DCB_H_

#define HINIC_DCB_CFG_TX	0
#define HINIC_DCB_CFG_RX	1

/*IEEE8021QAZ Transmission selection algorithm identifiers */
#define IEEE8021Q_TSA_STRICT	0x0
#define IEEE8021Q_TSA_CBSHAPER	0x1
#define IEEE8021Q_TSA_ETS	0x2
#define IEEE8021Q_TSA_VENDOR	0xFF

enum HINIC_DCB_FLAGS {
	HINIC_DCB_UP_COS_SETTING,
	HINIC_DCB_TRAFFIC_STOPPED,
};

extern const struct dcbnl_rtnl_ops hinic_dcbnl_ops;

u8 hinic_dcb_get_tc(struct hinic_dcb_config *dcb_cfg, int dir, u8 up);

int hinic_dcb_init(struct hinic_nic_dev *nic_dev);

int hinic_dcb_reset_hw_config(struct hinic_nic_dev *nic_dev);

int hinic_setup_tc(struct net_device *netdev, u8 tc);

void hinic_configure_dcb(struct net_device *netdev);

int hinic_set_cos_up_map(struct hinic_nic_dev *nic_dev, u8 *cos_up);

int hinic_get_num_cos(struct hinic_nic_dev *nic_dev, u8 *num_cos);

int hinic_get_cos_up_map(struct hinic_nic_dev *nic_dev,
			 u8 *num_cos, u8 *cos_up);

#endif
