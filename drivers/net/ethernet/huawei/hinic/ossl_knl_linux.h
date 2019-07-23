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

#ifndef OSSL_KNL_LINUX_H_
#define OSSL_KNL_LINUX_H_

#include <linux/string.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <net/checksum.h>
#include <net/ipv6.h>
#include <linux/if_vlan.h>
#include <linux/udp.h>
#include <linux/highmem.h>

/* UTS_RELEASE is in a different header starting in kernel 2.6.18 */
#ifndef UTS_RELEASE
/* utsrelease.h changed locations in 2.6.33 */
#include <generated/utsrelease.h>
#endif

#ifndef NETIF_F_SCTP_CSUM
#define NETIF_F_SCTP_CSUM 0
#endif

#ifndef __GFP_COLD
#define __GFP_COLD 0
#endif

#ifndef __GFP_COMP
#define __GFP_COMP 0
#endif

#ifndef SUPPORTED_100000baseKR4_Full
#define SUPPORTED_100000baseKR4_Full	0
#define ADVERTISED_100000baseKR4_Full	0
#endif
#ifndef SUPPORTED_100000baseCR4_Full
#define SUPPORTED_100000baseCR4_Full	0
#define ADVERTISED_100000baseCR4_Full	0
#endif

#ifndef SUPPORTED_40000baseKR4_Full
#define SUPPORTED_40000baseKR4_Full	0
#define ADVERTISED_40000baseKR4_Full	0
#endif
#ifndef SUPPORTED_40000baseCR4_Full
#define SUPPORTED_40000baseCR4_Full	0
#define ADVERTISED_40000baseCR4_Full	0
#endif

#ifndef SUPPORTED_25000baseKR_Full
#define	SUPPORTED_25000baseKR_Full	0
#define ADVERTISED_25000baseKR_Full	0
#endif
#ifndef SUPPORTED_25000baseCR_Full
#define SUPPORTED_25000baseCR_Full	0
#define	ADVERTISED_25000baseCR_Full	0
#endif

#ifndef ETHTOOL_GLINKSETTINGS
enum ethtool_link_mode_bit_indices {
	ETHTOOL_LINK_MODE_1000baseKX_Full_BIT = 17,
	ETHTOOL_LINK_MODE_10000baseKR_Full_BIT = 19,
	ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT = 23,
	ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT = 24,
	ETHTOOL_LINK_MODE_25000baseCR_Full_BIT = 31,
	ETHTOOL_LINK_MODE_25000baseKR_Full_BIT = 32,
	ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT = 36,
	ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT = 38,
};
#endif

#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) (((a) << 8) + (b))
#endif
#ifndef AX_RELEASE_VERSION
#define AX_RELEASE_VERSION(a, b) (((a) << 8) + (b))
#endif

#ifndef AX_RELEASE_CODE
#define AX_RELEASE_CODE 0
#endif

#if (AX_RELEASE_CODE && AX_RELEASE_CODE == AX_RELEASE_VERSION(3, 0))
#define RHEL_RELEASE_CODE RHEL_RELEASE_VERSION(5, 0)
#elif (AX_RELEASE_CODE && AX_RELEASE_CODE == AX_RELEASE_VERSION(3, 1))
#define RHEL_RELEASE_CODE RHEL_RELEASE_VERSION(5, 1)
#elif (AX_RELEASE_CODE && AX_RELEASE_CODE == AX_RELEASE_VERSION(3, 2))
#define RHEL_RELEASE_CODE RHEL_RELEASE_VERSION(5, 3)
#endif

#ifndef RHEL_RELEASE_CODE
/* NOTE: RHEL_RELEASE_* introduced in RHEL4.5. */
#define RHEL_RELEASE_CODE 0
#endif

/* RHEL 7 didn't backport the parameter change in
 * create_singlethread_workqueue.
 * If/when RH corrects this we will want to tighten up the version check.
 */
#if (RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 0))
#undef create_singlethread_workqueue
#define create_singlethread_workqueue(name)	\
	alloc_ordered_workqueue("%s", WQ_MEM_RECLAIM, name)
#endif

/* Ubuntu Release ABI is the 4th digit of their kernel version. You can find
 * it in /usr/src/linux/$(uname -r)/include/generated/utsrelease.h for new
 * enough versions of Ubuntu. Otherwise you can simply see it in the output of
 * uname as the 4th digit of the kernel. The UTS_UBUNTU_RELEASE_ABI is not in
 * the linux-source package, but in the linux-headers package. It begins to
 * appear in later releases of 14.04 and 14.10.
 *
 * Ex:
 * <Ubuntu 14.04.1>
 *  $uname -r
 *  3.13.0-45-generic
 * ABI is 45
 *
 * <Ubuntu 14.10>
 *  $uname -r
 *  3.16.0-23-generic
 * ABI is 23.
 */
#ifndef UTS_UBUNTU_RELEASE_ABI
#define UTS_UBUNTU_RELEASE_ABI 0
#define UBUNTU_VERSION_CODE 0
#else

#if UTS_UBUNTU_RELEASE_ABI > 255
#error UTS_UBUNTU_RELEASE_ABI is too large...
#endif /* UTS_UBUNTU_RELEASE_ABI > 255 */

#endif

/* Note that the 3rd digit is always zero, and will be ignored. This is
 * because Ubuntu kernels are based on x.y.0-ABI values, and while their linux
 * version codes are 3 digit, this 3rd digit is superseded by the ABI value.
 */
#define UBUNTU_VERSION(a, b, c, d) ((KERNEL_VERSION(a, b, 0) << 8) + (d))

#ifndef DEEPIN_PRODUCT_VERSION
#define DEEPIN_PRODUCT_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif

#ifdef CONFIG_DEEPIN_KERNEL
#endif

#ifndef DEEPIN_VERSION_CODE
#define DEEPIN_VERSION_CODE 0
#endif

/* SuSE version macros are the same as Linux kernel version macro. */
#ifndef SLE_VERSION
#define SLE_VERSION(a, b, c)	KERNEL_VERSION(a, b, c)
#endif
#define SLE_LOCALVERSION(a, b, c)	KERNEL_VERSION(a, b, c)
#ifdef CONFIG_SUSE_KERNEL
#if    (KERNEL_VERSION(92, 0, 0) <= SLE_LOCALVERSION_CODE && \
	KERNEL_VERSION(93, 0, 0) > SLE_LOCALVERSION_CODE)
/* SLES12 SP2 GA is 4.4.21-69.
 * SLES12 SP2 updates before SLES12 SP3 are: 4.4.{21,38,49,59}
 * SLES12 SP2 updates after SLES12 SP3 are: 4.4.{74,90,103,114,120}
 * but they all use a SLE_LOCALVERSION_CODE matching 92.nn.y
 */
#define SLE_VERSION_CODE SLE_VERSION(12, 2, 0)
#else
/* SLES15 Beta1 is 4.12.14-2.
 * SLES12 SP4 will also use 4.12.14-nn.xx.y
 */
#define SLE_VERSION_CODE SLE_VERSION(15, 0, 0)
/* new SLES kernels must be added here with >= based on kernel
 * the idea is to order from newest to oldest and just catch all
 * of them using the >=
 */
#endif /* LINUX_VERSION_CODE == KERNEL VERSION(x,y,z) */
#endif /* CONFIG_SUSE_KERNEL */
#ifndef SLE_VERSION_CODE
#define SLE_VERSION_CODE 0
#endif /* SLE_VERSION_CODE */
#ifndef SLE_LOCALVERSION_CODE
#define SLE_LOCALVERSION_CODE 0
#endif /* SLE_LOCALVERSION_CODE */

#ifndef ALIGN_DOWN
#ifndef __ALIGN_KERNEL
#define __ALIGN_KERNEL(x, a)	__ALIGN_MASK(x, (typeof(x))(a) - 1)
#endif
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))
#endif

/*****************************************************************************/
#define ETH_TYPE_TRANS_SETS_DEV
#define HAVE_NETDEV_STATS_IN_NETDEV

/*****************************************************************************/

#if (RHEL_RELEASE_CODE && \
	(RHEL_RELEASE_VERSION(6, 2) <= RHEL_RELEASE_CODE) && \
	(RHEL_RELEASE_VERSION(7, 0) > RHEL_RELEASE_CODE))
#define HAVE_RHEL6_NET_DEVICE_EXTENDED
#endif /* RHEL >= 6.2 && RHEL < 7.0 */
#if (RHEL_RELEASE_CODE && \
	(RHEL_RELEASE_VERSION(6, 6) <= RHEL_RELEASE_CODE) && \
	(RHEL_RELEASE_VERSION(7, 0) > RHEL_RELEASE_CODE))
#define HAVE_RHEL6_NET_DEVICE_OPS_EXT
#define HAVE_NDO_SET_FEATURES
#endif /* RHEL >= 6.6 && RHEL < 7.0 */

/*****************************************************************************/

/*****************************************************************************/
#ifndef HAVE_SET_RX_MODE
#define HAVE_SET_RX_MODE
#endif
#define HAVE_INET6_IFADDR_LIST

/*****************************************************************************/

#define HAVE_NDO_GET_STATS64

/*****************************************************************************/

#ifndef HAVE_MQPRIO
#define HAVE_MQPRIO
#endif
#ifndef HAVE_SETUP_TC
#define HAVE_SETUP_TC
#endif

#ifndef HAVE_NDO_SET_FEATURES
#define HAVE_NDO_SET_FEATURES
#endif
#define HAVE_IRQ_AFFINITY_NOTIFY

/*****************************************************************************/
#define HAVE_ETHTOOL_SET_PHYS_ID

/*****************************************************************************/
#define HAVE_NETDEV_WANTED_FEAUTES

/*****************************************************************************/
#ifndef HAVE_PCI_DEV_FLAGS_ASSIGNED
#define HAVE_PCI_DEV_FLAGS_ASSIGNED
#define HAVE_VF_SPOOFCHK_CONFIGURE
#endif
#ifndef HAVE_SKB_L4_RXHASH
#define HAVE_SKB_L4_RXHASH
#endif

/*****************************************************************************/
#define HAVE_ETHTOOL_GRXFHINDIR_SIZE
#define HAVE_INT_NDO_VLAN_RX_ADD_VID
#ifdef ETHTOOL_SRXNTUPLE
#undef ETHTOOL_SRXNTUPLE
#endif

/*****************************************************************************/
#include <linux/kconfig.h>

#define _kc_kmap_atomic(page)	kmap_atomic(page)
#define _kc_kunmap_atomic(addr)	kunmap_atomic(addr)

/*****************************************************************************/
#include <linux/of_net.h>
#define HAVE_FDB_OPS
#define HAVE_ETHTOOL_GET_TS_INFO

/*****************************************************************************/

/*****************************************************************************/
#define HAVE_NAPI_GRO_FLUSH_OLD

/*****************************************************************************/
#ifndef HAVE_SRIOV_CONFIGURE
#define HAVE_SRIOV_CONFIGURE
#endif

/*****************************************************************************/
#define HAVE_ENCAP_TSO_OFFLOAD
#define HAVE_SKB_INNER_NETWORK_HEADER
#if (RHEL_RELEASE_CODE && \
	(RHEL_RELEASE_VERSION(7, 0) <= RHEL_RELEASE_CODE) && \
	(RHEL_RELEASE_VERSION(8, 0) > RHEL_RELEASE_CODE))
#define HAVE_RHEL7_PCI_DRIVER_RH
#if (RHEL_RELEASE_VERSION(7, 2) <= RHEL_RELEASE_CODE)
#define HAVE_RHEL7_PCI_RESET_NOTIFY
#endif /* RHEL >= 7.2 */
#if (RHEL_RELEASE_VERSION(7, 3) <= RHEL_RELEASE_CODE)
#define HAVE_GENEVE_RX_OFFLOAD
#if !defined(HAVE_UDP_ENC_TUNNEL) && IS_ENABLED(CONFIG_GENEVE)
#define HAVE_UDP_ENC_TUNNEL
#endif
#ifdef ETHTOOL_GLINKSETTINGS
/* pay attention pangea platform when use this micro */
#define HAVE_ETHTOOL_25G_BITS
#endif /* ETHTOOL_GLINKSETTINGS */
#endif /* RHEL >= 7.3 */

/* new hooks added to net_device_ops_extended in RHEL7.4 */
#if (RHEL_RELEASE_VERSION(7, 4) <= RHEL_RELEASE_CODE)
#define HAVE_RHEL7_NETDEV_OPS_EXT_NDO_UDP_TUNNEL
#define HAVE_UDP_ENC_RX_OFFLOAD
#endif /* RHEL >= 7.4 */

#if (RHEL_RELEASE_VERSION(7, 5) <= RHEL_RELEASE_CODE)
#define HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
#endif /* RHEL > 7.5 */

#endif /* RHEL >= 7.0 && RHEL < 8.0 */

/*****************************************************************************/
#define HAVE_NDO_SET_VF_LINK_STATE
#define HAVE_SKB_INNER_PROTOCOL
#define HAVE_MPLS_FEATURES

/*****************************************************************************/
#if (SLE_VERSION_CODE && SLE_VERSION_CODE >= SLE_VERSION(12, 0, 0))
#define HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK
#endif
#define HAVE_NDO_GET_PHYS_PORT_ID
#define HAVE_NETIF_SET_XPS_QUEUE_CONST_MASK

/*****************************************************************************/
#define HAVE_VXLAN_CHECKS
#if (UBUNTU_VERSION_CODE && UBUNTU_VERSION_CODE >= UBUNTU_VERSION(3, 13, 0, 24))
#define HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK
#else
#define HAVE_NDO_SELECT_QUEUE_ACCEL
#endif
#define HAVE_NET_GET_RANDOM_ONCE
#define HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS

/*****************************************************************************/

#define HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK

/*****************************************************************************/
#define HAVE_NDO_SET_VF_MIN_MAX_TX_RATE

/*****************************************************************************/
#define HAVE_SKBUFF_CSUM_LEVEL
#define HAVE_MULTI_VLAN_OFFLOAD_EN

/*****************************************************************************/
#define HAVE_RXFH_HASHFUNC

/*****************************************************************************/

/****************************************************************/

/****************************************************************/

/****************************************************************/

/****************************************************************/

/****************************************************************/

#define HAVE_IO_MAP_WC_SIZE

/*****************************************************************************/
#define HAVE_NETDEVICE_MIN_MAX_MTU

/*****************************************************************************/
#define HAVE_VOID_NDO_GET_STATS64
#define HAVE_VM_OPS_FAULT_NO_VMA

/*****************************************************************************/
#define HAVE_HWTSTAMP_FILTER_NTP_ALL
#define HAVE_NDO_SETUP_TC_CHAIN_INDEX
#define HAVE_PCI_ERROR_HANDLER_RESET_PREPARE
#define HAVE_PTP_CLOCK_DO_AUX_WORK

/*****************************************************************************/
#define HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
/*****************************************************************************/

/*****************************************************************************/
#define HAVE_TIMER_SETUP
/*****************************************************************************/

/*****************************************************************************/
#define HAVE_NDO_SELECT_QUEUE_SB_DEV
/*****************************************************************************/

/* vxlan outer udp checksum will offload and skb->inner_transport_header
 * is wrong
 */
#if (SLE_VERSION_CODE && ((SLE_VERSION(12, 1, 0) == SLE_VERSION_CODE) || \
	(SLE_VERSION(12, 0, 0) == SLE_VERSION_CODE))) || \
	(RHEL_RELEASE_CODE && (RHEL_RELEASE_VERSION(7, 0) == RHEL_RELEASE_CODE))
#define HAVE_OUTER_IPV6_TUNNEL_OFFLOAD
#endif

#define HAVE_ENCAPSULATION_TSO

#define HAVE_ENCAPSULATION_CSUM

#ifndef eth_zero_addr
static inline void __kc_eth_zero_addr(u8 *addr)
{
	memset(addr, 0x00, ETH_ALEN);
}

#define eth_zero_addr(_addr) __kc_eth_zero_addr(_addr)
#endif

#ifndef netdev_hw_addr_list_for_each
#define netdev_hw_addr_list_for_each(ha, l) \
	list_for_each_entry(ha, &(l)->list, list)
#endif

#define spin_lock_deinit(lock)

typedef struct file sdk_file;

sdk_file *file_creat(const char *file_name);

sdk_file *file_open(const char *file_name);

void file_close(sdk_file *file_handle);

u32 get_file_size(sdk_file *file_handle);

void set_file_position(sdk_file *file_handle, u32 position);

int file_read(sdk_file *file_handle, char *log_buffer,
	      u32 rd_length, u32 *file_pos);

u32 file_write(sdk_file *file_handle, char *log_buffer, u32 wr_length);

struct sdk_thread_info {
	struct task_struct *thread_obj;
	char			*name;
	void			(*thread_fn)(void *x);
	void			*thread_event;
	void			*data;
};

int creat_thread(struct sdk_thread_info *thread_info);

void stop_thread(struct sdk_thread_info *thread_info);

#define destroy_work(work)
void utctime_to_localtime(u64 utctime, u64 *localtime);
#ifndef HAVE_TIMER_SETUP
void initialize_timer(void *adapter_hdl, struct timer_list *timer);
#endif
void add_to_timer(struct timer_list *timer, long period);
void stop_timer(struct timer_list *timer);
void delete_timer(struct timer_list *timer);

int local_atoi(const char *name);

#define nicif_err(priv, type, dev, fmt, args...)		\
	netif_level(err, priv, type, dev, "[NIC]"fmt, ##args)
#define nicif_warn(priv, type, dev, fmt, args...)		\
	netif_level(warn, priv, type, dev, "[NIC]"fmt, ##args)
#define nicif_notice(priv, type, dev, fmt, args...)		\
	netif_level(notice, priv, type, dev, "[NIC]"fmt, ##args)
#define nicif_info(priv, type, dev, fmt, args...)		\
	netif_level(info, priv, type, dev, "[NIC]"fmt, ##args)
#define nicif_dbg(priv, type, dev, fmt, args...)		\
	netif_level(dbg, priv, type, dev, "[NIC]"fmt, ##args)

#define destroy_completion(completion)
#define sema_deinit(lock)
#define mutex_deinit(lock)
#define rwlock_deinit(lock)

#define tasklet_state(tasklet) ((tasklet)->state)

#endif
