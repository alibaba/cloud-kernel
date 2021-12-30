// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021, 2022 Alibaba Inc.
 */

#include <linux/pci.h>
#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/cpuhotplug.h>
#include <linux/cpumask.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/perf_event.h>
#include <linux/platform_device.h>
#include <linux/smp.h>
#include <linux/sysfs.h>
#include <linux/types.h>

#define DRV_NAME "dwc_pcie_pmu"
#define DEV_NAME "dwc_pcie_pmu"
#define RP_NUM_MAX 32		/*2die * 4RC * 4Ctrol */
#define PCIE_RAS_CAP_ID 0xb
#define ATTRI_NAME_MAX_SIZE 32

#define DWC_PCIE_LINK_CAPABILITIES_REG		0xC
#define DWC_PCIE_LANE_SHIFT			4
#define DWC_PCIE_LANE_MASK			GENMASK(9, 4)

#define DWC_PCIE_RAS_DES_CAP_HDR		0x0

#define DWC_PCIE_VENDOR_SPECIFIC_HDR		0x4
#define DWC_PCIE__VSEC_ID_MASK			GENMASK(15, 0)
#define DWC_PCIE_VSEC_ID			0x02

#define DWC_PCIE_EVENT_CNT_CTRL			0x8
#define DWC_PCIE__CNT_EVENT_SELECT_SHIFT	16
#define DWC_PCIE__CNT_EVENT_SELECT_MASK		GENMASK(27, 16)
#define DWC_PCIE__CNT_LANE_SELECT_SHIFT		8
#define DWC_PCIE__CNT_LANE_SELECT_MASK		GENMASK(11, 8)
#define DWC_PCIE__CNT_STATUS_SHIFT		7
#define DWC_PCIE__CNT_STATUS_MASK		BIT(7)
#define DWC_PCIE__CNT_ENABLE_SHIFT		2
#define DWC_PCIE__CNT_ENABLE_MASK		GENMASK(4, 2)
#define DWC_PCIE_PER_EVENT_OFF			(0x1 << DWC_PCIE__CNT_ENABLE_SHIFT)
#define DWC_PCIE_PER_EVENT_ON			(0x3 << DWC_PCIE__CNT_ENABLE_SHIFT)
#define DWC_PCIE_EVENT_CLEAR_MASK		GENMASK(1, 0)

#define DWC_PCIE_EVENT_CNT_DATA			0xC

#define DWC_PCIE_TIME_BASED_ANALYSIS_CTRL	0x10
#define DWC_PCIE__TIME_BASED_REPORT_SELECT_SHIFT	24
#define DWC_PCIE__TIME_BASED_REPORT_SELECT_MASK	GENMASK(31, 24)
#define DWC_PCIE__TIME_BASED_DURATION_SHIFT	8
#define DWC_PCIE__TIME_BASED_DURATION_SELECT	GENMASK(15, 8)
#define DWC_PCIE__TIME_BASED_COUNTER_ENABLE	1

#define DWC_PCIE_TIME_BASED_ANALYSIS_DATA_REG_LOW	0x14
#define DWC_PCIE_TIME_BASED_ANALYSIS_DATA_REG_HIGH	0x18

/* Event attributes */
#define DWC_PCIE_CONFIG_EVENTID			GENMASK(15, 0)
#define DWC_PCIE_CONFIG_TYPE			GENMASK(19, 16)
#define DWC_PCIE_CONFIG_LANE			GENMASK(27, 20)

#define DWC_PCIE_EVENT_ID(event)	FIELD_GET(DWC_PCIE_CONFIG_EVENTID, (event)->attr.config)
#define DWC_PCIE_EVENT_TYPE(event)	FIELD_GET(DWC_PCIE_CONFIG_TYPE, (event)->attr.config)
#define DWC_PCIE_EVENT_LANE(event)	FIELD_GET(DWC_PCIE_CONFIG_LANE, (event)->attr.config)

#define DWC_PCIE_PMU_HAS_REGISTER		1

enum dwc_pcie_event_type {
	DWC_PCIE_TYPE_INVALID,
	DWC_PCIE_TIME_BASE_EVENT,
	DWC_PCIE_LANE_EVENT,
};

struct dwc_event_counters {
	const char name[32];
	u32 event_id;
};

struct dwc_pcie_pmu {
	struct hlist_node node;
	unsigned int on_cpu;
	struct pmu pmu;
	struct device *dev;
};

struct dwc_pcie_info_table {
	u32 bdf;
	u32 cap_pos;
	u32 num_lanes;
	struct pci_dev *pdev;
	struct dwc_pcie_pmu pcie_pmu;
	u8 pmu_is_register;

	struct dwc_pcie_event_attr *lane_event_attrs;
	struct attribute **pcie_pmu_event_attrs;
	struct attribute_group pcie_pmu_event_attrs_group;
	const struct attribute_group *pcie_pmu_attr_groups[4];
};

struct dwc_pcie_pmu_priv {
	struct device *dev;
	u32 pcie_ctrl_num;
	struct dwc_pcie_info_table *pcie_table;
};

#define DWC_PCIE_CREATE_BDF(seg, bus, dev, func)	\
	(((seg) << 24) | (((bus) & 0xFF) << 16) | (((dev) & 0xFF) << 8) | (func))
#define to_pcie_pmu(p) (container_of(p, struct dwc_pcie_pmu, pmu))

static struct platform_device *dwc_pcie_pmu_dev;
static char *event_attr_name = "events";

static ssize_t dwc_pcie_pmu_cpumask_show(struct device *dev,
					 struct device_attribute *attr,
					 char *buf)
{
	struct dwc_pcie_pmu *pcie_pmu = to_pcie_pmu(dev_get_drvdata(dev));

	return cpumap_print_to_pagebuf(true, buf, cpumask_of(pcie_pmu->on_cpu));
}

static struct device_attribute dwc_pcie_pmu_cpumask_attr =
__ATTR(cpumask, 0444, dwc_pcie_pmu_cpumask_show, NULL);

static struct attribute *dwc_pcie_pmu_cpumask_attrs[] = {
	&dwc_pcie_pmu_cpumask_attr.attr,
	NULL
};

static struct attribute_group pcie_pmu_cpumask_attrs_group = {
	.attrs = dwc_pcie_pmu_cpumask_attrs,
};

struct dwc_pcie_format_attr {
	struct device_attribute attr;
	u64 field;
	int config;
};

static ssize_t dwc_pcie_pmu_format_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct dwc_pcie_format_attr *fmt = container_of(attr, typeof(*fmt), attr);
	int lo = __ffs(fmt->field), hi = __fls(fmt->field);

	if (lo == hi)
		return snprintf(buf, PAGE_SIZE, "config:%d\n", lo);

	if (!fmt->config)
		return snprintf(buf, PAGE_SIZE, "config:%d-%d\n", lo, hi);

	return snprintf(buf, PAGE_SIZE, "config%d:%d-%d\n", fmt->config, lo,
			hi);
}

#define _dwc_pcie_format_attr(_name, _cfg, _fld)				\
	(&((struct dwc_pcie_format_attr[]) {{				\
		.attr = __ATTR(_name, 0444, dwc_pcie_pmu_format_show, NULL),	\
		.config = _cfg,						\
		.field = _fld,						\
	}})[0].attr.attr)

#define dwc_pcie_format_attr(_name, _fld)	_dwc_pcie_format_attr(_name, 0, _fld)

static struct attribute *dwc_pcie_format_attrs[] = {
	dwc_pcie_format_attr(type, DWC_PCIE_CONFIG_TYPE),
	dwc_pcie_format_attr(eventid, DWC_PCIE_CONFIG_EVENTID),
	dwc_pcie_format_attr(lane, DWC_PCIE_CONFIG_LANE),
	NULL,
};

static struct attribute_group pcie_pmu_format_attrs_group = {
	.name = "format",
	.attrs = dwc_pcie_format_attrs,
};

struct dwc_pcie_event_attr {
	struct device_attribute attr;
	enum dwc_pcie_event_type type;
	u16 eventid;
	u8 lane;
};

ssize_t dwc_pcie_event_show(struct device *dev,
				struct device_attribute *attr, char *page)
{
	struct dwc_pcie_event_attr *eattr;

	eattr = container_of(attr, typeof(*eattr), attr);

	if (eattr->type == DWC_PCIE_LANE_EVENT)
		return sprintf(page, "eventid=0x%lx, type=0x%lx, lane=0x%lx\n",
			       (unsigned long)eattr->eventid,
			       (unsigned long)eattr->type,
			       (unsigned long)eattr->lane);
	else
		return sprintf(page, "eventid=0x%lx, type=0x%lx",
			       (unsigned long)eattr->eventid,
			       (unsigned long)eattr->type);
}

#define DWC_PCIE_EVENT_ATTR(_name, _type, _eventid, _lane)		\
	(&((struct dwc_pcie_event_attr[]) {{				\
		.attr = __ATTR(_name, 0444, dwc_pcie_event_show, NULL),	\
		.type = _type,						\
		.eventid = _eventid,					\
		.lane = _lane,					\
	}})[0].attr.attr)

#define DWC_PCIE_PMU_BASE_TIME_ATTR(_name, _eventid)			\
	DWC_PCIE_EVENT_ATTR(_name, DWC_PCIE_TIME_BASE_EVENT, _eventid, 0)

static struct attribute *dwc_pcie_pmu_time_event_attrs[] = {
	/* Group #0 */
	DWC_PCIE_PMU_BASE_TIME_ATTR(one_cycle, 0x00),
	DWC_PCIE_PMU_BASE_TIME_ATTR(TX_L0S, 0x01),
	DWC_PCIE_PMU_BASE_TIME_ATTR(RX_L0S, 0x02),
	DWC_PCIE_PMU_BASE_TIME_ATTR(L0, 0x03),
	DWC_PCIE_PMU_BASE_TIME_ATTR(L1, 0x04),
	DWC_PCIE_PMU_BASE_TIME_ATTR(L1_1, 0x05),
	DWC_PCIE_PMU_BASE_TIME_ATTR(L1_2, 0x06),
	DWC_PCIE_PMU_BASE_TIME_ATTR(CFG_RCVRY, 0x07),
	DWC_PCIE_PMU_BASE_TIME_ATTR(TX_RX_L0S, 0x08),
	DWC_PCIE_PMU_BASE_TIME_ATTR(L1_AUX, 0x09),
	DWC_PCIE_PMU_BASE_TIME_ATTR(ONE_cycle, 0x10),
	DWC_PCIE_PMU_BASE_TIME_ATTR(TX_L0S_, 0x11),
	DWC_PCIE_PMU_BASE_TIME_ATTR(RX_L0S_, 0x12),
	DWC_PCIE_PMU_BASE_TIME_ATTR(L0_, 0x13),
	DWC_PCIE_PMU_BASE_TIME_ATTR(L1_, 0x17),
	DWC_PCIE_PMU_BASE_TIME_ATTR(CFG_RCVRY_, 0x17),
	DWC_PCIE_PMU_BASE_TIME_ATTR(TX_RX_L0S_, 0x18),
	/* Group #1 */
	DWC_PCIE_PMU_BASE_TIME_ATTR(Tx_PCIe_TLP_Data_Payload, 0x20),
	DWC_PCIE_PMU_BASE_TIME_ATTR(Rx_PCIe_TLP_Data_Payload, 0x21),
	DWC_PCIE_PMU_BASE_TIME_ATTR(Tx_CCIX_TLP_Data_Payload, 0x22),
	DWC_PCIE_PMU_BASE_TIME_ATTR(Rx_CCIX_TLP_Data_Payload, 0x23),
	NULL
};

static inline umode_t pcie_pmu_event_attr_is_visible(struct kobject *kobj,
						     struct attribute *attr,
						     int unuse)
{
	return attr->mode;
}

static inline bool pci_dev_is_rootport(struct pci_dev *pdev)
{
	return (pci_is_pcie(pdev) &&
		pci_pcie_type(pdev) == PCI_EXP_TYPE_ROOT_PORT);
}

static inline unsigned int dwc_pcie_get_bdf(struct pci_dev *dev)
{
	return (DWC_PCIE_CREATE_BDF(pci_domain_nr(dev->bus), dev->bus->number,
				    PCI_SLOT(dev->devfn),
				    PCI_FUNC(dev->devfn)));
}

static int dwc_pcie_find_ras_des_cap_position(struct pci_dev *pdev, int *pos)
{
	int ret = -1;
	int start = 0;
	u32 val;
	u32 vsec_id;
	int where;
	int count = 0;
	int end = 256;

	do {
		where = pci_find_next_ext_capability(pdev, start, PCIE_RAS_CAP_ID);
		if (!where)
			return -EINVAL;

		pci_read_config_dword(pdev,
				      where + DWC_PCIE_VENDOR_SPECIFIC_HDR,
				      &val);
		vsec_id = val & DWC_PCIE__VSEC_ID_MASK;

		if (vsec_id == DWC_PCIE_VSEC_ID) {
			*pos = where;
			ret = 0;
			break;
		}

		pci_read_config_dword(pdev, where, &val);
		start = PCI_EXT_CAP_NEXT(val);
		count++;
	} while (count < end);

	return ret;
}

static int dwc_pcie_pmu_discover(struct dwc_pcie_pmu_priv *priv)
{
	int ret;
	int val;
	int where;
	bool is_rp;
	int index = 0;
	struct pci_dev *pdev;
	struct dwc_pcie_info_table *pcie_info;

	priv->pcie_table =
	    devm_kcalloc(priv->dev, RP_NUM_MAX, sizeof(*pcie_info), GFP_KERNEL);
	if (!priv->pcie_table)
		return -EINVAL;

	pcie_info = priv->pcie_table;
	while ((pdev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, pdev)) != NULL
		&& index < RP_NUM_MAX) {
		is_rp = pci_dev_is_rootport(pdev);
		if (!is_rp)
			continue;

		pcie_info[index].bdf = dwc_pcie_get_bdf(pdev);
		pcie_info[index].pdev = pdev;

		ret = dwc_pcie_find_ras_des_cap_position(pdev, &where);
		if (ret != 0) {
			pci_err(pcie_info->pdev,
			"Get extern capability offset fail\n");
			return -EINVAL;
		}

		pcie_info[index].cap_pos = where;

		pci_read_config_dword(pdev,
				pdev->pcie_cap + DWC_PCIE_LINK_CAPABILITIES_REG,
				&val);
		pcie_info[index].num_lanes =
		(val & DWC_PCIE_LANE_MASK) >> DWC_PCIE_LANE_SHIFT;
		index++;
	}

	if (!index) {
		pci_err(pcie_info->pdev, "No pcie controller\n");
		return -EINVAL;
	}

	priv->pcie_ctrl_num = index;

	return 0;
}

static inline int dwc_pcie_pmu_read_dword(struct dwc_pcie_info_table *pcie_info,
					  u32 reg, u32 *val)
{
	return pci_read_config_dword(pcie_info->pdev, pcie_info->cap_pos + reg,
				     val);
}

static inline int dwc_pcie_pmu_write_dword(struct dwc_pcie_info_table
					   *pcie_info, u32 reg, u32 val)
{
	return pci_write_config_dword(pcie_info->pdev, pcie_info->cap_pos + reg,
				      val);
}

static int dwc_pcie_pmu_set_event_id(struct dwc_pcie_info_table *pcie_info,
				     int event_id)
{
	int ret;
	u32 val;

	ret = dwc_pcie_pmu_read_dword(pcie_info, DWC_PCIE_EVENT_CNT_CTRL, &val);
	if (ret) {
		pci_err(pcie_info->pdev, "PCIe read fail\n");
		return ret;
	}

	val &= ~DWC_PCIE__CNT_ENABLE_MASK;
	val &= ~DWC_PCIE__CNT_EVENT_SELECT_MASK;
	val |= event_id << DWC_PCIE__CNT_EVENT_SELECT_SHIFT;

	ret = dwc_pcie_pmu_write_dword(pcie_info, DWC_PCIE_EVENT_CNT_CTRL, val);
	if (ret)
		pci_err(pcie_info->pdev, "PCIe write fail\n");

	return ret;
}

static int dwc_pcie_pmu_write_event_lane(struct dwc_pcie_info_table *pcie_info,
					 int lane, int event_id)
{
	u32 ret;
	u32 val;

	ret = dwc_pcie_pmu_read_dword(pcie_info, DWC_PCIE_EVENT_CNT_CTRL, &val);
	if (ret) {
		pci_err(pcie_info->pdev, "PCIe read fail\n");
		return ret;
	}

	val &= ~DWC_PCIE__CNT_LANE_SELECT_MASK;
	val |= lane << DWC_PCIE__CNT_LANE_SELECT_SHIFT;

	ret = dwc_pcie_pmu_write_dword(pcie_info, DWC_PCIE_EVENT_CNT_CTRL, val);
	if (ret)
		pci_err(pcie_info->pdev, "PCIe write fail\n");

	return ret;
}

static int dwc_pcie_pmu_event_enable(struct dwc_pcie_info_table *pcie_info,
				     u32 enable)
{
	u32 ret;
	u32 val;

	ret = dwc_pcie_pmu_read_dword(pcie_info, DWC_PCIE_EVENT_CNT_CTRL, &val);
	if (ret) {
		pci_err(pcie_info->pdev, "PCIe read fail\n");
		return ret;
	}

	val &= ~(DWC_PCIE__CNT_ENABLE_MASK);

	if (enable)
		val |= DWC_PCIE_PER_EVENT_ON;
	else
		val |= DWC_PCIE_PER_EVENT_OFF;

	ret = dwc_pcie_pmu_write_dword(pcie_info, DWC_PCIE_EVENT_CNT_CTRL, val);
	if (ret)
		pci_err(pcie_info->pdev, "PCIe write fail\n");

	return ret;
}

static int dwc_pcie_pmu_base_time_enable(struct dwc_pcie_info_table *pcie_info,
					 u32 enable)
{
	u32 ret;
	u32 val;

	ret = dwc_pcie_pmu_read_dword(pcie_info,
				      DWC_PCIE_TIME_BASED_ANALYSIS_CTRL, &val);
	if (ret) {
		pci_err(pcie_info->pdev, "PCIe read fail\n");
		return ret;
	}

	if (enable)
		val |= DWC_PCIE__TIME_BASED_COUNTER_ENABLE;
	else
		val &= ~DWC_PCIE__TIME_BASED_COUNTER_ENABLE;

	ret = dwc_pcie_pmu_write_dword(pcie_info,
				       DWC_PCIE_TIME_BASED_ANALYSIS_CTRL, val);
	if (ret)
		pci_err(pcie_info->pdev, "PCIe write fail\n");

	return ret;
}

static int dwc_pcie_pmu_read_event_counter(struct dwc_pcie_info_table
					   *pcie_info, u32 *counter)
{
	u32 ret, val;

	ret = dwc_pcie_pmu_read_dword(pcie_info, DWC_PCIE_EVENT_CNT_DATA, &val);
	if (ret) {
		pci_err(pcie_info->pdev, "PCIe read fail\n");
		return ret;
	}
	*counter = val;

	return ret;
}

static int dwc_pcie_pmu_read_base_time_counter(struct dwc_pcie_info_table
					       *pcie_info, u32 *counter)
{
	u32 ret, val;

	ret = dwc_pcie_pmu_read_dword(pcie_info,
				      DWC_PCIE_TIME_BASED_ANALYSIS_DATA_REG_LOW,
				      &val);
	if (ret) {
		pci_err(pcie_info->pdev, "PCIe read fail\n");
		return ret;
	}

	*counter = val;

	return ret;
}

static int dwc_pcie_pmu_clear_event_counter(struct dwc_pcie_info_table
					    *pcie_info)
{
	u32 ret;
	u32 val;

	ret = dwc_pcie_pmu_read_dword(pcie_info, DWC_PCIE_EVENT_CNT_CTRL, &val);
	if (ret) {
		pci_err(pcie_info->pdev, "PCIe read fail\n");
		return ret;
	}

	val &= ~DWC_PCIE_EVENT_CLEAR_MASK;
	val |= 1;

	ret = dwc_pcie_pmu_write_dword(pcie_info, DWC_PCIE_EVENT_CNT_CTRL, val);
	if (ret)
		pci_err(pcie_info->pdev, "PCIe write fail\n");

	return ret;
}

static int dwc_pcie_pmu_base_time_add_prepare(struct dwc_pcie_info_table
					      *pcie_info, u32 event_id)
{
	u32 ret;
	u32 val;

	ret = dwc_pcie_pmu_read_dword(pcie_info,
				      DWC_PCIE_TIME_BASED_ANALYSIS_CTRL, &val);
	if (ret) {
		pci_err(pcie_info->pdev, "PCIe read fail\n");
		return ret;
	}

	val &= ~DWC_PCIE__TIME_BASED_REPORT_SELECT_MASK;
	val |= event_id << DWC_PCIE__TIME_BASED_REPORT_SELECT_SHIFT;
	val &= ~DWC_PCIE__TIME_BASED_DURATION_SELECT;


	/* perf count just 1 second */
	val &= ~(0x0000FF00);
	val |= 0x00000400;

	ret = dwc_pcie_pmu_write_dword(pcie_info,
				       DWC_PCIE_TIME_BASED_ANALYSIS_CTRL, val);
	if (ret)
		pci_err(pcie_info->pdev, "PCIe write fail\n");

	return ret;
}

static struct dwc_pcie_info_table *pmu_to_pcie_info(struct pmu *pmu)
{
	struct dwc_pcie_info_table *pcie_info;
	struct dwc_pcie_pmu *pcie_pmu = to_pcie_pmu(pmu);

	pcie_info = container_of(pcie_pmu, struct dwc_pcie_info_table, pcie_pmu);
	if (pcie_info == NULL)
		pci_err(pcie_info->pdev, "Can't get pcie info\n");

	return pcie_info;
}

static void dwc_pcie_pmu_event_update(struct perf_event *event)
{
	u32 counter;
	struct dwc_pcie_info_table *pcie_info = pmu_to_pcie_info(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	enum dwc_pcie_event_type type = DWC_PCIE_EVENT_TYPE(event);
	u64 delta, prev, now;

	do {
		prev = local64_read(&hwc->prev_count);

		if (type == DWC_PCIE_LANE_EVENT)
			dwc_pcie_pmu_read_event_counter(pcie_info, &counter);
		else if (type == DWC_PCIE_TIME_BASE_EVENT)
			dwc_pcie_pmu_read_base_time_counter(pcie_info,
							    &counter);
		else
			pci_err(pcie_info->pdev, "Input param is invalid\n");

		now = counter;
	} while (local64_cmpxchg(&hwc->prev_count, prev, now) != prev);

	delta = now - prev;

	local64_add(delta, &event->count);
}

static int dwc_pcie_pmu_event_init(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct dwc_pcie_pmu *pcie_pmu = to_pcie_pmu(event->pmu);
	struct perf_event *sibling;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	if (hwc->sample_period) {
		dev_dbg(pcie_pmu->dev, "Sampling not supported\n");
		return -EOPNOTSUPP;
	}

	if (event->cpu < 0) {
		dev_dbg(pcie_pmu->dev, "Per-task mode not supported\n");
		return -EOPNOTSUPP;
	}

	event->cpu = pcie_pmu->on_cpu;

	if (event->group_leader != event &&
	    !is_software_event(event->group_leader)) {
		dev_dbg(pcie_pmu->dev, "Drive way only allow one event!\n");
		return -EINVAL;
	}

	for_each_sibling_event(sibling, event->group_leader) {
		if (sibling != event && !is_software_event(sibling)) {
			dev_dbg(pcie_pmu->dev, "Drive way event not allowed!\n");
			return -EINVAL;
		}
	}

	hwc->idx = -1;

	return 0;
}

static void dwc_pcie_pmu_set_period(struct hw_perf_event *hwc)
{
	u64 new = 0;

	local64_set(&hwc->prev_count, new);
}

static void dwc_pcie_pmu_event_start(struct perf_event *event, int flags)
{
	struct hw_perf_event *hwc = &event->hw;
	struct dwc_pcie_info_table *pcie_info = pmu_to_pcie_info(event->pmu);
	enum dwc_pcie_event_type type = DWC_PCIE_EVENT_TYPE(event);

	hwc->state = 0;
	dwc_pcie_pmu_set_period(hwc);

	if (type == DWC_PCIE_LANE_EVENT)
		dwc_pcie_pmu_event_enable(pcie_info, 1);
	else if (type == DWC_PCIE_TIME_BASE_EVENT)
		dwc_pcie_pmu_base_time_enable(pcie_info, 1);
	else
		pci_err(pcie_info->pdev, "Input param is invalid\n");
}

static void dwc_pcie_pmu_event_stop(struct perf_event *event, int flags)
{
	struct dwc_pcie_info_table *pcie_info = pmu_to_pcie_info(event->pmu);
	enum dwc_pcie_event_type type = DWC_PCIE_EVENT_TYPE(event);

	if (event->hw.state & PERF_HES_STOPPED)
		return;

	if (type == DWC_PCIE_LANE_EVENT)
		dwc_pcie_pmu_event_enable(pcie_info, 0);
	else if (type == DWC_PCIE_TIME_BASE_EVENT)
		dwc_pcie_pmu_base_time_enable(pcie_info, 0);
	else
		pci_err(pcie_info->pdev, "Input param is invalid\n");

	dwc_pcie_pmu_event_update(event);
}

static int dwc_pcie_pmu_event_add(struct perf_event *event, int flags)
{
	struct dwc_pcie_info_table *pcie_info = pmu_to_pcie_info(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	enum dwc_pcie_event_type type = DWC_PCIE_EVENT_TYPE(event);
	int event_id = DWC_PCIE_EVENT_ID(event);
	int lane = DWC_PCIE_EVENT_LANE(event);

	hwc->state = PERF_HES_STOPPED | PERF_HES_UPTODATE;

	if (type == DWC_PCIE_LANE_EVENT) {
		dwc_pcie_pmu_event_enable(pcie_info, 0);
		dwc_pcie_pmu_write_event_lane(pcie_info, lane, event_id);
		dwc_pcie_pmu_set_event_id(pcie_info, event_id);
		dwc_pcie_pmu_clear_event_counter(pcie_info);
	} else if (type == DWC_PCIE_TIME_BASE_EVENT) {
		dwc_pcie_pmu_base_time_enable(pcie_info, 0);
		dwc_pcie_pmu_base_time_add_prepare(pcie_info, event_id);
	} else {
		pci_err(pcie_info->pdev, "Input param is invalid\n");
		return -EINVAL;
	}

	if (flags & PERF_EF_START)
		dwc_pcie_pmu_event_start(event, PERF_EF_RELOAD);

	perf_event_update_userpage(event);

	return 0;
}

static void dwc_pcie_pmu_event_del(struct perf_event *event, int flags)
{
	dwc_pcie_pmu_event_stop(event, flags | PERF_EF_UPDATE);
	perf_event_update_userpage(event);
}

static void dwc_pcie_pmu_event_read(struct perf_event *event)
{
	dwc_pcie_pmu_event_update(event);
}

static struct dwc_event_counters event_array[] = {
	{"tx_ack_dllp", 0x600},
	{"tx_update_fc_dllp", 0x601},
	{"rx_ack_dllp", 0x602},
	{"rx_update_fc_dllp", 0x603},
	{"rx_nulified_tlp", 0x604},
	{"tx_nulified_tlp", 0x605},
	{"rx_duplicate_tlp", 0x606},
	{"tx_memory_write", 0x700},
	{"tx_memory_read", 0x701},
	{"tx_configuration_write", 0x702},
	{"tx_configuration_read", 0x703},
	{"tx_io_write", 0x704},
	{"tx_io_read", 0x705},
	{"tx_completion_without_data", 0x706},
	{"tx_completion_with_data", 0x707},
	{"tx_message_tlp", 0x708},
	{"tx_atomic", 0x709},
	{"tx_tlp_with_prefix", 0x70A},
	{"rx_memory_write", 0x70B},
	{"rx_memory_read", 0x70C},
	{"rx_io_write", 0x70F},
	{"rx_io_read", 0x710},
	{"rx_completion_without_data", 0x711},
	{"rx_completion_with_data", 0x712},
	{"rx_message_tlp", 0x713},
	{"rx_atomic", 0x714},
	{"rx_tlp_with_prefix", 0x715},
	{"tx_ccix_tlp", 0x716},
	{"rx_ccix_tlp", 0x717},
};

static int dwc_pcie_pmu_attr_init(struct dwc_pcie_pmu_priv *priv,
				  struct dwc_pcie_info_table *pcie_info)
{
	int i, j;
	char lane[8];
	const char tmp[64];
	int events_per_lane;
	int num_lane_events;
	int time_base_count;
	int num_attrs, attr_idx;
	struct dwc_pcie_event_attr *lane_attrs;
	struct attribute **pmu_attrs;

	memset((void *)tmp, 0, sizeof(tmp));
	memset((void *)lane, 0, sizeof(lane));
	time_base_count = ARRAY_SIZE(dwc_pcie_pmu_time_event_attrs);
	events_per_lane = ARRAY_SIZE(event_array);
	num_lane_events = pcie_info->num_lanes * events_per_lane;
	num_attrs = time_base_count + num_lane_events;

	pcie_info->lane_event_attrs =
		devm_kcalloc(priv->dev, num_lane_events,
				sizeof(struct dwc_pcie_event_attr),
				GFP_KERNEL);
	if (!pcie_info->lane_event_attrs)
		return -ENOMEM;
	lane_attrs = pcie_info->lane_event_attrs;
	pcie_info->pcie_pmu_event_attrs =
		devm_kcalloc(priv->dev, num_attrs, sizeof(struct attribute *),
			 GFP_KERNEL);
	if (!pcie_info->pcie_pmu_event_attrs)
		return -ENOMEM;
	pmu_attrs = pcie_info->pcie_pmu_event_attrs;

	for (i = 0; i < num_lane_events; i++) {
		lane_attrs[i].attr.attr.name =
		    devm_kzalloc(priv->dev, sizeof(char)
				 * ATTRI_NAME_MAX_SIZE, GFP_KERNEL);
		if (!lane_attrs[i].attr.attr.name)
			return -ENOMEM;
	}

	attr_idx = 0;
	for (i = 0; i < pcie_info->num_lanes; i++) {
		sprintf(lane, "_lane%d", i);

		for (j = 0; j < events_per_lane; j++) {
			int pos = i * events_per_lane + j;

			strcat((char *)tmp, event_array[j].name);
			strcat((char *)tmp, lane);
			memcpy((void *)lane_attrs[pos].attr.attr.name,
			       (void *)tmp,
			       sizeof(tmp));

			lane_attrs[pos].attr.attr.mode =
			    VERIFY_OCTAL_PERMISSIONS(0444);
			lane_attrs[pos].attr.show = dwc_pcie_event_show;
			lane_attrs[pos].attr.store = NULL;
			lane_attrs[pos].type = DWC_PCIE_LANE_EVENT;
			lane_attrs[pos].eventid = event_array[j].event_id;
			lane_attrs[pos].lane = i;
			pmu_attrs[attr_idx++] = &lane_attrs[pos].attr.attr;

			memset((void *)tmp, 0, sizeof(tmp));
		}
	}

	for (i = 0; i < ARRAY_SIZE(dwc_pcie_pmu_time_event_attrs); i++)
		pmu_attrs[attr_idx++] = dwc_pcie_pmu_time_event_attrs[i];

	pcie_info->pcie_pmu_event_attrs[attr_idx++] = NULL;

	pcie_info->pcie_pmu_event_attrs_group.name = event_attr_name;
	pcie_info->pcie_pmu_event_attrs_group.is_visible =
	    pcie_pmu_event_attr_is_visible;
	pcie_info->pcie_pmu_event_attrs_group.attrs =
	    pcie_info->pcie_pmu_event_attrs;

	pcie_info->pcie_pmu_attr_groups[0] =
	    &pcie_info->pcie_pmu_event_attrs_group;
	pcie_info->pcie_pmu_attr_groups[1] = &pcie_pmu_format_attrs_group;
	pcie_info->pcie_pmu_attr_groups[2] = &pcie_pmu_cpumask_attrs_group;
	pcie_info->pcie_pmu_attr_groups[3] = NULL;

	return 0;
}

static int __dwc_pcie_pmu_probe(struct dwc_pcie_pmu_priv *priv,
				struct dwc_pcie_info_table *pcie_info)
{
	int ret;
	char *name;
	struct dwc_pcie_pmu *pcie_pmu;
	struct device *dev;

	if (!pcie_info || !pcie_info->pdev) {
		pci_err(pcie_info->pdev, "Input parameter is invalid\n");
		return -EINVAL;
	}

	pcie_pmu = &pcie_info->pcie_pmu;
	dev = &pcie_info->pdev->dev;

	ret = dwc_pcie_pmu_attr_init(priv, pcie_info);
	if (ret) {
		pci_err(pcie_info->pdev, "PMU attr init fail ret=%d\n", ret);
		return ret;
	}

	pcie_pmu->dev = dev;
	pcie_pmu->pmu = (struct pmu) {
		.module		= THIS_MODULE,
		.task_ctx_nr	= perf_invalid_context,
		.pmu_enable	= NULL,
		.pmu_disable	= NULL,
		.event_init	= dwc_pcie_pmu_event_init,
		.add		= dwc_pcie_pmu_event_add,
		.del		= dwc_pcie_pmu_event_del,
		.start		= dwc_pcie_pmu_event_start,
		.stop		= dwc_pcie_pmu_event_stop,
		.read		= dwc_pcie_pmu_event_read,
		.attr_groups	= pcie_info->pcie_pmu_attr_groups,
		.capabilities	= PERF_PMU_CAP_NO_EXCLUDE,
	};

	name = devm_kasprintf(priv->dev, GFP_KERNEL, "pcie_bdf_%x",
			      pcie_info->bdf);
	if (!name)
		return -ENOMEM;

	/* Pick one CPU to be the preferred one to use */
	pcie_pmu->on_cpu = raw_smp_processor_id();

	ret = perf_pmu_register(&pcie_pmu->pmu, name, -1);
	if (ret) {
		pci_err(pcie_info->pdev, "Error %d registering PMU @%x\n", ret,
				 pcie_info->bdf);
		return ret;
	}

	pcie_info->pmu_is_register = DWC_PCIE_PMU_HAS_REGISTER;

	return ret;
}

static int dwc_pcie_pmu_remove(struct platform_device *pdev)
{
	struct dwc_pcie_pmu_priv *priv = platform_get_drvdata(pdev);
	int index;
	struct dwc_pcie_pmu *pcie_pmu;

	for (index = 0; index < priv->pcie_ctrl_num; index++)
		if (priv->pcie_table[index].pmu_is_register) {
			pcie_pmu = &priv->pcie_table[index].pcie_pmu;
			perf_pmu_unregister(&pcie_pmu->pmu);
		}
	return 0;
}

static int dwc_pcie_pmu_probe(struct platform_device *pdev)
{
	int ret = 0;
	int pcie_index;
	struct dwc_pcie_pmu_priv *priv;

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	priv->dev = &pdev->dev;
	platform_set_drvdata(pdev, priv);

	ret = dwc_pcie_pmu_discover(priv);
	if (ret) {
		dev_err(&pdev->dev, "Input parameter is invalid\n");
		return ret;
	}

	for (pcie_index = 0; pcie_index < priv->pcie_ctrl_num; pcie_index++) {
		ret = __dwc_pcie_pmu_probe(priv, &priv->pcie_table[pcie_index]);
		if (ret) {
			dev_err(&pdev->dev, "PCIe pmu probe fail\n");
			goto pmu_unregister;
		}
	}

	return 0;

pmu_unregister:
	dwc_pcie_pmu_remove(pdev);

	return ret;
}

static struct platform_driver dwc_pcie_pmu_driver = {
	.probe = dwc_pcie_pmu_probe,
	.remove = dwc_pcie_pmu_remove,
	.driver = {.name = DRV_NAME,},
};

static int __init dwc_pcie_pmu_init(void)
{
	int ret;

	ret = platform_driver_register(&dwc_pcie_pmu_driver);

	if (ret)
		return ret;

	dwc_pcie_pmu_dev =
	    platform_device_register_simple(DEV_NAME, -1, NULL, 0);
	if (IS_ERR(dwc_pcie_pmu_dev)) {
		platform_driver_unregister(&dwc_pcie_pmu_driver);
		return PTR_ERR(dwc_pcie_pmu_dev);
	}

	return 0;
}

static void __exit dwc_pcie_pmu_exit(void)
{
	platform_device_unregister(dwc_pcie_pmu_dev);
	platform_driver_unregister(&dwc_pcie_pmu_driver);
}

module_init(dwc_pcie_pmu_init);
module_exit(dwc_pcie_pmu_exit);

MODULE_DESCRIPTION("PMU driver for DesignWare Cores PCI Express Controller");
MODULE_AUTHOR("yinxuan_cw@linux.alibaba.com");
MODULE_AUTHOR("xueshuai@linux.alibaba.com");
MODULE_LICENSE("GPL v2");
