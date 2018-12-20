// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2016-2018 Arm Limited
// CMN-600 Coherent Mesh Network PMU driver

#include <linux/acpi.h>
#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/perf_event.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

/* Common register stuff */
#define CMN_NODE_INFO			0x0000
#define CMN_NI_NODE_TYPE		GENMASK_ULL(15, 0)
#define CMN_NI_NODE_ID			GENMASK_ULL(31, 16)
#define CMN_NI_LOGICAL_ID		GENMASK_ULL(47, 32)

#define CMN_NODEID_DEVID(reg)		((reg) & 3)
#define CMN_NODEID_PID(reg)		(((reg) >> 2) & 1)
#define CMN_NODEID_X(reg, bits)		((reg) >> (3 + (bits)))
#define CMN_NODEID_Y(reg, bits)		(((reg) >> 3) & ((1U << (bits)) - 1))

#define CMN_CHILD_INFO			0x0080
#define CMN_CI_CHILD_COUNT		GENMASK_ULL(15, 0)
#define CMN_CI_CHILD_PTR_OFFSET		GENMASK_ULL(31, 16)

#define CMN_CHILD_NODE_ADDR		GENMASK(27,0)
#define CMN_CHILD_NODE_EXTERNAL		BIT(31)

#define CMN_ADDR_NODE_PTR		GENMASK(27, 14)

#define CMN_NODE_PTR_DEVID(ptr)		(((ptr) >> 2) & 3)
#define CMN_NODE_PTR_PID(ptr)		((ptr) & 1)
#define CMN_NODE_PTR_X(ptr, bits)	((ptr) >> (6 + (bits)))
#define CMN_NODE_PTR_Y(ptr, bits)	(((ptr) >> 6) & ((1U << (bits)) - 1))

/* PMU registers occupy the 3rd 4KB page of each node's 16KB space */
#define CMN_PMU_OFFSET			0x2000

/* For most nodes, this is all there is */
#define CMN_PMU_EVENT_SEL		0x000
#define CMN_PMU_EVENTn_ID_SHIFT(n)	((n) * 8)
/* DVM, HN-F and CXHA nodes have this extra selector for occupancy events */
#define CMN_PMU_OCCUP_ID_SHIFT		32

/* DTMs live in the PMU space of XP registers */
#define CMN_DTM_CONTROL			0x100
#define CMN_DTM_CONTROL_DTM_ENABLE	BIT(0) // Apparently does nothing...

#define CMN_DTM_WPn(n)			(0x1A0 + (n) * 0x18)
#define CMN_DTM_WPn_CONFIG(n)		(CMN_DTM_WPn(n) + 0x00)
#define CMN_DTM_WPn_VAL(n)		(CMN_DTM_WPn(n) + 0x08)
#define CMN_DTM_WPn_MASK(n)		(CMN_DTM_WPn(n) + 0x10)

#define CMN_DTM_PMU_CONFIG		0x210
#define CMN__PMEVCNT0_INPUT_SEL		GENMASK_ULL(37, 32)
#define CMN__PMEVCNT0_INPUT_SEL_WP	0x00
#define CMN__PMEVCNT0_INPUT_SEL_XP	0x04
#define CMN__PMEVCNT0_INPUT_SEL_DEV	0x10
#define CMN__PMEVCNT0_GLOBAL_NUM	GENMASK_ULL(18, 16)
#define CMN__PMEVCNTn_GLOBAL_NUM_SHIFT(n)	((n) * 4)
//XXX: mysterious +1 because of combined counters; see arm_cmn_event_add()
#define CMN__PMEVCNT_PAIRED(n)		BIT(4 + (n) + 1)
#define CMN__PMEVCNT23_COMBINED		BIT(2)
#define CMN__PMEVCNT01_COMBINED		BIT(1)
#define CMN_DTM_PMU_CONFIG_PMU_EN	BIT(0)

#define CMN_DTM_PMEVCNT			0x220

#define CMN_DTM_NUM_COUNTERS		4

/* The DTC node is where the magic happens */
#define CMN_DT_DTC_CTL			0x0a00
#define CMN_DT_DTC_CTL_DT_EN		BIT(0)

#define CMN_DT_TRACE_CONTROL		0x0a30
#define CMN_DT_TRACE_CONTROL_CC_ENABLE	BIT(8)

/* DTC counters are paired in 64-bit registers on a 16-byte stride. Yuck */
#define _CMN_DT_CNT_REG(n)		((((n) / 2) * 4 + (n) % 2) * 4)
#define CMN_DT_PMEVCNT(n)		(CMN_PMU_OFFSET + _CMN_DT_CNT_REG(n))
#define CMN_DT_PMCCNTR			(CMN_PMU_OFFSET + 0x40)

#define CMN_DT_PMCR			(CMN_PMU_OFFSET + 0x100)
#define CMN_DT_PMCR_PMU_EN		BIT(0)
#define CMN_DT_PMCR_CNTR_RST		BIT(5)
#define CMN_DT_PMCR_OVFL_INTR_EN	BIT(6)

#define CMN_DT_PMOVSR			(CMN_PMU_OFFSET + 0x118)
#define CMN_DT_PMOVSR_CLR		(CMN_PMU_OFFSET + 0x120)

#define CMN_DT_PMSSR			0x128
#define CMN_DT_PMSSR_SS_STATUS(n)	BIT(n)

#define CMN_DT_PMSRR			0x130
#define CMN_DT_PMSRR_SS_REQ		BIT(0)

//TODO: Is it worth probing dt_dbg_id.num_pmucntr?
#define CMN_DT_NUM_COUNTERS		8


enum cmn_node_type {
	CMN_TYPE_INVALID,
	CMN_TYPE_DVM,
	CMN_TYPE_CFG,
	CMN_TYPE_DTC,
	CMN_TYPE_HNI,
	CMN_TYPE_HNF,
	CMN_TYPE_XP,
	CMN_TYPE_SBSX,
	CMN_TYPE_RNI = 0xa,
	CMN_TYPE_RND = 0xd,
	CMN_TYPE_RNSAM = 0xf,
	/* CML nodes, only CMN-600r1 onwards */
	CMN_TYPE_CXRA = 0x100,
	CMN_TYPE_CXHA = 0x101,
	CMN_TYPE_CXLA = 0x102,
};

struct arm_cmn {
	struct device *dev;
	void __iomem *base;

	u8 mesh_x;
	u8 mesh_y;
	u16 num_xps;
	u16 num_dns;
	struct arm_cmn_node *xps;
	struct arm_cmn_node *dns;

	u32 dns_present;
};

struct arm_cmn_node {
	void __iomem *pmu_base;
	u16 id, logid;
	enum cmn_node_type type;
	union {
		u8 event[4];
		u32 event_sel;
	};
	union {
		u8 occupid;		// DN/HN-F/CXHA
		u32 pmu_config_low;	// DTM
	};
	/* Only for DTMs */
	union {
		s8 input_sel[4];
		u32 pmu_config_high;
	};
};

struct arm_cmn_dtc {
	struct arm_cmn *cmn;
	void __iomem *base;
	struct hlist_node cpuhp_node;
	int cpu;

	/* One of these is not like the others... */
	struct perf_event *counters[CMN_DT_NUM_COUNTERS + 1];

	struct pmu pmu;
};

#define to_cmn_dtc(x)	container_of(x, struct arm_cmn_dtc, pmu)

struct arm_cmn_event_attr {
	struct device_attribute attr;
	enum cmn_node_type type;
	u8 eventid;
	//TODO: maybe just encode this directly in eventid?
	u8 occupid;
};

/* By remapping CML node types to fit, we can keep everything in one u32 */
static u32 arm_cmn_node_type_to_bit(enum cmn_node_type type)
{
	if (type & 0x100)
		type ^= 0x110;
	return 1U << type;
}

static bool arm_cmn_has_node(struct arm_cmn *cmn, enum cmn_node_type type)
{
	return cmn->dns_present & arm_cmn_node_type_to_bit(type);
}

static void arm_cmn_set_node(struct arm_cmn *cmn, enum cmn_node_type type)
{
	cmn->dns_present |= arm_cmn_node_type_to_bit(type);
}

static int arm_cmn_xyidbits(struct arm_cmn *cmn)
{
	return cmn->mesh_x > 4 || cmn->mesh_y > 4 ? 3 : 2;
}

static int arm_cmn_node_to_xp(struct arm_cmn *cmn, u16 nodeid)
{
	int bits = arm_cmn_xyidbits(cmn);
	int x = CMN_NODEID_X(nodeid, bits);
	int y = CMN_NODEID_Y(nodeid, bits);

	return cmn->mesh_x * y + x;
}

#define CMN_EVENT_ATTR(_name, _type, _eventid, _occupid)		\
	(&((struct arm_cmn_event_attr[]) {{				\
		.attr = __ATTR(_name, 0444, arm_cmn_event_show, NULL),	\
		.type = _type,						\
		.eventid = _eventid,					\
		.occupid = _occupid,					\
	}})[0].attr.attr)

//TODO: this is rubbish
static ssize_t arm_cmn_event_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct arm_cmn_event_attr *eattr;

	eattr = container_of(attr, typeof(*eattr), attr);
	return snprintf(buf, PAGE_SIZE, "type=0x%x,eventid=0x%x,occupid=0x%x\n",
			eattr->type, eattr->eventid, eattr->occupid);
}

static umode_t arm_cmn_event_attr_is_visible(struct kobject *kobj,
					     struct attribute *attr,
					     int unused)
{
	struct device *dev = kobj_to_dev(kobj);
	struct arm_cmn_dtc *dtc = to_cmn_dtc(dev_get_drvdata(dev));
	struct arm_cmn_event_attr *eattr;

	eattr = container_of(attr, typeof(*eattr), attr.attr);
	if (arm_cmn_has_node(dtc->cmn, eattr->type))
		return attr->mode;

	//TODO: munge these at probe time, or do we want to preserve topology?
	if (eattr->type == CMN_TYPE_RNI && arm_cmn_has_node(dtc->cmn, CMN_TYPE_RND))
		return attr->mode;

	//TODO: Revision-specific event differences. Can we probe the revision reliably?

	return 0;
}

#define _CMN_EVENT_DVM(_name, _event, _occup)			\
	CMN_EVENT_ATTR(dn_##_name, CMN_TYPE_DVM, _event, _occup)
#define CMN_EVENT_DTC(_name)					\
	CMN_EVENT_ATTR(dtc_##_name, CMN_TYPE_DTC, 0, 0)
#define _CMN_EVENT_HNF(_name, _event, _occup)			\
	CMN_EVENT_ATTR(hnf_##_name, CMN_TYPE_HNF, _event, _occup)
#define CMN_EVENT_HNI(_name, _event)				\
	CMN_EVENT_ATTR(hni_##_name, CMN_TYPE_HNI, _event, 0)
#define __CMN_EVENT_XP(_name, _event)				\
	CMN_EVENT_ATTR(mxp_##_name, CMN_TYPE_XP, _event, 0)
#define CMN_EVENT_SBSX(_name, _event)				\
	CMN_EVENT_ATTR(sbsx_##_name, CMN_TYPE_SBSX, _event, 0)
//TODO: Does the RN-I/RN-D distinction ever matter?
#define CMN_EVENT_RNID(_name, _event)				\
	CMN_EVENT_ATTR(rnid_##_name, CMN_TYPE_RNI, _event, 0)

#define CMN_EVENT_DVM(_name, _event)				\
	_CMN_EVENT_DVM(_name, _event, 0)
#define CMN_EVENT_HNF(_name, _event)				\
	_CMN_EVENT_HNF(_name, _event, 0)
#define _CMN_EVENT_XP(_name, _event)				\
	__CMN_EVENT_XP(e_##_name, (_event) | (0 << 2)),		\
	__CMN_EVENT_XP(w_##_name, (_event) | (1 << 2)),		\
	__CMN_EVENT_XP(n_##_name, (_event) | (2 << 2)),		\
	__CMN_EVENT_XP(s_##_name, (_event) | (3 << 2)),		\
	__CMN_EVENT_XP(p0_##_name, (_event) | (4 << 2)),	\
	__CMN_EVENT_XP(p1_##_name, (_event) | (5 << 2))

/* Good thing there are only 3 fundamental XP events... */
#define CMN_EVENT_XP(_name, _event)				\
	_CMN_EVENT_XP(req_##_name, (_event) | (0 << 5)),	\
	_CMN_EVENT_XP(rsp_##_name, (_event) | (1 << 5)),	\
	_CMN_EVENT_XP(snp_##_name, (_event) | (2 << 5)),	\
	_CMN_EVENT_XP(dat_##_name, (_event) | (3 << 5))


static struct attribute *arm_cmn_event_attrs[] = {
	CMN_EVENT_DTC(cycles),

	CMN_EVENT_DVM(rxreq_dvmop,	0x01),
	CMN_EVENT_DVM(rxreq_dvmsync,	0x02),
	CMN_EVENT_DVM(rxreq_dvmop_vmid_filtered, 0x03),
	CMN_EVENT_DVM(rxreq_retried,	0x04),
	_CMN_EVENT_DVM(rxreq_trk_occupancy_all, 0x05, 0),
	_CMN_EVENT_DVM(rxreq_trk_occupancy_dvmop, 0x05, 1),
	_CMN_EVENT_DVM(rxreq_trk_occupancy_dvmsync, 0x05, 2),

	CMN_EVENT_HNF(cache_miss,	0x01),
	CMN_EVENT_HNF(l3_sf_cache_access, 0x02),
	CMN_EVENT_HNF(cache_fill,	0x03),
	CMN_EVENT_HNF(pocq_retry,	0x04),
	CMN_EVENT_HNF(pocq_reqs_recvd,	0x05),
	CMN_EVENT_HNF(sf_hit,		0x06),
	CMN_EVENT_HNF(sf_evictions,	0x07),
	CMN_EVENT_HNF(dir_snoops_sent,	0x08),
	CMN_EVENT_HNF(brd_snoops_sent,	0x09),
	CMN_EVENT_HNF(l3_eviction,	0x0a),
	CMN_EVENT_HNF(l3_fill_invalid_way, 0x0b),
	CMN_EVENT_HNF(mc_retries,	0x0c),
	CMN_EVENT_HNF(mc_reqs,		0x0d),
	CMN_EVENT_HNF(qos_hh_retry,	0x0e),
	_CMN_EVENT_HNF(qos_pocq_occupancy_all, 0x0f, 0),
	_CMN_EVENT_HNF(qos_pocq_occupancy_read, 0x0f, 1),
	_CMN_EVENT_HNF(qos_pocq_occupancy_write, 0x0f, 2),
	_CMN_EVENT_HNF(qos_pocq_occupancy_atomic, 0x0f, 3),
	_CMN_EVENT_HNF(qos_pocq_occupancy_stash, 0x0f, 4),
	CMN_EVENT_HNF(pocq_addrhaz,	0x10),
	CMN_EVENT_HNF(pocq_atomic_addrhaz, 0x11),
	CMN_EVENT_HNF(ld_st_swp_adq_full, 0x12),
	CMN_EVENT_HNF(cmp_adq_full,	0x13),
	CMN_EVENT_HNF(txdat_stall,	0x14),
	CMN_EVENT_HNF(txrsp_stall,	0x15),
	CMN_EVENT_HNF(seq_full,		0x16),
	CMN_EVENT_HNF(seq_hit,		0x17),
	CMN_EVENT_HNF(snp_sent,		0x18),
	CMN_EVENT_HNF(sfbi_dir_snp_sent, 0x19),
	CMN_EVENT_HNF(sfbi_brd_snp_sent, 0x1a),
	CMN_EVENT_HNF(sfbi_intv,	0x1b), //TODO: r0 only, RESERVED in r1p0
	CMN_EVENT_HNF(snp_sent_untrk,	0x1b), //TODO: r1p2 onwards
	CMN_EVENT_HNF(intv_dirty,	0x1c),
	CMN_EVENT_HNF(stash_snp_sent,	0x1d),
	CMN_EVENT_HNF(stash_data_pull,	0x1e),
	CMN_EVENT_HNF(snp_fwded,	0x1f), //TODO: r1 only

	//TODO: HN-I bandwidth events HNI_{RXDAT,TXDAT,TXREQ_TOTAL} on XP
	CMN_EVENT_HNI(rrt_rd_occ_cnt_ovfl, 0x20),
	CMN_EVENT_HNI(rrt_wr_occ_cnt_ovfl, 0x21),
	CMN_EVENT_HNI(rdt_rd_occ_cnt_ovfl, 0x22),
	CMN_EVENT_HNI(rdt_wr_occ_cnt_ovfl, 0x23),
	CMN_EVENT_HNI(wdb_occ_cnt_ovfl,	0x24),
	CMN_EVENT_HNI(rrt_rd_alloc,	0x25),
	CMN_EVENT_HNI(rrt_wr_alloc,	0x26),
	CMN_EVENT_HNI(rdt_rd_alloc,	0x27),
	CMN_EVENT_HNI(rdt_wr_alloc,	0x28),
	CMN_EVENT_HNI(wdb_alloc,	0x29),
	CMN_EVENT_HNI(txrsp_retryack,	0x2a),
	CMN_EVENT_HNI(arvalid_no_arready, 0x2b),
	CMN_EVENT_HNI(arready_no_arvalid, 0x2c),
	CMN_EVENT_HNI(awvalid_no_awready, 0x2d),
	CMN_EVENT_HNI(awready_no_awvalid, 0x2e),
	CMN_EVENT_HNI(wvalid_no_wready,	0x2f),
	CMN_EVENT_HNI(txdat_stall,	0x30),
	CMN_EVENT_HNI(nonpcie_serialization, 0x31),
	CMN_EVENT_HNI(pcie_serialization, 0x32),

	CMN_EVENT_XP(txflit_valid,	0x01),
	CMN_EVENT_XP(txflit_stall,	0x02),
	CMN_EVENT_XP(partial_dat_flit,	0x03),
	//TODO: watchpoint events

	//TODO: SBSX bandwidth events SBSX_{RXDAT,TXDAT,TXREQ_TOTAL} on XP
	//TODO: no actual SBSX events on r0, these are all r1 only
	CMN_EVENT_SBSX(rd_req,		0x01),
	CMN_EVENT_SBSX(wr_req,		0x02),
	CMN_EVENT_SBSX(cmo_req,		0x03),
	CMN_EVENT_SBSX(txrsp_retryack,	0x04),
	CMN_EVENT_SBSX(txdat_flitv,	0x05),
	CMN_EVENT_SBSX(txrsp_flitv,	0x06),
	CMN_EVENT_SBSX(rd_req_trkr_occ_cnt_ovfl, 0x11),
	CMN_EVENT_SBSX(wr_req_trkr_occ_cnt_ovfl, 0x12),
	CMN_EVENT_SBSX(cmo_req_trkr_occ_cnt_ovfl, 0x13),
	CMN_EVENT_SBSX(wdb_occ_cnt_ovfl, 0x14),
	CMN_EVENT_SBSX(rd_axi_trkr_occ_cnt_ovfl, 0x15),
	CMN_EVENT_SBSX(cmo_axi_trkr_occ_cnt_ovfl, 0x16),
	CMN_EVENT_SBSX(arvalid_no_arready, 0x21),
	CMN_EVENT_SBSX(awvalid_no_awready, 0x22),
	CMN_EVENT_SBSX(wvalid_no_wready, 0x23),
	CMN_EVENT_SBSX(txdat_stall,	0x24),
	CMN_EVENT_SBSX(txrsp_stall,	0x25),

	CMN_EVENT_RNID(s0_rdata_beats,	0x01),
	CMN_EVENT_RNID(s1_rdata_beats,	0x02),
	CMN_EVENT_RNID(s2_rdata_beats,	0x03),
	CMN_EVENT_RNID(rxdat_flits,	0x04),
	CMN_EVENT_RNID(txdat_flits,	0x05),
	CMN_EVENT_RNID(txreq_flits_total, 0x06),
	CMN_EVENT_RNID(txreq_flits_retried, 0x07),
	CMN_EVENT_RNID(rrt_occ_ovfl,	0x08),
	CMN_EVENT_RNID(wrt_occ_ovfl,	0x09),
	CMN_EVENT_RNID(txreq_flits_replayed, 0x0a),
	CMN_EVENT_RNID(wrcancel_sent,	0x0b),
	CMN_EVENT_RNID(s0_wdata_beats,	0x0c),
	CMN_EVENT_RNID(s1_wdata_beats,	0x0d),
	CMN_EVENT_RNID(s2_wdata_beats,	0x0e),
	CMN_EVENT_RNID(rrt_alloc,	0x0f),
	CMN_EVENT_RNID(wrt_alloc,	0x10),
	CMN_EVENT_RNID(rdb_unord,	0x11),
	CMN_EVENT_RNID(rdb_replay,	0x12),
	CMN_EVENT_RNID(rdb_hybrid,	0x13),
	CMN_EVENT_RNID(rdb_ord,		0x14),

	//TODO: CML events, now that they appear at least vaguely documented
	NULL
};

static const struct attribute_group arm_cmn_event_attrs_group = {
	.name = "events",
	.attrs = arm_cmn_event_attrs,
	.is_visible = arm_cmn_event_attr_is_visible,
};

static ssize_t arm_cmn_format_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct dev_ext_attribute *eattr = container_of(attr, typeof(*eattr),
						       attr);

	return snprintf(buf, PAGE_SIZE, "%s\n", (char *)eattr->var);
}

#define CMN_FORMAT_ATTR(_name, _var)					\
	(&((struct dev_ext_attribute[]) {{				\
		.attr = __ATTR(_name, 0444, arm_cmn_format_show, NULL),	\
		.var = _var,						\
	}})[0].attr.attr)

//TODO: make this better
static struct attribute *arm_cmn_format_attrs[] = {
	CMN_FORMAT_ATTR(nodeid, "config:0-15"),
	CMN_FORMAT_ATTR(x, "config:5-6"), //XXX: needs to be dynamic
	CMN_FORMAT_ATTR(y, "config:3-4"), //XXX: needs to be dynamic
	CMN_FORMAT_ATTR(port, "config:2"),
	CMN_FORMAT_ATTR(devid, "config:0-1"),
	CMN_FORMAT_ATTR(type, "config:16-31"),
	CMN_FORMAT_ATTR(eventid, "config:32-39"),
	CMN_FORMAT_ATTR(occupid, "config:40-43"),
	NULL
};
#define CMN_EVENT_TYPE(event)		(((event)->attr.config >> 16) & 0xffff)
#define CMN_EVENT_NODEID(event)		(((event)->attr.config >> 0) & 0xffff)
#define CMN_EVENT_EVENTID(event)	(((event)->attr.config >> 32) & 0xff)
#define CMN_EVENT_OCCUPID(event)	(((event)->attr.config >> 40) & 0xf)

static const struct attribute_group arm_cmn_format_attrs_group = {
	.name = "format",
	.attrs = arm_cmn_format_attrs,
};

static ssize_t arm_cmn_cpumask_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct arm_cmn_dtc *dtc = to_cmn_dtc(dev_get_drvdata(dev));

	return cpumap_print_to_pagebuf(true, buf, cpumask_of(dtc->cpu));
}

static struct device_attribute arm_cmn_cpumask_attr =
		__ATTR(cpumask, 0444, arm_cmn_cpumask_show, NULL);

static struct attribute *arm_cmn_cpumask_attrs[] = {
	&arm_cmn_cpumask_attr.attr,
	NULL,
};

static struct attribute_group arm_cmn_cpumask_attr_group = {
	.attrs = arm_cmn_cpumask_attrs,
};

static const struct attribute_group *arm_cmn_attr_groups[] = {
	&arm_cmn_event_attrs_group,
	&arm_cmn_format_attrs_group,
	&arm_cmn_cpumask_attr_group,
	NULL
};

static void arm_cmn_pmu_enable(struct pmu *pmu)
{
	struct arm_cmn_dtc *dtc = to_cmn_dtc(pmu);
	/*
	 * Empirically, it seems we have to toggle dt_dtc_ctl.dt_en with
	 * dt_pmcr.pmuen already set, which seems a little bit backwards,
	 * but leaving dt_en set and toggling pmuen makes DTM events give up
	 * counting properly. Thanks for not documenting any of this, TRM!
	 */
	writel_relaxed(CMN_DT_DTC_CTL_DT_EN, dtc->base + CMN_DT_DTC_CTL);
}

static void arm_cmn_pmu_disable(struct pmu *pmu)
{
	struct arm_cmn_dtc *dtc = to_cmn_dtc(pmu);

	writel_relaxed(0, dtc->base + CMN_DT_DTC_CTL);
}

static u64 arm_cmn_read_ctr(struct perf_event *event)
{
	struct arm_cmn_dtc *dtc = to_cmn_dtc(event->pmu);
	struct arm_cmn_node *xp = (void *)event->hw.event_base;
	int dtc_idx = event->hw.idx;
	int dtm_idx = event->hw.event_base_rdpmc;
	u32 lo, hi, old;

	if (dtc_idx == CMN_DT_NUM_COUNTERS)
		return readq_relaxed(dtc->base + CMN_DT_PMCCNTR);

	//TODO: snapshots would be handy for this (and probably the only way to handle multiple DTMs)
	hi = readl_relaxed(dtc->base + CMN_DT_PMEVCNT(dtc_idx));
	do {
		old = hi;
		//XXX: combined DTM counters
		lo = readl_relaxed(xp->pmu_base + CMN_DTM_PMEVCNT + dtm_idx * 2);
		hi = readl_relaxed(dtc->base + CMN_DT_PMEVCNT(dtc_idx));
	} while (hi != old);

	return (u64)hi << 32 | lo;
}

static void arm_cmn_write_ctr(struct perf_event *event, u64 val)
{
	struct arm_cmn_dtc *dtc = to_cmn_dtc(event->pmu);
	struct arm_cmn_node *xp = (void *)event->hw.event_base;
	int dtc_idx = event->hw.idx;
	int dtm_idx = event->hw.event_base_rdpmc;

	if (dtc_idx == CMN_DT_NUM_COUNTERS) {
		writeq_relaxed(val, dtc->base + CMN_DT_PMCCNTR);
	} else {
		//XXX: combined DTM counters
		writel_relaxed(val, xp->pmu_base + CMN_DTM_PMEVCNT + dtm_idx * 2);
		writel_relaxed(val >> 32, dtc->base + CMN_DT_PMEVCNT(dtc_idx));
	}
}

static void arm_cmn_init_ctr(struct perf_event *event)
{
	local64_set(&event->hw.prev_count, 0);
	arm_cmn_write_ctr(event, 0);
}

static void arm_cmn_event_read(struct perf_event *event)
{
	local64_t *hw_prev = &event->hw.prev_count;
	u64 new, prev, mask;

	do {
		prev = local64_read(hw_prev);
		new = arm_cmn_read_ctr(event);
	} while (local64_cmpxchg(hw_prev, prev, new) != prev);

	if (event->hw.idx == CMN_DT_NUM_COUNTERS)
		mask = (1ULL << 40) - 1;
	else
		mask = ~0ULL;

	local64_add((new - prev) & mask, &event->count);
}

static void arm_cmn_event_start(struct perf_event *event, int flags)
{
	struct arm_cmn_dtc *dtc = to_cmn_dtc(event->pmu);
	struct arm_cmn_node *node = (void *)event->hw.config_base;

	if (flags & PERF_EF_RELOAD)
		arm_cmn_write_ctr(event, local64_read(&event->hw.prev_count));

	if (!node) {
		writel_relaxed(CMN_DT_TRACE_CONTROL_CC_ENABLE, dtc->base + CMN_DT_TRACE_CONTROL);
	} else {
		//TODO: maybe repurpose hw.config for this?
		node->event[event->hw.event_base_rdpmc] = CMN_EVENT_EVENTID(event);
		writel_relaxed(node->event_sel, node->pmu_base + CMN_PMU_EVENT_SEL);
	}
	event->hw.state = 0;
}

static void arm_cmn_event_stop(struct perf_event *event, int flags)
{
	struct arm_cmn_dtc *dtc = to_cmn_dtc(event->pmu);
	struct arm_cmn_node *node = (void *)event->hw.config_base;

	if (!node) {
		writel_relaxed(0, dtc->base + CMN_DT_TRACE_CONTROL);
	} else {
		node->event[event->hw.event_base_rdpmc] = 0;
		writel_relaxed(node->event_sel, node->pmu_base + CMN_PMU_EVENT_SEL);
	}

	if (flags & PERF_EF_UPDATE) {
		arm_cmn_event_read(event);
		event->hw.state |= PERF_HES_UPTODATE;
	}
	event->hw.state |= PERF_HES_STOPPED;
}

static int arm_cmn_event_init(struct perf_event *event)
{
	struct arm_cmn_dtc *dtc = to_cmn_dtc(event->pmu);
	struct arm_cmn *cmn = dtc->cmn;
	enum cmn_node_type type;
	int i, bits, x, y, dev, port;
	u16 nodeid;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	if (is_sampling_event(event) || event->attach_state & PERF_ATTACH_TASK)
		return -EINVAL;

	if (event->attr.exclude_user   ||
	    event->attr.exclude_kernel ||
	    event->attr.exclude_hv     ||
	    event->attr.exclude_idle   ||
	    event->attr.exclude_host   ||
	    event->attr.exclude_guest)
		return -EINVAL;

	event->cpu = dtc->cpu;
	if (event->cpu < 0)
		return -EINVAL;

	//TODO: actually validate event/group, once all the subtleties are nailed down

	type = CMN_EVENT_TYPE(event);
	/* DTC events (i.e. cycles) already have everything they need */
	if (type == CMN_TYPE_DTC)
		return 0;

	nodeid = CMN_EVENT_NODEID(event);
	bits = arm_cmn_xyidbits(cmn);
	x = CMN_NODEID_X(nodeid, bits);
	y = CMN_NODEID_Y(nodeid, bits);
	port = CMN_NODEID_PID(nodeid);
	dev = CMN_NODEID_DEVID(nodeid);

	if (x >= cmn->mesh_x || y >= cmn->mesh_y)
		goto err;

	/* Generate a base input_sel value based on the target node's event 0 */
	if (type == CMN_TYPE_XP)
		event->hw.config = CMN__PMEVCNT0_INPUT_SEL_XP;
	else
		event->hw.config = (port << 4) + (dev << 2) + CMN__PMEVCNT0_INPUT_SEL_DEV;

	i = arm_cmn_node_to_xp(cmn, nodeid);
	event->hw.event_base = (unsigned long)&cmn->xps[i];

	if (type == CMN_TYPE_XP) {
		event->hw.config_base = event->hw.event_base;
		return 0;
	}

	for (i = 0; i < cmn->num_dns; i++)
		if (cmn->dns[i].type == type && cmn->dns[i].id == nodeid)
			goto found;
err:
	dev_dbg(cmn->dev, "invalid node %d,%d,%d,%d type 0x%x\n", x, y, port, dev, type);
	return -EINVAL;
found:
	event->hw.config_base = (unsigned long)&cmn->dns[i];
	return 0;
}

static int arm_cmn_event_add(struct perf_event *event, int flags)
{
	struct arm_cmn_dtc *dtc = to_cmn_dtc(event->pmu);
	struct arm_cmn_node *node, *xp;
	int dtc_idx, dtm_idx;

	if (CMN_EVENT_TYPE(event) == CMN_TYPE_DTC) {
		if (dtc->counters[CMN_DT_NUM_COUNTERS])
			return -ENOSPC;
		dtc->counters[CMN_DT_NUM_COUNTERS] = event;
		event->hw.idx = CMN_DT_NUM_COUNTERS;
		event->hw.state = PERF_HES_STOPPED | PERF_HES_UPTODATE;
		arm_cmn_init_ctr(event);
		if (flags & PERF_EF_START)
			arm_cmn_event_start(event, 0);
		return 0;
	}

	/* Grab a free global counter first... */
	//TODO: we should be able to count the same event on multiple nodes at once, but the config magic to specify that will probably be fiddly...
	for (dtc_idx = 0; dtc_idx < CMN_DT_NUM_COUNTERS; dtc_idx++)
		if (!dtc->counters[dtc_idx])
			goto found_global;
	return -ENOSPC;
found_global:
	/* ...then a local counter to feed it. */
	xp = (void *)event->hw.event_base;
	//XXX: since we can't make 16-bit register accesses, using individual DTM counters
	//     will be a massive pain. Combining them into 32-bit counters which we can then
	//     write individually saves a bunch of headaches in the beginning. Thus we consider
	//     only counters 0 and 2 for allocation and accesses, but silently translate to
	//     counters 1 and 3 respectively when pairing the overflow with the DTC counter.
	for (dtm_idx = 0; dtm_idx < CMN_DTM_NUM_COUNTERS; dtm_idx += 2)
		if (!(xp->pmu_config_low & CMN__PMEVCNT_PAIRED(dtm_idx)))
			goto found_local;
	return -ENOSPC;
found_local:
	/* Go go go! */
	dtc->counters[dtc_idx] = event;
	event->hw.idx = dtc_idx;
	event->hw.event_base_rdpmc = dtm_idx;
	event->hw.state = PERF_HES_STOPPED | PERF_HES_UPTODATE;
	arm_cmn_init_ctr(event);

	node = (void *)event->hw.config_base;
	if (node->type != CMN_TYPE_XP) {
		node->occupid = CMN_EVENT_OCCUPID(event);
		writel(node->occupid, node->pmu_base + CMN_PMU_EVENT_SEL + 4);
	}

	xp->input_sel[dtm_idx] = event->hw.config + dtm_idx;
	xp->pmu_config_low &= ~(CMN__PMEVCNT0_GLOBAL_NUM << CMN__PMEVCNTn_GLOBAL_NUM_SHIFT(dtc_idx));
	xp->pmu_config_low |= FIELD_PREP(CMN__PMEVCNT0_GLOBAL_NUM, dtc_idx) << CMN__PMEVCNTn_GLOBAL_NUM_SHIFT(dtc_idx);
	xp->pmu_config_low |= CMN__PMEVCNT_PAIRED(dtm_idx);
	writeq_relaxed((u64)xp->pmu_config_high << 32 | xp->pmu_config_low, xp->pmu_base + CMN_DTM_PMU_CONFIG);

	if (flags & PERF_EF_START)
		arm_cmn_event_start(event, 0);

	return 0;
}

static void arm_cmn_event_del(struct perf_event *event, int flags)
{
	struct arm_cmn_dtc *dtc = to_cmn_dtc(event->pmu);
	struct arm_cmn_node *xp = (void *)event->hw.event_base;

	arm_cmn_event_stop(event, PERF_EF_UPDATE);
	dtc->counters[event->hw.idx] = NULL;
	if (!xp)
		return;

	xp->pmu_config_low &= ~CMN__PMEVCNT_PAIRED(event->hw.event_base_rdpmc);
	writel_relaxed(xp->pmu_config_low, xp->pmu_base + CMN_DTM_PMU_CONFIG);
}

static int arm_cmn_pmu_offline_cpu(unsigned int cpu, struct hlist_node *node)
{
	struct arm_cmn_dtc *dtc;
	unsigned int target;

	dtc = hlist_entry_safe(node, struct arm_cmn_dtc, cpuhp_node);
	if (cpu != dtc->cpu)
		return 0;

	target = cpumask_any_but(cpu_online_mask, cpu);
	if (target >= nr_cpu_ids)
		return 0;

	perf_pmu_migrate_context(&dtc->pmu, cpu, target);
	dtc->cpu = target;
	return 0;
}

static irqreturn_t arm_cmn_irq_handler(int irq, void *dev_id)
{
	irqreturn_t res = IRQ_NONE;

	//TODO: actually enable interrupt

	return res;
}

static int arm_cmn_init_pmu(struct arm_cmn *cmn, void __iomem *base, int id)
{
	struct platform_device *pdev = to_platform_device(cmn->dev);
	struct arm_cmn_dtc *dtc;
	const char *name;
	int irq, err;

	dtc = devm_kzalloc(cmn->dev, sizeof(*dtc), GFP_KERNEL);
	if (!dtc)
		return -ENOMEM;

	irq = platform_get_irq(pdev, id);
	if (irq <= 0) {
		dev_err(cmn->dev, "missing IRQ for DTC %d\n", id);
		return -EINVAL;
	}

	err = devm_request_irq(cmn->dev, irq, arm_cmn_irq_handler,
			       IRQF_NOBALANCING | IRQF_NO_THREAD,
			       dev_name(cmn->dev), dtc);
	if (err)
		return err;

	dtc->cmn = cmn;
	dtc->base = base;
	dtc->cpu = get_cpu();
	dtc->pmu = (struct pmu) {
		.attr_groups = arm_cmn_attr_groups,
		.task_ctx_nr = perf_invalid_context,
		.pmu_enable = arm_cmn_pmu_enable,
		.pmu_disable = arm_cmn_pmu_disable,
		.event_init = arm_cmn_event_init,
		.add = arm_cmn_event_add,
		.del = arm_cmn_event_del,
		.start = arm_cmn_event_start,
		.stop = arm_cmn_event_stop,
		.read = arm_cmn_event_read,
	};

	if (id == 0) {
		name = "arm_cmn";
	} else {
		name = devm_kasprintf(cmn->dev, GFP_KERNEL, "arm_cmn_%d", id);
		if (!name)
			return -ENOMEM;
	}

	cpuhp_state_add_instance_nocalls(CPUHP_AP_PERF_ARM_CMN_ONLINE,
					 &dtc->cpuhp_node);
	put_cpu();

	writel_relaxed(CMN_DT_PMCR_PMU_EN, base + CMN_DT_PMCR);

	return perf_pmu_register(&dtc->pmu, name, -1);
}

static int arm_cmn_discover(struct arm_cmn *cmn, unsigned int rgn_offset, int lvl)
{
	void __iomem *region = cmn->base + rgn_offset;
	struct arm_cmn_node *node;
	unsigned int node_ptr;
	u16 node_type, node_id, node_logid, child_count, child_poff;
	u64 reg;
	int i, ret;

	if (lvl > 2)
		return -EINVAL;

	reg = readq(region + CMN_NODE_INFO);
	node_type = FIELD_GET(CMN_NI_NODE_TYPE, reg);
	node_id = FIELD_GET(CMN_NI_NODE_ID, reg);
	node_logid = FIELD_GET(CMN_NI_LOGICAL_ID, reg);

	/*
	 * The DevID field is always zero in node_info registers for
	 * some reason; decode it from the node pointer instead.
	 */
	node_ptr = FIELD_GET(CMN_ADDR_NODE_PTR, rgn_offset);
	node_id |= CMN_NODE_PTR_DEVID(node_ptr);

	reg = readq(region + CMN_CHILD_INFO);
	child_count = FIELD_GET(CMN_CI_CHILD_COUNT, reg);
	child_poff = FIELD_GET(CMN_CI_CHILD_PTR_OFFSET, reg);

	arm_cmn_set_node(cmn, node_type);
	dev_dbg(cmn->dev, "node%*c%#06hx%*ctype:%-#6hx id:%-4hd off:%#x\n",
		(lvl * 2) + 1, ' ', node_id, 5 - (lvl * 2), ' ',
		node_type, node_logid, rgn_offset);

	switch (node_type) {
	case CMN_TYPE_CFG:
		cmn->xps = devm_kcalloc(cmn->dev, child_count,
					sizeof(*cmn->xps), GFP_KERNEL);
		if (!cmn->xps)
			return -ENOMEM;

		cmn->num_xps = child_count;
		goto wrangle_children;
	case CMN_TYPE_XP:
		node = devm_kcalloc(cmn->dev, cmn->num_dns + child_count,
				    sizeof(*cmn->dns), GFP_KERNEL);
		if (!node)
			return -ENOMEM;

		if (cmn->dns) {
			memcpy(node, cmn->dns, cmn->num_dns * sizeof(*cmn->dns));
			devm_kfree(cmn->dev, cmn->dns);
		}
		cmn->dns = node;

		node = &cmn->xps[node_logid];
		node->pmu_config_low = CMN__PMEVCNT23_COMBINED | CMN__PMEVCNT01_COMBINED | CMN_DTM_PMU_CONFIG_PMU_EN;
		break;
	case CMN_TYPE_DTC:
		if (node_logid > 0) {
			dev_warn(cmn->dev,
				 "multiple DTCs not supported; events outside domain 0 will not be counted correctly\n");
			return 0;
		}
		// FIXME: node_logid is apparently not a nice simple index
		return arm_cmn_init_pmu(cmn, region, node_logid);
	/* These guys have PMU events */
	case CMN_TYPE_DVM:
	case CMN_TYPE_HNI:
	case CMN_TYPE_HNF:
	case CMN_TYPE_SBSX:
	case CMN_TYPE_RNI:
	case CMN_TYPE_RND:
	case CMN_TYPE_CXRA:
	case CMN_TYPE_CXHA:
		node = &cmn->dns[cmn->num_dns++];
		break;
	/* Nothing to see here */
	case CMN_TYPE_RNSAM:
	case CMN_TYPE_CXLA:
		return 0;
	default:
		dev_err(cmn->dev, "invalid node type: 0x%hx\n", node_type);
		return -ENODEV;
	}

	node->pmu_base = region + CMN_PMU_OFFSET;
	node->type = node_type;
	node->logid = node_logid;
	node->id = node_id;

wrangle_children:
	for (i = 0; i < child_count; i++) {
		reg = readq(region + child_poff + i * 8);

		/*
		 * Don't even try to touch anything external, since in general
		 * we haven't a clue how to power up arbitrary CHI requesters.
		 * As of CMN-600r1 these could only be RN-SAMs or CXLAs,
		 * neither of which have any PMU events anyway.
		 * (Actually, CXLAs do seem to have grown some events in r1p2,
		 * but they don't go to regular XP DTMs, and they depend on
		 * secure configuration which we can't easily deal with)
		 */
		if (reg & CMN_CHILD_NODE_EXTERNAL) {
			dev_dbg(cmn->dev, "ignoring external node %llx\n", reg);
			continue;
		}

		/* Recursion is strictly bounded at 2: CFG->XPs->devices */
		ret = arm_cmn_discover(cmn, reg & CMN_CHILD_NODE_ADDR, lvl + 1);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Thanks to the order in which XP logical IDs seem to be assigned, we can
 * handily infer the mesh X dimension by counting the number of XPs at Y=0
 * without needing to know the exact node ID format, which we can then derive.
 */
static void arm_cmn_mesh_fixup(struct arm_cmn *cmn)
{
	int i;

	for (i = 1; i < cmn->num_xps; i++)
		if (cmn->xps[i].id & (1 << 3))
			break;
	cmn->mesh_x = i;
	cmn->mesh_y = cmn->num_xps / i;
	dev_dbg(cmn->dev, "mesh %dx%d, ID width %d\n",
		cmn->mesh_x, cmn->mesh_y, arm_cmn_xyidbits(cmn));
}

/* There is no guarantee that this will work... */
static int arm_cmn_get_root_node(struct arm_cmn *cmn)
{
	int offset;
	u64 reg;

	dev_warn(cmn->dev, "Unknown root node! Trying to probe address space...\n");

	for (offset = 0; offset < SZ_64M; offset += SZ_16K) {
		reg = readq(cmn->base + offset + CMN_NODE_INFO);
		if (FIELD_GET(CMN_NI_NODE_TYPE, reg) == CMN_TYPE_CFG)
			return offset;
	}

	return -ENODEV;
}

static int arm_cmn_acpi_probe(struct platform_device *pdev, struct arm_cmn *cmn)
{
	struct resource *cfg, *root;

	cfg = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!cfg)
		return -EINVAL;

	root = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!root)
		return -EINVAL;

	if (!resource_contains(cfg, root))
		swap(cfg, root);
	/*
	 * Note that devm_ioremap_resource() is dumb and won't let the platform
	 * device claim cfg when the ACPI companion device has already claimed
	 * root within it. But since they *are* already both claimed in the
	 * appropriate name, we don't really need to do it again here anyway.
	 */
	cmn->base = devm_ioremap(cmn->dev, cfg->start, resource_size(cfg));
	if (!cmn->base)
		return -ENOMEM;

	return root->start - cfg->start;
}

static int arm_cmn_of_probe(struct platform_device *pdev, struct arm_cmn *cmn)
{
	struct device_node *np = pdev->dev.of_node;
	struct resource *res;
	u32 rootnode;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -EINVAL;

	cmn->base = devm_ioremap_resource(cmn->dev, res);
	if (IS_ERR(cmn->base))
		return PTR_ERR(cmn->base);

	if (of_property_read_u32(np, "arm,root-node", &rootnode))
		return arm_cmn_get_root_node(cmn);

	return rootnode;
}

static int arm_cmn_probe(struct platform_device *pdev)
{
	struct arm_cmn *cmn;
	int err, rootnode;

	cmn = devm_kzalloc(&pdev->dev, sizeof(*cmn), GFP_KERNEL);
	if (!cmn)
		return -ENOMEM;

	cmn->dev = &pdev->dev;
	platform_set_drvdata(pdev, cmn);

	if (has_acpi_companion(cmn->dev))
		rootnode = arm_cmn_acpi_probe(pdev, cmn);
	else
		rootnode = arm_cmn_of_probe(pdev, cmn);
	if (rootnode < 0)
		return rootnode;

	err = arm_cmn_discover(cmn, rootnode, 0);
	if (err)
		return err;

	arm_cmn_mesh_fixup(cmn);

	return cpuhp_setup_state_multi(CPUHP_AP_PERF_ARM_CMN_ONLINE,
				       "perf/arm/cmn:online", NULL,
				       arm_cmn_pmu_offline_cpu);
}

static int arm_cmn_remove(struct platform_device *pdev)
{
	//TODO: What's the neatest way to find the DTCs and clean them up?

	cpuhp_remove_multi_state(CPUHP_AP_PERF_ARM_CMN_ONLINE);

	return 0;
}

static const struct of_device_id arm_cmn_of_match[] = {
	{ .compatible = "arm,cmn-600", },
	{}
};
MODULE_DEVICE_TABLE(of, arm_cmn_of_match);

#ifdef CONFIG_ACPI
static const struct acpi_device_id arm_cmn_acpi_match[] = {
	{ "ARMHC600", },
	{}
};
MODULE_DEVICE_TABLE(acpi, arm_cmn_acpi_match);
#endif

static struct platform_driver arm_cmn_driver = {
	.driver = {
		.name = "arm-cmn",
		.of_match_table = arm_cmn_of_match,
		.acpi_match_table = ACPI_PTR(arm_cmn_acpi_match),
	},
	.probe = arm_cmn_probe,
	.remove = arm_cmn_remove,
};
module_platform_driver(arm_cmn_driver);

MODULE_AUTHOR("Robin Murphy <robin.murphy@arm.com>");
MODULE_DESCRIPTION("Arm CMN-600 PMU driver");
MODULE_LICENSE("GPL v2");
