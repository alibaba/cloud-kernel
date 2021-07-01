/*
 * Copyright IBM Corporation, 2012
 * Author Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef _LINUX_HUGETLB_CGROUP_H
#define _LINUX_HUGETLB_CGROUP_H

#include <linux/mmdebug.h>

#ifdef CONFIG_CGROUP_HUGETLB
struct hugetlb_cgroup;
/*
 * Minimum page order trackable by hugetlb cgroup.
 * At least 3 pages are necessary for all the tracking information.
 * The second tail page (hpage[SUBPAGE_INDEX_CGROUP]) is the fault
 * usage cgroup. The third tail page (hpage[SUBPAGE_INDEX_CGROUP_RSVD])
 * is the reservation usage cgroup.
 */
#define HUGETLB_CGROUP_MIN_ORDER order_base_2(__MAX_CGROUP_SUBPAGE_INDEX + 1)

static inline struct hugetlb_cgroup *hugetlb_cgroup_from_page(struct page *page)
{
	VM_BUG_ON_PAGE(!PageHuge(page), page);

	if (compound_order(page) < HUGETLB_CGROUP_MIN_ORDER)
		return NULL;
	return (void *)page_private(page + SUBPAGE_INDEX_CGROUP);
}

static inline
int set_hugetlb_cgroup(struct page *page, struct hugetlb_cgroup *h_cg)
{
	VM_BUG_ON_PAGE(!PageHuge(page), page);

	if (compound_order(page) < HUGETLB_CGROUP_MIN_ORDER)
		return -1;

	set_page_private(page + SUBPAGE_INDEX_CGROUP,
			 (unsigned long)h_cg);

	return 0;
}

static inline bool hugetlb_cgroup_disabled(void)
{
	return !cgroup_subsys_enabled(hugetlb_cgrp_subsys);
}

extern int hugetlb_cgroup_charge_cgroup(int idx, unsigned long nr_pages,
					struct hugetlb_cgroup **ptr);
extern void hugetlb_cgroup_commit_charge(int idx, unsigned long nr_pages,
					 struct hugetlb_cgroup *h_cg,
					 struct page *page);
extern void hugetlb_cgroup_uncharge_page(int idx, unsigned long nr_pages,
					 struct page *page);
extern void hugetlb_cgroup_uncharge_cgroup(int idx, unsigned long nr_pages,
					   struct hugetlb_cgroup *h_cg);
extern void hugetlb_cgroup_file_init(void) __init;
extern void hugetlb_cgroup_migrate(struct page *oldhpage,
				   struct page *newhpage);

#else
static inline struct hugetlb_cgroup *hugetlb_cgroup_from_page(struct page *page)
{
	return NULL;
}

static inline
int set_hugetlb_cgroup(struct page *page, struct hugetlb_cgroup *h_cg)
{
	return 0;
}

static inline bool hugetlb_cgroup_disabled(void)
{
	return true;
}

static inline int
hugetlb_cgroup_charge_cgroup(int idx, unsigned long nr_pages,
			     struct hugetlb_cgroup **ptr)
{
	return 0;
}

static inline void
hugetlb_cgroup_commit_charge(int idx, unsigned long nr_pages,
			     struct hugetlb_cgroup *h_cg,
			     struct page *page)
{
}

static inline void
hugetlb_cgroup_uncharge_page(int idx, unsigned long nr_pages, struct page *page)
{
}

static inline void
hugetlb_cgroup_uncharge_cgroup(int idx, unsigned long nr_pages,
			       struct hugetlb_cgroup *h_cg)
{
}

static inline void hugetlb_cgroup_file_init(void)
{
}

static inline void hugetlb_cgroup_migrate(struct page *oldhpage,
					  struct page *newhpage)
{
}

#endif  /* CONFIG_MEM_RES_CTLR_HUGETLB */
#endif
