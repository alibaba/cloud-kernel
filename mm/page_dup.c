// SPDX-License-Identifier: GPL-2.0

#include <linux/list.h>
#include <linux/xarray.h>
#include <linux/rcupdate.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/rmap.h>
#include <linux/pagemap.h>
#include <linux/migrate.h>
#include <linux/memcontrol.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/page_dup.h>

#include "internal.h"

DEFINE_STATIC_KEY_FALSE(duptext_enabled_key);
struct xarray dup_pages[MAX_NUMNODES];

/* XXX copy_huge_page without cond_resched */
static void copy_huge_page(struct page *dst, struct page *src)
{
	int nr_pages;
	int i;

	nr_pages = thp_nr_pages(src);

	for (i = 0; i < nr_pages; i++)
		copy_highpage(dst + i, src + i);
}

static inline void attach_dup_page_private(struct page *dup_page,
					   struct page *page)
{
	set_page_private(dup_page, (unsigned long)page);
	SetPagePrivate(dup_page);
}

static inline void detach_dup_page_private(struct page *dup_page)
{
	ClearPagePrivate(dup_page);
	set_page_private(dup_page, 0);
}

static struct page *find_get_dup_page(struct page *page, int node)
{
	struct page *dup_page, *tmp_page;
	struct list_head *list;
	int nid = page_to_nid(page);

	XA_STATE(xas, &dup_pages[nid], page_to_pfn(page));

	rcu_read_lock();
repeat:
	dup_page = NULL;
	xas_reset(&xas);
	list = xas_load(&xas);
	if (xas_retry(&xas, list))
		goto repeat;

	if (!list)
		goto out;

	list_for_each_entry(tmp_page, list, lru) {
		if (page_to_nid(tmp_page) == node) {
			dup_page = tmp_page;
			break;
		}
	}

	if (dup_page && !page_cache_get_speculative(dup_page))
		goto repeat;

out:
	rcu_read_unlock();
	return dup_page;
}

static int add_to_dup_pages(struct page *new_page, struct page *page)
{
	struct list_head *list;
	unsigned long flags;
	int ret = 0;
	int nid = page_to_nid(page);

	XA_STATE(xas, &dup_pages[nid], page_to_pfn(page));

	get_page(new_page);
	xas_lock_irqsave(&xas, flags);

	list = xas_load(&xas);
	if (!list) {
		list = kmalloc_node(sizeof(struct list_head), GFP_ATOMIC, nid);
		if (!list) {
			ret = -ENOMEM;
			goto out;
		}

		INIT_LIST_HEAD(list);
		xas_store(&xas, list);
	}

	new_page->mapping = page->mapping;
	new_page->index = page->index;
	attach_dup_page_private(new_page, page);
	SetPageDup(new_page);
	list_add(&new_page->lru, list);

	if (!PageDup(page))
		SetPageDup(page);
	__mod_node_page_state(page_pgdat(page), NR_DUPTEXT,
			      PageTransHuge(page) ? HPAGE_PMD_NR : 1);
	filemap_nr_duptext_add(page_mapping(page),
			       PageTransHuge(page) ? HPAGE_PMD_NR : 1);

out:
	xas_unlock_irqrestore(&xas, flags);
	if (unlikely(ret))
		put_page(new_page);
	return ret;
}

static void __delete_from_dup_pages(struct page *dup_page, struct page *page)
{
	struct address_space *mapping = page_mapping(dup_page);

	list_del(&dup_page->lru);
	ClearPageDup(dup_page);
	detach_dup_page_private(dup_page);
	dup_page->mapping = NULL;
	dup_page->index = 0;
	__mod_node_page_state(page_pgdat(page), NR_DUPTEXT,
			      PageTransHuge(page) ? -HPAGE_PMD_NR : -1);
	filemap_nr_duptext_add(mapping,
			       PageTransHuge(page) ? -HPAGE_PMD_NR : -1);
}

static void delete_from_dup_pages(struct page *page, bool locked)
{
	struct page *tmp_page, *next_page;
	struct list_head *list;
	unsigned long flags;
	enum ttu_flags ttu_flags = TTU_IGNORE_MLOCK | TTU_SYNC | TTU_BATCH_FLUSH;
	int nid = page_to_nid(page);

	XA_STATE(xas, &dup_pages[nid], page_to_pfn(page));

	xas_lock_irqsave(&xas, flags);
	list = xas_load(&xas);
	if (!list) {
		xas_unlock_irqrestore(&xas, flags);
		goto out;
	}
	xas_store(&xas, NULL);
	xas_unlock_irqrestore(&xas, flags);

	if (locked)
		ttu_flags |= TTU_RMAP_LOCKED;
	list_for_each_entry_safe(tmp_page, next_page, list, lru) {
		VM_BUG_ON_PAGE(!page_dup_slave(tmp_page), tmp_page);

		/* Unmap before delete */
		if (page_mapped(tmp_page)) {
			lock_page(tmp_page);
			if (unlikely(PageTransHuge(tmp_page)))
				try_to_unmap(tmp_page, ttu_flags | TTU_SPLIT_HUGE_PMD);
			else
				try_to_unmap(tmp_page, ttu_flags);
			unlock_page(tmp_page);
		}

		__delete_from_dup_pages(tmp_page, page);
		put_page(tmp_page);
	}

	kfree(list);
out:
	ClearPageDup(page);
}

bool __dup_page_suitable(struct vm_area_struct *vma, struct mm_struct *mm)
{
	/* Is executable file? */
	if ((vma->vm_flags & VM_EXEC) && vma->vm_file)  {
		struct inode *inode = vma->vm_file->f_inode;
		struct mem_cgroup *memcg;
		bool allow_duptext = false;

		/* Is read-only ? */
		if (!S_ISREG(inode->i_mode) || inode_is_open_for_write(inode))
			return false;

		/* Allow dup? */
		memcg = get_mem_cgroup_from_mm(mm);
		if (memcg) {
			allow_duptext = memcg->allow_duptext;
			css_put(&memcg->css);
		}

		return allow_duptext;
	}

	return false;
}

struct page *__dup_page_master(struct page *page)
{
	struct page *mhpage = NULL;
	struct page *hpage = compound_head(page);

	if (!page_dup_slave(hpage))
		return page;

	mhpage = (struct page *)page_private(hpage);

	return mhpage + (page - hpage);
}

bool __dup_page_mapped(struct page *page)
{
	struct page *tmp_page;
	struct list_head *list;
	bool ret = false;
	int nid = page_to_nid(page);

	XA_STATE(xas, &dup_pages[nid], 0);

	page = compound_head(page);
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	if (!page_dup_master(page))
		return false;
	xas_set(&xas, page_to_pfn(page));

	rcu_read_lock();
repeat:
	xas_reset(&xas);
	list = xas_load(&xas);
	if (xas_retry(&xas, list))
		goto repeat;

	if (!list)
		goto out;

	list_for_each_entry(tmp_page, list, lru) {
		if (page_mapped(tmp_page)) {
			ret = true;
			break;
		}
	}

out:
	rcu_read_unlock();
	return ret;
}

/* NOTE @page can be file THP head or tail page */
struct page *__dup_page(struct page *page, struct vm_area_struct *vma)
{
	int target_node = numa_node_id();
	struct page *dup_hpage = NULL;
	struct page *hpage = compound_head(page);

	VM_BUG_ON_PAGE(!PageLocked(hpage), hpage);

	if (likely(page_to_nid(hpage) == target_node) ||
	    !dup_page_suitable(vma, current->mm) ||
	    unlikely(PageDirty(page) || PageWriteback(page) || !PageUptodate(page)))
		return NULL;

	if (page_has_private(page) &&
	    !try_to_release_page(page, GFP_ATOMIC))
		return NULL;

	if (page_dup_master(hpage))
		dup_hpage = find_get_dup_page(hpage, target_node);

	if (!dup_hpage) {
		/*
		 * XXX GFP_ATOMIC is used, since dup_page is called
		 * inside rcu lock in filemap_map_pages.
		 */
		gfp_t gfp_mask = GFP_ATOMIC | __GFP_THISNODE;
		unsigned int order = 0;
		struct page *new_hpage = NULL;
		int ret;

		if (PageTransHuge(hpage)) {
			gfp_mask |= __GFP_COMP | __GFP_NOMEMALLOC | __GFP_NOWARN;
			order = HPAGE_PMD_ORDER;
		}

		new_hpage = __alloc_pages(gfp_mask, order, target_node);
		if (!new_hpage)
			return NULL;

		if (PageTransHuge(new_hpage)) {
			prep_transhuge_page(new_hpage);
			copy_huge_page(new_hpage, hpage);
		} else
			copy_highpage(new_hpage, hpage);

		ret = add_to_dup_pages(new_hpage, hpage);
		if (ret) {
			put_page(new_hpage);
			return NULL;
		}

		dup_hpage = new_hpage;
	}

	/* dup_page is returned with refcount increased, but !PageLocked */
	return PageTransHuge(dup_hpage) ? find_subpage(dup_hpage, page_to_pgoff(page))
					: dup_hpage;
}

void __dedup_page(struct page *page, bool locked)
{
	page = compound_head(page);
	VM_BUG_ON_PAGE(!PageLocked(page), page);

	if (!page_dup_master(page))
		return;
	delete_from_dup_pages(page, locked);
}

static int __init setup_duptext(char *s)
{
	if (!strcmp(s, "1"))
		static_branch_enable(&duptext_enabled_key);
	else if (!strcmp(s, "0"))
		static_branch_disable(&duptext_enabled_key);
	return 1;
}
__setup("duptext=", setup_duptext);

#ifdef CONFIG_SYSFS
static ssize_t duptext_enabled_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!static_branch_unlikely(&duptext_enabled_key));
}
static ssize_t duptext_enabled_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	if (!strncmp(buf, "1", 1))
		static_branch_enable(&duptext_enabled_key);
	else if (!strncmp(buf, "0", 1))
		static_branch_disable(&duptext_enabled_key);
	else
		return -EINVAL;

	return count;
}
static struct kobj_attribute duptext_enabled_attr =
	__ATTR(enabled, 0644, duptext_enabled_show,
	       duptext_enabled_store);

static struct attribute *duptext_attrs[] = {
	&duptext_enabled_attr.attr,
	NULL,
};

static struct attribute_group duptext_attr_group = {
	.attrs = duptext_attrs,
};

static int __init duptext_init_sysfs(void)
{
	int err;
	struct kobject *duptext_kobj;

	duptext_kobj = kobject_create_and_add("duptext", mm_kobj);
	if (!duptext_kobj) {
		pr_err("failed to create duptext kobject\n");
		return -ENOMEM;
	}
	err = sysfs_create_group(duptext_kobj, &duptext_attr_group);
	if (err) {
		pr_err("failed to register duptext group\n");
		goto delete_obj;
	}
	return 0;

delete_obj:
	kobject_put(duptext_kobj);
	return err;
}
#endif /* CONFIG_SYSFS */

static int __init duptext_init(void)
{
	int ret = 0, nid;

	for_each_node(nid)
		xa_init_flags(&dup_pages[nid], XA_FLAGS_LOCK_IRQ);

#ifdef CONFIG_SYSFS
	ret = duptext_init_sysfs();
#endif

	return ret;
}
module_init(duptext_init);
