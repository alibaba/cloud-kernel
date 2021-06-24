/*
 * Reap zombie memcgs:
 * - reap at background periodically
 *   echo 1 > /sys/kernel/mm/memcg_reaper/reap_background
 * - one-shot reap triggerred by users
 *   echo 1 > /sys/kernel/mm/memcg_reaper/reap
 *
 * Copyright (C) 2019 Alibaba
 * Author: Xunlei Pang <xlpang@linux.alibaba.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/memcontrol.h>
#include <linux/swap.h> /* try_to_free_mem_cgroup_pages */

#define for_each_mem_cgroup_tree(iter, root)		\
	for (iter = mem_cgroup_iter(root, NULL, NULL);	\
	     iter != NULL;				\
	     iter = mem_cgroup_iter(root, iter, NULL))

/* Reap by kthread at background, off by default */
static unsigned int reaper_kthread_on;
static unsigned int reaper_verbose;
static unsigned int reaper_scan_interval = 5; /* in seconds */
/* pages one scan, 5GiB for 4KiB page size */
static unsigned int reaper_pages_scan = 1310720;

static DECLARE_WAIT_QUEUE_HEAD(reaper_waitq);

#ifdef CONFIG_SYSFS
static void reap_zombie_memcgs(bool background);

#define REAPER_ATTR(_name) \
	static struct kobj_attribute _name##_attr = \
		__ATTR(_name, 0644, _name##_show, _name##_store)

static ssize_t pages_scan_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", reaper_pages_scan);
}

static ssize_t pages_scan_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	unsigned long pages;
	int err;

	err = kstrtoul(buf, 10, &pages);
	if (err || pages > UINT_MAX)
		return -EINVAL;

	reaper_pages_scan = pages;

	return count;
}
REAPER_ATTR(pages_scan);

static ssize_t scan_interval_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", reaper_scan_interval);
}

static ssize_t scan_interval_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int err;
	unsigned long interval;

	err = kstrtoul(buf, 10, &interval);
	if (err || interval > UINT_MAX || interval == 0)
		return -EINVAL;

	reaper_scan_interval = interval;

	return count;
}
REAPER_ATTR(scan_interval);

static ssize_t verbose_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", reaper_verbose);
}

static ssize_t verbose_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int err;
	unsigned long verbose;

	err = kstrtoul(buf, 10, &verbose);
	if (err || (verbose != 0 && verbose != 1))
		return -EINVAL;

	reaper_verbose = verbose;

	return count;
}
REAPER_ATTR(verbose);

static ssize_t reap_background_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", reaper_kthread_on);
}

static ssize_t reap_background_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int err;
	unsigned long enable;

	err = kstrtoul(buf, 10, &enable);
	if (err || (enable != 0 && enable != 1))
		return -EINVAL;

	reaper_kthread_on = enable;
	if (reaper_kthread_on)
		wake_up_interruptible(&reaper_waitq);

	return count;
}
REAPER_ATTR(reap_background);

static ssize_t reap_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", 0);
}

static ssize_t reap_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int err;
	unsigned long enable;

	err = kstrtoul(buf, 10, &enable);
	if (err || enable != 1)
		return -EINVAL;

	reap_zombie_memcgs(false);

	return count;
}
REAPER_ATTR(reap);

static struct attribute *reaper_attrs[] = {
	&pages_scan_attr.attr,
	&scan_interval_attr.attr,
	&verbose_attr.attr,
	&reap_background_attr.attr,
	&reap_attr.attr,
	NULL,
};

static struct attribute_group reaper_attr_group = {
	.attrs = reaper_attrs,
	.name = "memcg_reaper",
};
#endif

static char name_buf[1024];
static unsigned long
do_reap_zombie_memcg(struct mem_cgroup *memcg, bool background)
{
	unsigned long did_some = 0;
	bool drained = false;
	unsigned int jiffies_thresh = dirty_expire_interval * HZ / 100;

	/* Let dirty dying memcgs be controlled a while by writeback */
	if (background &&
	    time_before(jiffies, memcg->offline_jiffies + jiffies_thresh) &&
	    (memcg_page_state_local(memcg, NR_FILE_DIRTY) +
	     memcg_page_state_local(memcg, NR_WRITEBACK)))
		return 0;

	/* try to free all pages in this cgroup */
	while (page_counter_read(&memcg->memory)) {
		unsigned int ret;

		ret = try_to_free_mem_cgroup_pages(memcg, 1, GFP_KERNEL, true);
		did_some += ret;
		if (ret)
			continue;

		if (drained == false) {
			drain_all_stock(memcg);
			drained = true;
		} else {
			break;
		}
	}

	if (reaper_verbose) {
		cgroup_name(memcg->css.cgroup, name_buf, sizeof(name_buf));
		if (page_counter_read(&memcg->memory) == 0) {
			printk_ratelimited("empty zombie memcg: 0x%lx: %s\n",
				(unsigned long)memcg, name_buf);
		} else {
			printk_ratelimited("non-empty zombie memcg: 0x%lx, counter %ld, %s\n",
				(unsigned long)memcg,
				page_counter_read(&memcg->memory),
				name_buf);
		}
	}

	return did_some;
}

static void reap_zombie_memcgs(bool background)
{
	unsigned long reclaimed;
	unsigned long reclaimed_threshold;
	struct mem_cgroup *iter;

	reclaimed = 0;
	reclaimed_threshold = reaper_pages_scan;
	for_each_mem_cgroup_tree(iter, NULL) {
		if (background && reclaimed >= reclaimed_threshold) {
			mem_cgroup_iter_break(NULL, iter);
			break;
		}
		if (mem_cgroup_online(iter))
			continue;
		reclaimed += do_reap_zombie_memcg(iter, background);
		cond_resched();
	}

	if (background && reaper_scan_interval)
		msleep_interruptible(reaper_scan_interval*1000);
}

static int zombie_reaper_thread(void *unused)
{
	set_freezable();

	/* Lower its priority to avoid hogging too much cpu */
	set_user_nice(current, 19);

	while (!kthread_should_stop()) {
		if (reaper_kthread_on) {
			reap_zombie_memcgs(true);
		} else {
			wait_event_freezable(reaper_waitq,
				kthread_should_stop() || reaper_kthread_on);
		}

		try_to_freeze();
	}

	return 0;
}

static int __init memcg_zombie_reaper_init(void)
{
	static struct task_struct *zombie_reaper;
	int err;

	zombie_reaper = kthread_run(zombie_reaper_thread,
			NULL, "zombie_memcg_reaper");
	if (IS_ERR(zombie_reaper)) {
		pr_err("%s: Unable to start reaper kthread\n", __func__);
		return PTR_ERR(zombie_reaper);
	}

#ifdef CONFIG_SYSFS
	err = sysfs_create_group(mm_kobj, &reaper_attr_group);
	if (err) {
		kthread_stop(zombie_reaper);
		pr_err("%s: Unable to populate sysfs files\n", __func__);
		return err;
	}
#endif

	return 0;
}

module_init(memcg_zombie_reaper_init);
