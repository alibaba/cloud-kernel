// SPDX-License-Identifier: GPL-2.0
/*
 * virtio-fs: Virtio Filesystem
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include <linux/fs.h>
#include <linux/dax.h>
#include <linux/pci.h>
#include <linux/pfn_t.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_fs.h>
#include <linux/delay.h>
#include <linux/highmem.h>
#include <linux/uio.h>
#include "fuse_i.h"

/* Used to help calculate the FUSE connection's max_pages limit for a request's
 * size. Parts of the struct fuse_req are sliced into scattergather lists in
 * addition to the pages used, so this can help account for that overhead.
 */
#define FUSE_HEADER_OVERHEAD    4

/* List of virtio-fs device instances and a lock for the list. Also provides
 * mutual exclusion in device removal and mounting path
 */
static DEFINE_MUTEX(virtio_fs_mutex);
static LIST_HEAD(virtio_fs_instances);

enum {
	VQ_HIPRIO,
	VQ_REQUEST
};

#define VQ_NAME_LEN	24

/* Per-virtqueue state */
struct virtio_fs_vq {
	spinlock_t lock;
	struct virtqueue *vq;     /* protected by ->lock */
	struct work_struct done_work;
	struct list_head queued_reqs;
	struct list_head end_reqs;	/* End these requests */
	struct delayed_work dispatch_work;
	struct fuse_dev *fud;
	bool connected;
	long in_flight;
	struct completion in_flight_zero; /* No inflight requests */
	char name[VQ_NAME_LEN];
} ____cacheline_aligned_in_smp;

/* State needed for devm_memremap_pages().  This API is called on the
 * underlying pci_dev instead of struct virtio_fs (layering violation).  Since
 * the memremap release function only gets called when the pci_dev is released,
 * keep the associated state separate from struct virtio_fs (it has a different
 * lifecycle from pci_dev).
 */
struct virtio_fs_memremap_info {
	struct dev_pagemap pgmap;
	struct percpu_ref ref;
	struct completion completion;
};

struct virtio_fs_mount_info {
	void *data;
	const char *dev_name;
};

/* A virtio-fs device instance */
struct virtio_fs {
	struct kref refcount;
	struct list_head list;    /* on virtio_fs_instances */
	char *tag;
	struct virtio_fs_vq *vqs;
	unsigned int nvqs;               /* number of virtqueues */
	unsigned int num_request_queues; /* number of request queues */
	struct dax_device *dax_dev;

	/* DAX memory window where file contents are mapped */
	void *window_kaddr;
	phys_addr_t window_phys_addr;
	size_t window_len;
};

struct virtio_fs_forget_req {
	struct fuse_in_header ih;
	struct fuse_forget_in arg;
};

struct virtio_fs_forget {
	/* This request can be temporarily queued on virt queue */
	struct list_head list;
	struct virtio_fs_forget_req req;
};

static int virtio_fs_enqueue_req(struct virtio_fs_vq *fsvq,
				 struct fuse_req *req, bool in_flight);

static inline struct virtio_fs_vq *vq_to_fsvq(struct virtqueue *vq)
{
	struct virtio_fs *fs = vq->vdev->priv;

	return &fs->vqs[vq->index];
}

static inline struct fuse_pqueue *vq_to_fpq(struct virtqueue *vq)
{
	return &vq_to_fsvq(vq)->fud->pq;
}

/* Should be called with fsvq->lock held. */
static inline void inc_in_flight_req(struct virtio_fs_vq *fsvq)
{
	fsvq->in_flight++;
}

/* Should be called with fsvq->lock held. */
static inline void dec_in_flight_req(struct virtio_fs_vq *fsvq)
{
	WARN_ON(fsvq->in_flight <= 0);
	fsvq->in_flight--;
	if (!fsvq->in_flight)
		complete(&fsvq->in_flight_zero);
}

static void release_virtio_fs_obj(struct kref *ref)
{
	struct virtio_fs *vfs = container_of(ref, struct virtio_fs, refcount);

	kfree(vfs->vqs);
	kfree(vfs);
}

/* Make sure virtiofs_mutex is held */
static void virtio_fs_put(struct virtio_fs *fs)
{
	kref_put(&fs->refcount, release_virtio_fs_obj);
}

static void virtio_fs_fiq_release(struct fuse_iqueue *fiq)
{
	struct virtio_fs *vfs = fiq->priv;

	mutex_lock(&virtio_fs_mutex);
	virtio_fs_put(vfs);
	mutex_unlock(&virtio_fs_mutex);
}

static void virtio_fs_drain_queue(struct virtio_fs_vq *fsvq)
{
	WARN_ON(fsvq->in_flight < 0);

	/* Wait for in flight requests to finish.*/
	spin_lock(&fsvq->lock);
	if (fsvq->in_flight) {
		/* We are holding virtio_fs_mutex. There should not be any
		 * waiters waiting for completion.
		 */
		reinit_completion(&fsvq->in_flight_zero);
		spin_unlock(&fsvq->lock);
		wait_for_completion(&fsvq->in_flight_zero);
	} else {
		spin_unlock(&fsvq->lock);
	}

	flush_work(&fsvq->done_work);
	flush_delayed_work(&fsvq->dispatch_work);
}

static void virtio_fs_drain_all_queues_locked(struct virtio_fs *fs)
{
	struct virtio_fs_vq *fsvq;
	int i;

	for (i = 0; i < fs->nvqs; i++) {
		fsvq = &fs->vqs[i];
		virtio_fs_drain_queue(fsvq);
	}
}

static void virtio_fs_drain_all_queues(struct virtio_fs *fs)
{
	/* Provides mutual exclusion between ->remove and ->kill_sb
	 * paths. We don't want both of these draining queue at the
	 * same time. Current completion logic reinits completion
	 * and that means there should not be any other thread
	 * doing reinit or waiting for completion already.
	 */
	mutex_lock(&virtio_fs_mutex);
	virtio_fs_drain_all_queues_locked(fs);
	mutex_unlock(&virtio_fs_mutex);
}

static void virtio_fs_start_all_queues(struct virtio_fs *fs)
{
	struct virtio_fs_vq *fsvq;
	int i;

	for (i = 0; i < fs->nvqs; i++) {
		fsvq = &fs->vqs[i];
		spin_lock(&fsvq->lock);
		fsvq->connected = true;
		spin_unlock(&fsvq->lock);
	}
}

/* Add a new instance to the list or return -EEXIST if tag name exists*/
static int virtio_fs_add_instance(struct virtio_fs *fs)
{
	struct virtio_fs *fs2;
	bool duplicate = false;

	mutex_lock(&virtio_fs_mutex);

	list_for_each_entry(fs2, &virtio_fs_instances, list) {
		if (strcmp(fs->tag, fs2->tag) == 0)
			duplicate = true;
	}

	if (!duplicate)
		list_add_tail(&fs->list, &virtio_fs_instances);

	mutex_unlock(&virtio_fs_mutex);

	if (duplicate)
		return -EEXIST;
	return 0;
}

/* Return the virtio_fs with a given tag, or NULL */
static struct virtio_fs *virtio_fs_find_instance(const char *tag)
{
	struct virtio_fs *fs;

	list_for_each_entry(fs, &virtio_fs_instances, list) {
		if (strcmp(fs->tag, tag) == 0) {
			kref_get(&fs->refcount);
			goto found;
		}
	}

	fs = NULL; /* not found */

found:
	return fs;
}

static void virtio_fs_free_devs(struct virtio_fs *fs)
{
	unsigned int i;

	for (i = 0; i < fs->nvqs; i++) {
		struct virtio_fs_vq *fsvq = &fs->vqs[i];

		if (!fsvq->fud)
			continue;

		fuse_dev_free(fsvq->fud);
		fsvq->fud = NULL;
	}
}

/* Read filesystem name from virtio config into fs->tag (must kfree()). */
static int virtio_fs_read_tag(struct virtio_device *vdev, struct virtio_fs *fs)
{
	char tag_buf[sizeof_field(struct virtio_fs_config, tag)];
	char *end;
	size_t len;

	virtio_cread_bytes(vdev, offsetof(struct virtio_fs_config, tag),
			   &tag_buf, sizeof(tag_buf));
	end = memchr(tag_buf, '\0', sizeof(tag_buf));
	if (end == tag_buf)
		return -EINVAL; /* empty tag */
	if (!end)
		end = &tag_buf[sizeof(tag_buf)];

	len = end - tag_buf;
	fs->tag = devm_kmalloc(&vdev->dev, len + 1, GFP_KERNEL);
	if (!fs->tag)
		return -ENOMEM;
	memcpy(fs->tag, tag_buf, len);
	fs->tag[len] = '\0';
	return 0;
}

/* Work function for hiprio completion */
static void virtio_fs_hiprio_done_work(struct work_struct *work)
{
	struct virtio_fs_vq *fsvq = container_of(work, struct virtio_fs_vq,
						 done_work);
	struct virtqueue *vq = fsvq->vq;

	/* Free completed FUSE_FORGET requests */
	spin_lock(&fsvq->lock);
	do {
		unsigned int len;
		void *req;

		virtqueue_disable_cb(vq);

		while ((req = virtqueue_get_buf(vq, &len)) != NULL) {
			kfree(req);
			dec_in_flight_req(fsvq);
		}
	} while (!virtqueue_enable_cb(vq) && likely(!virtqueue_is_broken(vq)));
	spin_unlock(&fsvq->lock);
}

static void virtio_fs_request_dispatch_work(struct work_struct *work)
{
	struct fuse_req *req;
	struct virtio_fs_vq *fsvq = container_of(work, struct virtio_fs_vq,
						 dispatch_work.work);
	struct fuse_conn *fc = fsvq->fud->fc;
	int ret;

	pr_debug("virtio-fs: worker %s called.\n", __func__);
	while (1) {
		spin_lock(&fsvq->lock);
		req = list_first_entry_or_null(&fsvq->end_reqs, struct fuse_req,
					       list);
		if (!req) {
			spin_unlock(&fsvq->lock);
			break;
		}

		list_del_init(&req->list);
		spin_unlock(&fsvq->lock);
		fuse_request_end(fc, req);
	}

	/* Dispatch pending requests */
	while (1) {
		spin_lock(&fsvq->lock);
		req = list_first_entry_or_null(&fsvq->queued_reqs,
					       struct fuse_req, list);
		if (!req) {
			spin_unlock(&fsvq->lock);
			return;
		}
		list_del_init(&req->list);
		spin_unlock(&fsvq->lock);

		ret = virtio_fs_enqueue_req(fsvq, req, true);
		if (ret < 0) {
			if (ret == -ENOMEM || ret == -ENOSPC) {
				spin_lock(&fsvq->lock);
				list_add_tail(&req->list, &fsvq->queued_reqs);
				schedule_delayed_work(&fsvq->dispatch_work,
						      msecs_to_jiffies(1));
				spin_unlock(&fsvq->lock);
				return;
			}
			req->out.h.error = ret;
			spin_lock(&fsvq->lock);
			dec_in_flight_req(fsvq);
			spin_unlock(&fsvq->lock);
			pr_err("virtio-fs: virtio_fs_enqueue_req() failed %d\n",
			       ret);
			fuse_request_end(fc, req);
		}
	}
}

/*
 * Returns 1 if queue is full and sender should wait a bit before sending
 * next request, 0 otherwise.
 */
static int send_forget_request(struct virtio_fs_vq *fsvq,
			       struct virtio_fs_forget *forget,
			       bool in_flight)
{
	struct scatterlist sg;
	struct virtqueue *vq;
	int ret = 0;
	bool notify;
	struct virtio_fs_forget_req *req = &forget->req;

	spin_lock(&fsvq->lock);
	if (!fsvq->connected) {
		if (in_flight)
			dec_in_flight_req(fsvq);
		kfree(forget);
		goto out;
	}

	sg_init_one(&sg, req, sizeof(*req));
	vq = fsvq->vq;
	dev_dbg(&vq->vdev->dev, "%s\n", __func__);

	ret = virtqueue_add_outbuf(vq, &sg, 1, forget, GFP_ATOMIC);
	if (ret < 0) {
		if (ret == -ENOMEM || ret == -ENOSPC) {
			pr_debug("virtio-fs: Could not queue FORGET: err=%d. Will try later\n",
				 ret);
			list_add_tail(&forget->list, &fsvq->queued_reqs);
			schedule_delayed_work(&fsvq->dispatch_work,
					      msecs_to_jiffies(1));
			if (!in_flight)
				inc_in_flight_req(fsvq);
			/* Queue is full */
			ret = 1;
		} else {
			pr_debug("virtio-fs: Could not queue FORGET: err=%d. Dropping it.\n",
				 ret);
			kfree(forget);
			if (in_flight)
				dec_in_flight_req(fsvq);
		}
		goto out;
	}

	if (!in_flight)
		inc_in_flight_req(fsvq);
	notify = virtqueue_kick_prepare(vq);
	spin_unlock(&fsvq->lock);

	if (notify)
		virtqueue_notify(vq);
	return ret;
out:
	spin_unlock(&fsvq->lock);
	return ret;
}

static void virtio_fs_hiprio_dispatch_work(struct work_struct *work)
{
	struct virtio_fs_forget *forget;
	struct virtio_fs_vq *fsvq = container_of(work, struct virtio_fs_vq,
						 dispatch_work.work);
	pr_debug("virtio-fs: worker %s called.\n", __func__);
	while (1) {
		spin_lock(&fsvq->lock);
		forget = list_first_entry_or_null(&fsvq->queued_reqs,
					struct virtio_fs_forget, list);
		if (!forget) {
			spin_unlock(&fsvq->lock);
			return;
		}

		list_del(&forget->list);
		spin_unlock(&fsvq->lock);
		if (send_forget_request(fsvq, forget, true))
			return;
	}
}

/* Allocate and copy args into req->argbuf */
static int copy_args_to_argbuf(struct fuse_req *req)
{
	unsigned offset = 0;
	unsigned num_in;
	unsigned num_out;
	unsigned len;
	unsigned i;

	num_in = req->in.numargs - req->in.argpages;
	num_out = req->out.numargs - req->out.argpages;
	len = fuse_len_args(num_in, (struct fuse_arg *)req->in.args) +
	      fuse_len_args(num_out, req->out.args);

	req->argbuf = kmalloc(len, GFP_ATOMIC);
	if (!req->argbuf)
		return -ENOMEM;

	for (i = 0; i < num_in; i++) {
		memcpy(req->argbuf + offset,
		       req->in.args[i].value,
		       req->in.args[i].size);
		offset += req->in.args[i].size;
	}

	return 0;
}

/* Copy args out of and free req->argbuf */
static void copy_args_from_argbuf(struct fuse_req *req)
{
	unsigned remaining;
	unsigned offset;
	unsigned num_in;
	unsigned num_out;
	unsigned i;

	remaining = req->out.h.len - sizeof(req->out.h);
	num_in = req->in.numargs - req->in.argpages;
	num_out = req->out.numargs - req->out.argpages;
	offset = fuse_len_args(num_in, (struct fuse_arg *)req->in.args);

	for (i = 0; i < num_out; i++) {
		unsigned argsize = req->out.args[i].size;

		if (req->out.argvar &&
		    i == req->out.numargs - 1 &&
		    argsize > remaining) {
			argsize = remaining;
		}

		memcpy(req->out.args[i].value, req->argbuf + offset, argsize);
		offset += argsize;

		if (i != req->out.numargs - 1)
			remaining -= argsize;
	}

	/* Store the actual size of the variable-length arg */
	if (req->out.argvar)
		req->out.args[req->out.numargs - 1].size = remaining;

	kfree(req->argbuf);
	req->argbuf = NULL;
}

/* Work function for request completion */
static void virtio_fs_requests_done_work(struct work_struct *work)
{
	struct virtio_fs_vq *fsvq = container_of(work, struct virtio_fs_vq,
						 done_work);
	struct fuse_pqueue *fpq = &fsvq->fud->pq;
	struct fuse_conn *fc = fsvq->fud->fc;
	struct virtqueue *vq = fsvq->vq;
	struct fuse_req *req;
	struct fuse_req *next;
	unsigned int len, i, thislen;
	struct page *page;
	LIST_HEAD(reqs);

	/* Collect completed requests off the virtqueue */
	spin_lock(&fsvq->lock);
	do {
		virtqueue_disable_cb(vq);

		while ((req = virtqueue_get_buf(vq, &len)) != NULL) {
			spin_lock(&fpq->lock);
			list_move_tail(&req->list, &reqs);
			spin_unlock(&fpq->lock);
		}
	} while (!virtqueue_enable_cb(vq) && likely(!virtqueue_is_broken(vq)));
	spin_unlock(&fsvq->lock);

	/* End requests */
	list_for_each_entry_safe(req, next, &reqs, list) {
		/*
		 * TODO verify that server properly follows FUSE protocol
		 * (oh.uniq, oh.len)
		 */
		copy_args_from_argbuf(req);

		if (req->out.argpages && req->out.page_zeroing) {
			len = req->out.args[req->out.numargs - 1].size;
			for (i = 0; i < req->num_pages; i++) {
				thislen = req->page_descs[i].length;
				if (len < thislen) {
					WARN_ON(req->page_descs[i].offset);
					page = req->pages[i];
					zero_user_segment(page, len, thislen);
					len = 0;
				} else {
					len -= thislen;
				}
			}
		}

		spin_lock(&fpq->lock);
		clear_bit(FR_SENT, &req->flags);
		list_del_init(&req->list);
		spin_unlock(&fpq->lock);

		fuse_request_end(fc, req);
		spin_lock(&fsvq->lock);
		dec_in_flight_req(fsvq);
		spin_unlock(&fsvq->lock);
	}
}

/* Virtqueue interrupt handler */
static void virtio_fs_vq_done(struct virtqueue *vq)
{
	struct virtio_fs_vq *fsvq = vq_to_fsvq(vq);

	dev_dbg(&vq->vdev->dev, "%s %s\n", __func__, fsvq->name);

	schedule_work(&fsvq->done_work);
}

static void virtio_fs_init_vq(struct virtio_fs_vq *fsvq, char *name,
			      int vq_type)
{
	strncpy(fsvq->name, name, VQ_NAME_LEN);
	spin_lock_init(&fsvq->lock);
	INIT_LIST_HEAD(&fsvq->queued_reqs);
	INIT_LIST_HEAD(&fsvq->end_reqs);
	init_completion(&fsvq->in_flight_zero);

	if (vq_type == VQ_REQUEST) {
		INIT_WORK(&fsvq->done_work, virtio_fs_requests_done_work);
		INIT_DELAYED_WORK(&fsvq->dispatch_work,
				  virtio_fs_request_dispatch_work);
	} else {
		INIT_WORK(&fsvq->done_work, virtio_fs_hiprio_done_work);
		INIT_DELAYED_WORK(&fsvq->dispatch_work,
				  virtio_fs_hiprio_dispatch_work);
	}
}

/* Initialize virtqueues */
static int virtio_fs_setup_vqs(struct virtio_device *vdev,
			       struct virtio_fs *fs)
{
	struct virtqueue **vqs;
	vq_callback_t **callbacks;
	const char **names;
	unsigned int i;
	int ret = 0;

	virtio_cread(vdev, struct virtio_fs_config, num_request_queues,
		     &fs->num_request_queues);
	if (fs->num_request_queues == 0)
		return -EINVAL;

	fs->nvqs = VQ_REQUEST + fs->num_request_queues;
	fs->vqs = kcalloc(fs->nvqs, sizeof(fs->vqs[VQ_HIPRIO]), GFP_KERNEL);
	if (!fs->vqs)
		return -ENOMEM;

	vqs = kmalloc_array(fs->nvqs, sizeof(vqs[VQ_HIPRIO]), GFP_KERNEL);
	callbacks = kmalloc_array(fs->nvqs, sizeof(callbacks[VQ_HIPRIO]),
					GFP_KERNEL);
	names = kmalloc_array(fs->nvqs, sizeof(names[VQ_HIPRIO]), GFP_KERNEL);
	if (!vqs || !callbacks || !names) {
		ret = -ENOMEM;
		goto out;
	}

	/* Initialize the hiprio/forget request virtqueue */
	callbacks[VQ_HIPRIO] = virtio_fs_vq_done;
	virtio_fs_init_vq(&fs->vqs[VQ_HIPRIO], "hiprio", VQ_HIPRIO);
	names[VQ_HIPRIO] = fs->vqs[VQ_HIPRIO].name;

	/* Initialize the requests virtqueues */
	for (i = VQ_REQUEST; i < fs->nvqs; i++) {
		char vq_name[VQ_NAME_LEN];

		snprintf(vq_name, VQ_NAME_LEN, "requests.%u", i - VQ_REQUEST);
		virtio_fs_init_vq(&fs->vqs[i], vq_name, VQ_REQUEST);
		callbacks[i] = virtio_fs_vq_done;
		names[i] = fs->vqs[i].name;
	}

	ret = virtio_find_vqs(vdev, fs->nvqs, vqs, callbacks, names, NULL);
	if (ret < 0)
		goto out;

	for (i = 0; i < fs->nvqs; i++)
		fs->vqs[i].vq = vqs[i];

	virtio_fs_start_all_queues(fs);
out:
	kfree(names);
	kfree(callbacks);
	kfree(vqs);
	if (ret)
		kfree(fs->vqs);
	return ret;
}

/* Free virtqueues (device must already be reset) */
static void virtio_fs_cleanup_vqs(struct virtio_device *vdev,
				  struct virtio_fs *fs)
{
	vdev->config->del_vqs(vdev);
}

/* Map a window offset to a page frame number.  The window offset will have
 * been produced by .iomap_begin(), which maps a file offset to a window
 * offset.
 */
static long virtio_fs_direct_access(struct dax_device *dax_dev, pgoff_t pgoff,
				    long nr_pages, void **kaddr, pfn_t *pfn)
{
	struct virtio_fs *fs = dax_get_private(dax_dev);
	phys_addr_t offset = PFN_PHYS(pgoff);
	size_t max_nr_pages = fs->window_len/PAGE_SIZE - pgoff;

	if (kaddr)
		*kaddr = fs->window_kaddr + offset;
	if (pfn)
		*pfn = phys_to_pfn_t(fs->window_phys_addr + offset,
					PFN_DEV | PFN_MAP);
	return nr_pages > max_nr_pages ? max_nr_pages : nr_pages;
}

static size_t virtio_fs_copy_from_iter(struct dax_device *dax_dev,
				       pgoff_t pgoff, void *addr,
				       size_t bytes, struct iov_iter *i)
{
	return copy_from_iter(addr, bytes, i);
}

static size_t virtio_fs_copy_to_iter(struct dax_device *dax_dev,
				       pgoff_t pgoff, void *addr,
				       size_t bytes, struct iov_iter *i)
{
	return copy_to_iter(addr, bytes, i);
}

static const struct dax_operations virtio_fs_dax_ops = {
	.direct_access = virtio_fs_direct_access,
	.copy_from_iter = virtio_fs_copy_from_iter,
	.copy_to_iter = virtio_fs_copy_to_iter,
};

static void virtio_fs_percpu_release(struct percpu_ref *ref)
{
	struct virtio_fs_memremap_info *mi =
		container_of(ref, struct virtio_fs_memremap_info, ref);

	complete(&mi->completion);
}

static void virtio_fs_percpu_exit(void *data)
{
	struct virtio_fs_memremap_info *mi = data;

	wait_for_completion(&mi->completion);
	percpu_ref_exit(&mi->ref);
}

static void virtio_fs_percpu_kill(struct percpu_ref *ref)
{
	percpu_ref_kill(ref);
}

static void virtio_fs_cleanup_dax(void *data)
{
	struct dax_device *dax_dev = data;

	kill_dax(dax_dev);
	put_dax(dax_dev);
}

static void virtio_fs_release_pgmap_ops(void *_pgmap)
{
	dev_pagemap_put_ops();
}

static void virtio_fs_fsdax_pagefree(struct page *page, void *data)
{
	wake_up_var(&page->_refcount);
}

static int virtio_fs_setup_pagemap_fsdax(struct device *dev,
					 struct dev_pagemap *pgmap)
{
	dev_pagemap_get_ops();
	if (devm_add_action_or_reset(dev, virtio_fs_release_pgmap_ops, pgmap))
		return -ENOMEM;
	pgmap->type = MEMORY_DEVICE_FS_DAX;
	pgmap->page_free = virtio_fs_fsdax_pagefree;

	return 0;
}

static int virtio_fs_setup_dax(struct virtio_device *vdev, struct virtio_fs *fs)
{
	struct virtio_shm_region cache_reg;
	struct virtio_fs_memremap_info *mi;
	struct dev_pagemap *pgmap;
	bool have_cache;
	int ret;

	if (!IS_ENABLED(CONFIG_FUSE_DAX))
		return 0;

	/* Get cache region */
	have_cache = virtio_get_shm_region(vdev, &cache_reg,
					   (u8)VIRTIO_FS_SHMCAP_ID_CACHE);
	if (!have_cache) {
		dev_notice(&vdev->dev, "%s: No cache capability\n", __func__);
		return 0;
	}

	if (!devm_request_mem_region(&vdev->dev, cache_reg.addr, cache_reg.len,
				     dev_name(&vdev->dev))) {
		dev_warn(&vdev->dev, "could not reserve region addr=0x%llx len=0x%llx\n",
			 cache_reg.addr, cache_reg.len);
		return -EBUSY;
	}

	dev_notice(&vdev->dev, "Cache len: 0x%llx @ 0x%llx\n", cache_reg.len,
		   cache_reg.addr);

	mi = devm_kzalloc(&vdev->dev, sizeof(*mi), GFP_KERNEL);
	if (!mi)
		return -ENOMEM;

	init_completion(&mi->completion);
	ret = percpu_ref_init(&mi->ref, virtio_fs_percpu_release, 0,
			      GFP_KERNEL);
	if (ret < 0) {
		dev_err(&vdev->dev, "%s: percpu_ref_init failed (%d)\n",
			__func__, ret);
		return ret;
	}

	ret = devm_add_action(&vdev->dev, virtio_fs_percpu_exit, mi);
	if (ret < 0) {
		percpu_ref_exit(&mi->ref);
		return ret;
	}

	pgmap = &mi->pgmap;
	pgmap->altmap_valid = false;
	pgmap->ref = &mi->ref;
	pgmap->kill = virtio_fs_percpu_kill;

	if (virtio_fs_setup_pagemap_fsdax(&vdev->dev, pgmap))
		return -ENOMEM;

	/* Ideally we would directly use the PCI BAR resource but
	 * devm_memremap_pages() wants its own copy in pgmap.  So
	 * initialize a struct resource from scratch (only the start
	 * and end fields will be used).
	 */
	pgmap->res = (struct resource){
		.name = "virtio-fs dax window",
		.start = (phys_addr_t) cache_reg.addr,
		.end = (phys_addr_t) cache_reg.addr + cache_reg.len - 1,
	};

	fs->window_kaddr = devm_memremap_pages(&vdev->dev, pgmap);
	if (IS_ERR(fs->window_kaddr))
		return PTR_ERR(fs->window_kaddr);

	fs->window_phys_addr = (phys_addr_t) cache_reg.addr;
	fs->window_len = (phys_addr_t) cache_reg.len;

	dev_dbg(&vdev->dev, "%s: window kaddr 0x%px phys_addr 0x%llx len 0x%llx\n",
		__func__, fs->window_kaddr, cache_reg.addr, cache_reg.len);

	fs->dax_dev = alloc_dax(fs, NULL, &virtio_fs_dax_ops, 0);
	if (IS_ERR(fs->dax_dev))
		return PTR_ERR(fs->dax_dev);

	return devm_add_action_or_reset(&vdev->dev, virtio_fs_cleanup_dax,
					fs->dax_dev);
}

static int virtio_fs_probe(struct virtio_device *vdev)
{
	struct virtio_fs *fs;
	int ret;

	fs = kzalloc(sizeof(*fs), GFP_KERNEL);
	if (!fs)
		return -ENOMEM;
	kref_init(&fs->refcount);
	vdev->priv = fs;

	ret = virtio_fs_read_tag(vdev, fs);
	if (ret < 0)
		goto out;

	ret = virtio_fs_setup_vqs(vdev, fs);
	if (ret < 0)
		goto out;

	/* TODO vq affinity */

	ret = virtio_fs_setup_dax(vdev, fs);
	if (ret < 0)
		goto out_vqs;

	/* Bring the device online in case the filesystem is mounted and
	 * requests need to be sent before we return.
	 */
	virtio_device_ready(vdev);

	ret = virtio_fs_add_instance(fs);
	if (ret < 0)
		goto out_vqs;

	return 0;

out_vqs:
	vdev->config->reset(vdev);
	virtio_fs_cleanup_vqs(vdev, fs);

out:
	vdev->priv = NULL;
	kfree(fs);
	return ret;
}

static void virtio_fs_stop_all_queues(struct virtio_fs *fs)
{
	struct virtio_fs_vq *fsvq;
	int i;

	for (i = 0; i < fs->nvqs; i++) {
		fsvq = &fs->vqs[i];
		spin_lock(&fsvq->lock);
		fsvq->connected = false;
		spin_unlock(&fsvq->lock);
	}
}

static void virtio_fs_remove(struct virtio_device *vdev)
{
	struct virtio_fs *fs = vdev->priv;

	mutex_lock(&virtio_fs_mutex);
	/* This device is going away. No one should get new reference */
	list_del_init(&fs->list);
	virtio_fs_stop_all_queues(fs);
	virtio_fs_drain_all_queues_locked(fs);
	vdev->config->reset(vdev);
	virtio_fs_cleanup_vqs(vdev, fs);

	vdev->priv = NULL;
	/* Put device reference on virtio_fs object */
	virtio_fs_put(fs);
	mutex_unlock(&virtio_fs_mutex);
}

#ifdef CONFIG_PM_SLEEP
static int virtio_fs_freeze(struct virtio_device *vdev)
{
	/* TODO need to save state here */
	pr_warn("virtio-fs: suspend/resume not yet supported\n");
	return -EOPNOTSUPP;
}

static int virtio_fs_restore(struct virtio_device *vdev)
{
	 /* TODO need to restore state here */
	return 0;
}
#endif /* CONFIG_PM_SLEEP */

static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_FS, VIRTIO_DEV_ANY_ID },
	{},
};

static const unsigned int feature_table[] = {};

static struct virtio_driver virtio_fs_driver = {
	.driver.name		= KBUILD_MODNAME,
	.driver.owner		= THIS_MODULE,
	.id_table		= id_table,
	.feature_table		= feature_table,
	.feature_table_size	= ARRAY_SIZE(feature_table),
	.probe			= virtio_fs_probe,
	.remove			= virtio_fs_remove,
#ifdef CONFIG_PM_SLEEP
	.freeze			= virtio_fs_freeze,
	.restore		= virtio_fs_restore,
#endif
};

static void virtio_fs_wake_forget_and_unlock(struct fuse_iqueue *fiq)
__releases(fiq->lock)
{
	struct fuse_forget_link *link;
	struct virtio_fs_forget *forget;
	struct virtio_fs_forget_req *req;
	struct virtio_fs *fs;
	struct virtio_fs_vq *fsvq;
	u64 unique;

	link = fuse_dequeue_forget(fiq, 1, NULL);
	unique = fuse_get_unique(fiq);

	fs = fiq->priv;
	fsvq = &fs->vqs[VQ_HIPRIO];
	spin_unlock(&fiq->lock);

	/* Allocate a buffer for the request */
	forget = kmalloc(sizeof(*forget), GFP_NOFS | __GFP_NOFAIL);
	req = &forget->req;

	req->ih = (struct fuse_in_header){
		.opcode = FUSE_FORGET,
		.nodeid = link->forget_one.nodeid,
		.unique = unique,
		.len = sizeof(*req),
	};
	req->arg = (struct fuse_forget_in){
		.nlookup = link->forget_one.nlookup,
	};

	send_forget_request(fsvq, forget, false);
	kfree(link);
}

static void virtio_fs_wake_interrupt_and_unlock(struct fuse_iqueue *fiq)
__releases(fiq->lock)
{
	/*
	 * TODO interrupts.
	 *
	 * Normal fs operations on a local filesystems aren't interruptible.
	 * Exceptions are blocking lock operations; for example fcntl(F_SETLKW)
	 * with shared lock between host and guest.
	 */
	spin_unlock(&fiq->lock);
}

/* Return the number of scatter-gather list elements required */
static unsigned int sg_count_fuse_req(struct fuse_req *req)
{
	unsigned int total_sgs = 1 /* fuse_in_header */;

	if (req->in.numargs - req->in.argpages)
		total_sgs += 1;

	if (req->in.argpages)
		total_sgs += req->num_pages;

	if (!test_bit(FR_ISREPLY, &req->flags))
		return total_sgs;

	total_sgs += 1 /* fuse_out_header */;

	if (req->out.numargs - req->out.argpages)
		total_sgs += 1;

	if (req->out.argpages)
		total_sgs += req->num_pages;

	return total_sgs;
}

/* Add pages to scatter-gather list and return number of elements used */
static unsigned int sg_init_fuse_pages(struct scatterlist *sg,
				       struct page **pages,
				       struct fuse_page_desc *page_descs,
				       unsigned int num_pages,
				       unsigned int total_len)
{
	unsigned int i;
	unsigned int this_len;

	for (i = 0; i < num_pages && total_len; i++) {
		sg_init_table(&sg[i], 1);
		this_len =  min(page_descs[i].length, total_len);
		sg_set_page(&sg[i], pages[i], this_len, page_descs[i].offset);
		total_len -= this_len;
	}

	return i;
}

/* Add args to scatter-gather list and return number of elements used */
static unsigned int sg_init_fuse_args(struct scatterlist *sg,
				      struct fuse_req *req,
				      struct fuse_arg *args,
				      unsigned int numargs,
				      bool argpages,
				      void *argbuf,
				      unsigned int *len_used)
{
	unsigned int total_sgs = 0;
	unsigned int len;

	len = fuse_len_args(numargs - argpages, args);
	if (len)
		sg_init_one(&sg[total_sgs++], argbuf, len);

	if (argpages)
		total_sgs += sg_init_fuse_pages(&sg[total_sgs],
						req->pages,
						req->page_descs,
						req->num_pages,
						args[numargs - 1].size);

	if (len_used)
		*len_used = len;

	return total_sgs;
}

/* Add a request to a virtqueue and kick the device */
static int virtio_fs_enqueue_req(struct virtio_fs_vq *fsvq,
				 struct fuse_req *req, bool in_flight)
{
	/* requests need at least 4 elements */
	struct scatterlist *stack_sgs[6];
	struct scatterlist stack_sg[ARRAY_SIZE(stack_sgs)];
	struct scatterlist **sgs = stack_sgs;
	struct scatterlist *sg = stack_sg;
	struct virtqueue *vq;
	unsigned int argbuf_used = 0;
	unsigned int out_sgs = 0;
	unsigned int in_sgs = 0;
	unsigned int total_sgs;
	unsigned int i;
	int ret;
	bool notify;
	struct fuse_pqueue *fpq;

	/* Does the sglist fit on the stack? */
	total_sgs = sg_count_fuse_req(req);
	if (total_sgs > ARRAY_SIZE(stack_sgs)) {
		sgs = kmalloc_array(total_sgs, sizeof(sgs[0]), GFP_ATOMIC);
		sg = kmalloc_array(total_sgs, sizeof(sg[0]), GFP_ATOMIC);
		if (!sgs || !sg) {
			ret = -ENOMEM;
			goto out;
		}
	}

	/* Use a bounce buffer since stack args cannot be mapped */
	ret = copy_args_to_argbuf(req);
	if (ret < 0)
		goto out;

	/* Request elements */
	sg_init_one(&sg[out_sgs++], &req->in.h, sizeof(req->in.h));
	out_sgs += sg_init_fuse_args(&sg[out_sgs], req,
				     (struct fuse_arg *)req->in.args,
				     req->in.numargs, req->in.argpages,
				     req->argbuf, &argbuf_used);

	/* Reply elements */
	if (test_bit(FR_ISREPLY, &req->flags)) {
		sg_init_one(&sg[out_sgs + in_sgs++],
			    &req->out.h, sizeof(req->out.h));
		in_sgs += sg_init_fuse_args(&sg[out_sgs + in_sgs], req,
					    req->out.args, req->out.numargs,
					    req->out.argpages,
					    req->argbuf + argbuf_used, NULL);
	}

	WARN_ON(out_sgs + in_sgs != total_sgs);

	for (i = 0; i < total_sgs; i++)
		sgs[i] = &sg[i];

	spin_lock(&fsvq->lock);

	if (!fsvq->connected) {
		spin_unlock(&fsvq->lock);
		ret = -ENOTCONN;
		goto out;
	}

	vq = fsvq->vq;
	ret = virtqueue_add_sgs(vq, sgs, out_sgs, in_sgs, req, GFP_ATOMIC);
	if (ret < 0) {
		spin_unlock(&fsvq->lock);
		goto out;
	}

	/* Request successfully sent. */
	fpq = &fsvq->fud->pq;
	spin_lock(&fpq->lock);
	list_add_tail(&req->list, &fpq->processing);
	spin_unlock(&fpq->lock);
	set_bit(FR_SENT, &req->flags);
	/* matches barrier in request_wait_answer() */
	smp_mb__after_atomic();

	if (!in_flight)
		inc_in_flight_req(fsvq);
	notify = virtqueue_kick_prepare(vq);

	spin_unlock(&fsvq->lock);

	if (notify)
		virtqueue_notify(vq);

out:
	if (ret < 0 && req->argbuf) {
		kfree(req->argbuf);
		req->argbuf = NULL;
	}
	if (sgs != stack_sgs) {
		kfree(sgs);
		kfree(sg);
	}

	return ret;
}

static void virtio_fs_wake_pending_and_unlock(struct fuse_iqueue *fiq)
__releases(fiq->lock)
{
	unsigned int queue_id = VQ_REQUEST; /* TODO multiqueue */
	struct virtio_fs *fs;
	struct fuse_req *req;
	struct virtio_fs_vq *fsvq;
	int ret;

	WARN_ON(list_empty(&fiq->pending));
	req = list_last_entry(&fiq->pending, struct fuse_req, list);
	clear_bit(FR_PENDING, &req->flags);
	list_del_init(&req->list);
	WARN_ON(!list_empty(&fiq->pending));
	spin_unlock(&fiq->lock);

	fs = fiq->priv;

	pr_debug("%s: opcode %u unique %#llx nodeid %#llx in.len %u out.len %u\n",
		  __func__, req->in.h.opcode, req->in.h.unique,
		 req->in.h.nodeid, req->in.h.len,
		 fuse_len_args(req->out.numargs, req->out.args));

	fsvq = &fs->vqs[queue_id];
	ret = virtio_fs_enqueue_req(fsvq, req, false);
	if (ret < 0) {
		if (ret == -ENOMEM || ret == -ENOSPC) {
			/*
			 * Virtqueue full. Retry submission from worker
			 * context as we might be holding fc->bg_lock.
			 */
			spin_lock(&fsvq->lock);
			list_add_tail(&req->list, &fsvq->queued_reqs);
			inc_in_flight_req(fsvq);
			schedule_delayed_work(&fsvq->dispatch_work,
						msecs_to_jiffies(1));
			spin_unlock(&fsvq->lock);
			return;
		}
		req->out.h.error = ret;
		pr_err("virtio-fs: virtio_fs_enqueue_req() failed %d\n", ret);

		/* Can't end request in submission context. Use a worker */
		spin_lock(&fsvq->lock);
		list_add_tail(&req->list, &fsvq->end_reqs);
		schedule_delayed_work(&fsvq->dispatch_work, 0);
		spin_unlock(&fsvq->lock);
		return;
	}
}

static const struct fuse_iqueue_ops virtio_fs_fiq_ops = {
	.wake_forget_and_unlock		= virtio_fs_wake_forget_and_unlock,
	.wake_interrupt_and_unlock	= virtio_fs_wake_interrupt_and_unlock,
	.wake_pending_and_unlock	= virtio_fs_wake_pending_and_unlock,
	.release			= virtio_fs_fiq_release,
};

static int virtio_fs_fill_super(struct super_block *sb, void *data,
				int silent)
{
	struct fuse_mount_data d;
	struct fuse_conn *fc;
	struct virtio_fs *fs;
	int is_bdev = sb->s_bdev != NULL;
	unsigned int i;
	int err;
	struct fuse_req *init_req;
	struct virtio_fs_mount_info *info = (struct virtio_fs_mount_info *)data;
	const char *tag = NULL;
	unsigned int virtqueue_size;

	mutex_lock(&virtio_fs_mutex);
	err = -EINVAL;
	if (!parse_fuse_opt(info->data, &d, is_bdev, sb->s_user_ns, true))
		goto err;

	if (d.fd_present) {
		pr_err("virtio-fs: fd option cannot be used\n");
		goto err;
	}
	if (!d.tag_present) {
		tag = info->dev_name;
	} else {
		tag = d.tag;
	}
	if (!tag) {
		pr_err("virtio-fs: missing tag option\n");
		goto err;
	}

	fs = virtio_fs_find_instance(tag);
	if (!fs) {
		pr_err("virtio-fs: tag not found\n");
		err = -ENOENT;
		goto err;
	}

	virtqueue_size = virtqueue_get_vring_size(fs->vqs[VQ_REQUEST].vq);
	if (WARN_ON(virtqueue_size <= FUSE_HEADER_OVERHEAD)) {
		err = -EIO;
		goto err;
	}

	/* TODO lock */
	if (fs->vqs[VQ_REQUEST].fud) {
		pr_err("virtio-fs: device already in use\n");
		err = -EBUSY;
		goto err;
	}

	err = -ENOMEM;
	/* Allocate fuse_dev for hiprio and notification queues */
	for (i = 0; i < VQ_REQUEST; i++) {
		struct virtio_fs_vq *fsvq = &fs->vqs[i];

		fsvq->fud = fuse_dev_alloc();
		if (!fsvq->fud)
			goto err_free_fuse_devs;
	}

	init_req = fuse_request_alloc(0);
	if (!init_req)
		goto err_free_fuse_devs;
	__set_bit(FR_BACKGROUND, &init_req->flags);

	d.fiq_ops = &virtio_fs_fiq_ops;
	d.fiq_priv = fs;
	d.fudptr = (void **)&fs->vqs[VQ_REQUEST].fud;
	d.destroy = true; /* Send destroy request on unmount */
	if (d.dax_mode != FUSE_DAX_NEVER)
		d.dax_dev = fs->dax_dev;
	err = fuse_fill_super_common(sb, &d);
	if (err < 0)
		goto err_free_init_req;

	fc = fs->vqs[VQ_REQUEST].fud->fc;

	/* Tell FUSE to split requests that exceed the virtqueue's size */
	fc->max_pages_limit = min_t(unsigned int, fc->max_pages_limit,
				    virtqueue_size - FUSE_HEADER_OVERHEAD);

	/* TODO take fuse_mutex around this loop? */
	for (i = 0; i < fs->nvqs; i++) {
		struct virtio_fs_vq *fsvq = &fs->vqs[i];

		if (i == VQ_REQUEST)
			continue; /* already initialized */
		fuse_dev_install(fsvq->fud, fc);
		atomic_inc(&fc->dev_count);
	}

	/* Previous unmount will stop all queues. Start these again */
	virtio_fs_start_all_queues(fs);
	fuse_send_init(fc, init_req);
	mutex_unlock(&virtio_fs_mutex);
	return 0;

err_free_init_req:
	fuse_request_free(init_req);
err_free_fuse_devs:
	virtio_fs_free_devs(fs);
err:
	mutex_unlock(&virtio_fs_mutex);
	return err;
}

static void virtio_kill_sb(struct super_block *sb)
{
	struct fuse_conn *fc = get_fuse_conn_super(sb);
	struct virtio_fs *vfs;
	struct virtio_fs_vq *fsvq;

	/* If mount failed, we can still be called without any fc */
	if (!fc)
		return fuse_kill_sb_anon(sb);

	vfs = fc->iq.priv;
	fsvq = &vfs->vqs[VQ_HIPRIO];

	/* Stop dax worker. Soon evict_inodes() will be called which will
	 * free all memory ranges belonging to all inodes.
	 */
	if (IS_ENABLED(CONFIG_FUSE_DAX))
		fuse_dax_cancel_work(fc);

	/* Stop forget queue. Soon destroy will be sent */
	spin_lock(&fsvq->lock);
	fsvq->connected = false;
	spin_unlock(&fsvq->lock);
	virtio_fs_drain_all_queues(vfs);

	fuse_kill_sb_anon(sb);

	/* fuse_kill_sb_anon() must have sent destroy. Stop all queues
	 * and drain one more time and free fuse devices. Freeing fuse
	 * devices will drop their reference on fuse_conn and that in
	 * turn will drop its reference on virtio_fs object.
	 */
	virtio_fs_stop_all_queues(vfs);
	virtio_fs_drain_all_queues(vfs);
	virtio_fs_free_devs(vfs);
}

static struct dentry *virtio_fs_mount(struct file_system_type *fs_type,
				      int flags, const char *dev_name,
				      void *raw_data)
{
	struct virtio_fs_mount_info info = {
		.data = raw_data,
		.dev_name = dev_name,
	};
	return mount_nodev(fs_type, flags, &info, virtio_fs_fill_super);
}

static struct file_system_type virtio_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "virtiofs",
	.mount		= virtio_fs_mount,
	.kill_sb	= virtio_kill_sb,
};

/* Accept 'virtio_fs' as well to be compatible with old kangaroo runtime */
static struct file_system_type comp_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "virtio_fs",
	.mount		= virtio_fs_mount,
	.kill_sb	= virtio_kill_sb,
};
MODULE_ALIAS_FS("virtio_fs");
MODULE_ALIAS("virtio_fs");

static inline void register_as_virtio_fs(void)
{
	int err = register_filesystem(&comp_fs_type);

	if (err)
		pr_warn("virtiofs: Unable to register as virtio_fs (%d)\n",
			err);
}

static inline void unregister_as_virtio_fs(void)
{
	unregister_filesystem(&comp_fs_type);
}

static int __init virtio_fs_init(void)
{
	int ret;

	ret = register_virtio_driver(&virtio_fs_driver);
	if (ret < 0)
		return ret;

	register_as_virtio_fs();
	ret = register_filesystem(&virtio_fs_type);
	if (ret < 0) {
		unregister_as_virtio_fs();
		unregister_virtio_driver(&virtio_fs_driver);
		return ret;
	}

	return 0;
}
module_init(virtio_fs_init);

static void __exit virtio_fs_exit(void)
{
	unregister_as_virtio_fs();
	unregister_filesystem(&virtio_fs_type);
	unregister_virtio_driver(&virtio_fs_driver);
}
module_exit(virtio_fs_exit);

MODULE_AUTHOR("Stefan Hajnoczi <stefanha@redhat.com>");
MODULE_DESCRIPTION("Virtio Filesystem");
MODULE_LICENSE("GPL");
MODULE_ALIAS_FS(KBUILD_MODNAME);
MODULE_DEVICE_TABLE(virtio, id_table);
