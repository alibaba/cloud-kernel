/*
 * Zoned block device handling
 *
 * Copyright (c) 2015, Hannes Reinecke
 * Copyright (c) 2015, SUSE Linux GmbH
 *
 * Copyright (c) 2016, Damien Le Moal
 * Copyright (c) 2016, Western Digital
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/sched/mm.h>

#include "blk.h"

#define ZONE_COND_NAME(name) [BLK_ZONE_COND_##name] = #name
static const char *const zone_cond_name[] = {
	ZONE_COND_NAME(NOT_WP),
	ZONE_COND_NAME(EMPTY),
	ZONE_COND_NAME(IMP_OPEN),
	ZONE_COND_NAME(EXP_OPEN),
	ZONE_COND_NAME(CLOSED),
	ZONE_COND_NAME(READONLY),
	ZONE_COND_NAME(FULL),
	ZONE_COND_NAME(OFFLINE),
};
#undef ZONE_COND_NAME

/**
 * blk_zone_cond_str - Return string XXX in BLK_ZONE_COND_XXX.
 * @zone_cond: BLK_ZONE_COND_XXX.
 *
 * Description: Centralize block layer function to convert BLK_ZONE_COND_XXX
 * into string format. Useful in the debugging and tracing zone conditions. For
 * invalid BLK_ZONE_COND_XXX it returns string "UNKNOWN".
 */
const char *blk_zone_cond_str(enum blk_zone_cond zone_cond)
{
	static const char *zone_cond_str = "UNKNOWN";

	if (zone_cond < ARRAY_SIZE(zone_cond_name) && zone_cond_name[zone_cond])
		zone_cond_str = zone_cond_name[zone_cond];

	return zone_cond_str;
}
EXPORT_SYMBOL_GPL(blk_zone_cond_str);

/*
 * Return true if a request is a write requests that needs zone write locking.
 */
bool blk_req_needs_zone_write_lock(struct request *rq)
{
	if (!rq->q->seq_zones_wlock)
		return false;

	if (blk_rq_is_passthrough(rq))
		return false;

	switch (req_op(rq)) {
	case REQ_OP_WRITE_ZEROES:
	case REQ_OP_WRITE_SAME:
	case REQ_OP_WRITE:
		return blk_rq_zone_is_seq(rq);
	default:
		return false;
	}
}
EXPORT_SYMBOL_GPL(blk_req_needs_zone_write_lock);

void __blk_req_zone_write_lock(struct request *rq)
{
	if (WARN_ON_ONCE(test_and_set_bit(blk_rq_zone_no(rq),
					  rq->q->seq_zones_wlock)))
		return;

	WARN_ON_ONCE(rq->rq_flags & RQF_ZONE_WRITE_LOCKED);
	rq->rq_flags |= RQF_ZONE_WRITE_LOCKED;
}
EXPORT_SYMBOL_GPL(__blk_req_zone_write_lock);

void __blk_req_zone_write_unlock(struct request *rq)
{
	rq->rq_flags &= ~RQF_ZONE_WRITE_LOCKED;
	if (rq->q->seq_zones_wlock)
		WARN_ON_ONCE(!test_and_clear_bit(blk_rq_zone_no(rq),
						 rq->q->seq_zones_wlock));
}
EXPORT_SYMBOL_GPL(__blk_req_zone_write_unlock);

static inline unsigned int __blkdev_nr_zones(struct request_queue *q,
					     sector_t nr_sectors)
{
	sector_t zone_sectors = blk_queue_zone_sectors(q);

	return (nr_sectors + zone_sectors - 1) >> ilog2(zone_sectors);
}

/**
 * blkdev_nr_zones - Get number of zones
 * @bdev:	Target block device
 *
 * Description:
 *    Return the total number of zones of a zoned block device.
 *    For a regular block device, the number of zones is always 0.
 */
unsigned int blkdev_nr_zones(struct block_device *bdev)
{
	struct request_queue *q = bdev_get_queue(bdev);

	if (!blk_queue_is_zoned(q))
		return 0;

	return __blkdev_nr_zones(q, get_capacity(bdev->bd_disk));
}
EXPORT_SYMBOL_GPL(blkdev_nr_zones);

/**
 * blkdev_report_zones - Get zones information
 * @bdev:	Target block device
 * @sector:	Sector from which to report zones
 * @nr_zones:	Maximum number of zones to report
 * @cb:		Callback function called for each reported zone
 * @data:	Private data for the callback
 *
 * Description:
 *    Get zone information starting from the zone containing @sector for at most
 *    @nr_zones, and call @cb for each zone reported by the device.
 *    To report all zones in a device starting from @sector, the BLK_ALL_ZONES
 *    constant can be passed to @nr_zones.
 *    Returns the number of zones reported by the device, or a negative errno
 *    value in case of failure.
 *
 *    Note: The caller must use memalloc_noXX_save/restore() calls to control
 *    memory allocations done within this function.
 */
int blkdev_report_zones(struct block_device *bdev, sector_t sector,
			unsigned int nr_zones, report_zones_cb cb, void *data)
{
	struct gendisk *disk = bdev->bd_disk;
	sector_t capacity = get_capacity(disk);

	if (!blk_queue_is_zoned(bdev_get_queue(bdev)) ||
	    WARN_ON_ONCE(!disk->fops->report_zones))
		return -EOPNOTSUPP;

	if (!nr_zones || sector >= capacity)
		return 0;

	return disk->fops->report_zones(disk, sector, nr_zones, cb, data);
}
EXPORT_SYMBOL_GPL(blkdev_report_zones);

static inline bool blkdev_allow_reset_all_zones(struct block_device *bdev,
						sector_t sector,
						sector_t nr_sectors)
{
	if (!blk_queue_zone_resetall(bdev_get_queue(bdev)))
		return false;

	/*
	 * REQ_OP_ZONE_RESET_ALL can be executed only if the number of sectors
	 * of the applicable zone range is the entire disk.
	 */
	return !sector && nr_sectors == get_capacity(bdev->bd_disk);
}

/**
 * blkdev_zone_mgmt - Execute a zone management operation on a range of zones
 * @bdev:	Target block device
 * @op:		Operation to be performed on the zones
 * @sector:	Start sector of the first zone to operate on
 * @nr_sectors:	Number of sectors, should be at least the length of one zone and
 *		must be zone size aligned.
 * @gfp_mask:	Memory allocation flags (for bio_alloc)
 *
 * Description:
 *    Perform the specified operation on the range of zones specified by
 *    @sector..@sector+@nr_sectors. Specifying the entire disk sector range
 *    is valid, but the specified range should not contain conventional zones.
 *    The operation to execute on each zone can be a zone reset, open, close
 *    or finish request.
 */
int blkdev_zone_mgmt(struct block_device *bdev, enum req_opf op,
		     sector_t sector, sector_t nr_sectors,
		     gfp_t gfp_mask)
{
	struct request_queue *q = bdev_get_queue(bdev);
	sector_t zone_sectors = blk_queue_zone_sectors(q);
	sector_t capacity = get_capacity(bdev->bd_disk);
	sector_t end_sector = sector + nr_sectors;
	struct bio *bio = NULL;
	int ret;

	if (!blk_queue_is_zoned(q))
		return -EOPNOTSUPP;

	if (bdev_read_only(bdev))
		return -EPERM;

	if (!op_is_zone_mgmt(op))
		return -EOPNOTSUPP;

	if (end_sector <= sector || end_sector > capacity)
		/* Out of range */
		return -EINVAL;

	/* Check alignment (handle eventual smaller last zone) */
	if (sector & (zone_sectors - 1))
		return -EINVAL;

	if ((nr_sectors & (zone_sectors - 1)) && end_sector != capacity)
		return -EINVAL;

	while (sector < end_sector) {
		bio = blk_next_bio(bio, 0, gfp_mask);
		bio_set_dev(bio, bdev);

		/*
		 * Special case for the zone reset operation that reset all
		 * zones, this is useful for applications like mkfs.
		 */
		if (op == REQ_OP_ZONE_RESET &&
		    blkdev_allow_reset_all_zones(bdev, sector, nr_sectors)) {
			bio->bi_opf = REQ_OP_ZONE_RESET_ALL;
			break;
		}

		bio->bi_opf = op;
		bio->bi_iter.bi_sector = sector;
		sector += zone_sectors;

		/* This may take a while, so be nice to others */
		cond_resched();
	}

	ret = submit_bio_wait(bio);
	bio_put(bio);

	return ret;
}
EXPORT_SYMBOL_GPL(blkdev_zone_mgmt);

struct zone_report_args {
	struct blk_zone __user *zones;
};

static int blkdev_copy_zone_to_user(struct blk_zone *zone, unsigned int idx,
				    void *data)
{
	struct zone_report_args *args = data;

	if (copy_to_user(&args->zones[idx], zone, sizeof(struct blk_zone)))
		return -EFAULT;
	return 0;
}

/*
 * BLKREPORTZONE ioctl processing.
 * Called from blkdev_ioctl.
 */
int blkdev_report_zones_ioctl(struct block_device *bdev, fmode_t mode,
			      unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct zone_report_args args;
	struct request_queue *q;
	struct blk_zone_report rep;
	int ret;

	if (!argp)
		return -EINVAL;

	q = bdev_get_queue(bdev);
	if (!q)
		return -ENXIO;

	if (!blk_queue_is_zoned(q))
		return -ENOTTY;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	if (copy_from_user(&rep, argp, sizeof(struct blk_zone_report)))
		return -EFAULT;

	if (!rep.nr_zones)
		return -EINVAL;

	args.zones = argp + sizeof(struct blk_zone_report);
	ret = blkdev_report_zones(bdev, rep.sector, rep.nr_zones,
				  blkdev_copy_zone_to_user, &args);
	if (ret < 0)
		return ret;

	rep.nr_zones = ret;
	if (copy_to_user(argp, &rep, sizeof(struct blk_zone_report)))
		return -EFAULT;
	return 0;
}

/*
 * BLKRESETZONE, BLKOPENZONE, BLKCLOSEZONE and BLKFINISHZONE ioctl processing.
 * Called from blkdev_ioctl.
 */
int blkdev_zone_mgmt_ioctl(struct block_device *bdev, fmode_t mode,
			   unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct request_queue *q;
	struct blk_zone_range zrange;
	enum req_opf op;

	if (!argp)
		return -EINVAL;

	q = bdev_get_queue(bdev);
	if (!q)
		return -ENXIO;

	if (!blk_queue_is_zoned(q))
		return -ENOTTY;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	if (!(mode & FMODE_WRITE))
		return -EBADF;

	if (copy_from_user(&zrange, argp, sizeof(struct blk_zone_range)))
		return -EFAULT;

	switch (cmd) {
	case BLKRESETZONE:
		op = REQ_OP_ZONE_RESET;
		break;
	case BLKOPENZONE:
		op = REQ_OP_ZONE_OPEN;
		break;
	case BLKCLOSEZONE:
		op = REQ_OP_ZONE_CLOSE;
		break;
	case BLKFINISHZONE:
		op = REQ_OP_ZONE_FINISH;
		break;
	default:
		return -ENOTTY;
	}

	return blkdev_zone_mgmt(bdev, op, zrange.sector, zrange.nr_sectors,
				GFP_KERNEL);
}

static inline unsigned long *blk_alloc_zone_bitmap(int node,
						   unsigned int nr_zones)
{
	return kcalloc_node(BITS_TO_LONGS(nr_zones), sizeof(unsigned long),
			    GFP_NOIO, node);
}

void blk_queue_free_zone_bitmaps(struct request_queue *q)
{
	kfree(q->seq_zones_bitmap);
	q->seq_zones_bitmap = NULL;
	kfree(q->seq_zones_wlock);
	q->seq_zones_wlock = NULL;
}

struct blk_revalidate_zone_args {
	struct gendisk	*disk;
	unsigned long	*seq_zones_bitmap;
	unsigned long	*seq_zones_wlock;
	sector_t	sector;
};

/*
 * Helper function to check the validity of zones of a zoned block device.
 */
static int blk_revalidate_zone_cb(struct blk_zone *zone, unsigned int idx,
				  void *data)
{
	struct blk_revalidate_zone_args *args = data;
	struct gendisk *disk = args->disk;
	struct request_queue *q = disk->queue;
	sector_t zone_sectors = blk_queue_zone_sectors(q);
	sector_t capacity = get_capacity(disk);

	/*
	 * All zones must have the same size, with the exception on an eventual
	 * smaller last zone.
	 */
	if (zone->start + zone_sectors < capacity &&
	    zone->len != zone_sectors) {
		pr_warn("%s: Invalid zoned device with non constant zone size\n",
			disk->disk_name);
		return -ENODEV;
	}

	if (zone->start + zone->len >= capacity &&
	    zone->len > zone_sectors) {
		pr_warn("%s: Invalid zoned device with larger last zone size\n",
			disk->disk_name);
		return -ENODEV;
	}

	/* Check for holes in the zone report */
	if (zone->start != args->sector) {
		pr_warn("%s: Zone gap at sectors %llu..%llu\n",
			disk->disk_name, (unsigned long long)args->sector, zone->start);
		return -ENODEV;
	}

	/* Check zone type */
	switch (zone->type) {
	case BLK_ZONE_TYPE_CONVENTIONAL:
	case BLK_ZONE_TYPE_SEQWRITE_REQ:
	case BLK_ZONE_TYPE_SEQWRITE_PREF:
		break;
	default:
		pr_warn("%s: Invalid zone type 0x%x at sectors %llu\n",
			disk->disk_name, (int)zone->type, zone->start);
		return -ENODEV;
	}

	if (zone->type != BLK_ZONE_TYPE_CONVENTIONAL)
		set_bit(idx, args->seq_zones_bitmap);

	args->sector += zone->len;
	return 0;
}

static int blk_update_zone_info(struct gendisk *disk, unsigned int nr_zones,
				struct blk_revalidate_zone_args *args)
{
	/*
	 * Ensure that all memory allocations in this context are done as
	 * if GFP_NOIO was specified.
	 */
	unsigned int noio_flag = memalloc_noio_save();
	struct request_queue *q = disk->queue;
	int ret;

	args->seq_zones_wlock = blk_alloc_zone_bitmap(q->node, nr_zones);
	if (!args->seq_zones_wlock)
		return -ENOMEM;
	args->seq_zones_bitmap = blk_alloc_zone_bitmap(q->node, nr_zones);
	if (!args->seq_zones_bitmap)
		return -ENOMEM;

	ret = disk->fops->report_zones(disk, 0, nr_zones,
				       blk_revalidate_zone_cb, args);
	memalloc_noio_restore(noio_flag);
	return ret;
}

/**
 * blk_revalidate_disk_zones - (re)allocate and initialize zone bitmaps
 * @disk:	Target disk
 *
 * Helper function for low-level device drivers to (re) allocate and initialize
 * a disk request queue zone bitmaps. This functions should normally be called
 * within the disk ->revalidate method. For BIO based queues, no zone bitmap
 * is allocated.
 */
int blk_revalidate_disk_zones(struct gendisk *disk)
{
	struct request_queue *q = disk->queue;
	unsigned int nr_zones = __blkdev_nr_zones(q, get_capacity(disk));
	struct blk_revalidate_zone_args args = { .disk = disk };
	int ret = 0;

	if (WARN_ON_ONCE(!blk_queue_is_zoned(q)))
		return -EIO;

	/*
	 * BIO based queues do not use a scheduler so only q->nr_zones
	 * needs to be updated so that the sysfs exposed value is correct.
	 */
	if (!queue_is_rq_based(q)) {
		q->nr_zones = nr_zones;
		return 0;
	}

	if (nr_zones)
		ret = blk_update_zone_info(disk, nr_zones, &args);

	/*
	 * Install the new bitmaps, making sure the queue is stopped and
	 * all I/Os are completed (i.e. a scheduler is not referencing the
	 * bitmaps).
	 */
	blk_mq_freeze_queue(q);
	if (ret >= 0) {
		q->nr_zones = nr_zones;
		swap(q->seq_zones_wlock, args.seq_zones_wlock);
		swap(q->seq_zones_bitmap, args.seq_zones_bitmap);
		ret = 0;
	} else {
		pr_warn("%s: failed to revalidate zones\n", disk->disk_name);
		blk_queue_free_zone_bitmaps(q);
	}
	blk_mq_unfreeze_queue(q);

	kfree(args.seq_zones_wlock);
	kfree(args.seq_zones_bitmap);
	return ret;
}
EXPORT_SYMBOL_GPL(blk_revalidate_disk_zones);
