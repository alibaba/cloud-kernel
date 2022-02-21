// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017-2018 HUAWEI, Inc.
 *             https://www.huawei.com/
 * Copyright (C) 2021, Alibaba Cloud
 */
#include "internal.h"
#include <linux/prefetch.h>
#include <linux/sched/mm.h>

#include <trace/events/erofs.h>

static void erofs_readendio(struct bio *bio)
{
	int i;
	struct bio_vec *bvec;
	const blk_status_t err = bio->bi_status;

	bio_for_each_segment_all(bvec, bio, i) {
		struct page *page = bvec->bv_page;

		/* page is already locked */
		DBG_BUGON(PageUptodate(page));

		if (err)
			SetPageError(page);
		else
			SetPageUptodate(page);

		unlock_page(page);
		/* page could be reclaimed now */
	}
	bio_put(bio);
}

static struct page *erofs_read_meta_page(struct super_block *sb, pgoff_t index,
					 struct erofs_buf *buf)
{
	struct address_space *mapping;
	struct page *page;

	buf->mapping = NULL;
	if (EROFS_SB(sb)->bootstrap) {
		struct inode	*inode = EROFS_SB(sb)->bootstrap->f_inode;
		unsigned int	nofs_flag;

		mapping = inode->i_mapping;
		nofs_flag = memalloc_nofs_save();
		if (IS_DAX(inode)) {
			page = mapping->a_ops->startpfn(mapping, index,
					&buf->iomap);
			if (!IS_ERR(page))
				buf->mapping = mapping;
		} else {
			page = read_cache_page(mapping, index,
					(filler_t *)mapping->a_ops->readpage,
					EROFS_SB(sb)->bootstrap);
		}
		memalloc_nofs_restore(nofs_flag);
	} else {
		mapping = sb->s_bdev->bd_inode->i_mapping;
		page = read_cache_page_gfp(mapping, index,
				mapping_gfp_constraint(mapping, ~__GFP_FS));
	}
	return page;
}

void erofs_unmap_metabuf(struct erofs_buf *buf)
{
	if (buf->kmap_type == EROFS_KMAP)
		kunmap(buf->page);
	else if (buf->kmap_type == EROFS_KMAP_ATOMIC)
		kunmap_atomic(buf->base);
	buf->base = NULL;
	buf->kmap_type = EROFS_NO_KMAP;
}

void erofs_put_metabuf(struct erofs_buf *buf)
{
	pgoff_t index;

	if (!buf->page)
		return;
	erofs_unmap_metabuf(buf);

	index = buf->page->index;
	put_page(buf->page);
	buf->page = NULL;

	if (buf->mapping) {
		buf->mapping->a_ops->endpfn(buf->mapping, index,
				&buf->iomap, 0);
		buf->mapping = NULL;
		memset(&buf->iomap, 0, sizeof(buf->iomap));
	}
}

void *erofs_read_metabuf(struct erofs_buf *buf, struct super_block *sb,
			erofs_blk_t blkaddr, enum erofs_kmap_type type)
{
	erofs_off_t offset = blknr_to_addr(blkaddr);
	pgoff_t index = offset >> PAGE_SHIFT;
	struct page *page = buf->page;

	if (!page || page->index != index) {
		erofs_put_metabuf(buf);
		page = erofs_read_meta_page(sb, index, buf);
		if (IS_ERR(page))
			return page;
		/* should already be PageUptodate, no need to lock page */
		buf->page = page;
	}
	if (buf->kmap_type == EROFS_NO_KMAP) {
		if (type == EROFS_KMAP)
			buf->base = kmap(page);
		else if (type == EROFS_KMAP_ATOMIC)
			buf->base = kmap_atomic(page);
		buf->kmap_type = type;
	} else if (buf->kmap_type != type) {
		DBG_BUGON(1);
		return ERR_PTR(-EFAULT);
	}
	if (type == EROFS_NO_KMAP)
		return NULL;
	return buf->base + (offset & ~PAGE_MASK);
}

static int erofs_map_blocks_flatmode(struct inode *inode,
				     struct erofs_map_blocks *map,
				     int flags)
{
	erofs_blk_t nblocks, lastblk;
	u64 offset = map->m_la;
	struct erofs_inode *vi = EROFS_I(inode);
	bool tailendpacking = (vi->datalayout == EROFS_INODE_FLAT_INLINE);

	nblocks = DIV_ROUND_UP(inode->i_size, EROFS_BLKSIZ);
	lastblk = nblocks - tailendpacking;

	/* there is no hole in flatmode */
	map->m_flags = EROFS_MAP_MAPPED;
	if (offset < blknr_to_addr(lastblk)) {
		map->m_pa = blknr_to_addr(vi->raw_blkaddr) + map->m_la;
		map->m_plen = blknr_to_addr(lastblk) - offset;
	} else if (tailendpacking) {
		/* 2 - inode inline B: inode, [xattrs], inline last blk... */
		struct erofs_sb_info *sbi = EROFS_SB(inode->i_sb);

		map->m_pa = iloc(sbi, vi->nid) + vi->inode_isize +
			vi->xattr_isize + erofs_blkoff(map->m_la);
		map->m_plen = inode->i_size - offset;

		/* inline data should be located in the same meta block */
		if (erofs_blkoff(map->m_pa) + map->m_plen > EROFS_BLKSIZ) {
			erofs_err(inode->i_sb,
				  "inline data cross block boundary @ nid %llu",
				  vi->nid);
			DBG_BUGON(1);
			return -EFSCORRUPTED;
		}
		map->m_flags |= EROFS_MAP_META;
	} else {
		erofs_err(inode->i_sb,
			  "internal error @ nid: %llu (size %llu), m_la 0x%llx",
			  vi->nid, inode->i_size, map->m_la);
		DBG_BUGON(1);
		return -EIO;
	}
	return 0;
}

int erofs_map_blocks(struct inode *inode,
		     struct erofs_map_blocks *map, int flags)
{
	struct super_block *sb = inode->i_sb;
	struct erofs_inode *vi = EROFS_I(inode);
	struct erofs_inode_chunk_index *idx;
	struct erofs_buf buf = __EROFS_BUF_INITIALIZER;
	u64 chunknr;
	unsigned int unit;
	erofs_off_t pos;
	void *kaddr;
	int err = 0;

	trace_erofs_map_blocks_enter(inode, map, flags);
	map->m_deviceid = 0;
	if (map->m_la >= inode->i_size) {
		/* leave out-of-bound access unmapped */
		map->m_flags = 0;
		map->m_plen = 0;
		goto out;
	}

	if (vi->datalayout != EROFS_INODE_CHUNK_BASED) {
		err = erofs_map_blocks_flatmode(inode, map, flags);
		goto out;
	}

	if (vi->chunkformat & EROFS_CHUNK_FORMAT_INDEXES)
		unit = sizeof(*idx);			/* chunk index */
	else
		unit = EROFS_BLOCK_MAP_ENTRY_SIZE;	/* block map */

	chunknr = map->m_la >> vi->chunkbits;
	pos = ALIGN(iloc(EROFS_SB(sb), vi->nid) + vi->inode_isize +
		    vi->xattr_isize, unit) + unit * chunknr;

	kaddr = erofs_read_metabuf(&buf, sb, erofs_blknr(pos), EROFS_KMAP);
	if (IS_ERR(kaddr)) {
		err = PTR_ERR(kaddr);
		goto out;
	}
	map->m_la = chunknr << vi->chunkbits;
	map->m_plen = min_t(erofs_off_t, 1UL << vi->chunkbits,
			    roundup(inode->i_size - map->m_la, EROFS_BLKSIZ));

	/* handle block map */
	if (!(vi->chunkformat & EROFS_CHUNK_FORMAT_INDEXES)) {
		__le32 *blkaddr = kaddr + erofs_blkoff(pos);

		if (le32_to_cpu(*blkaddr) == EROFS_NULL_ADDR) {
			map->m_flags = 0;
		} else {
			map->m_pa = blknr_to_addr(le32_to_cpu(*blkaddr));
			map->m_flags = EROFS_MAP_MAPPED;
		}
		goto out_unlock;
	}
	/* parse chunk indexes */
	idx = kaddr + erofs_blkoff(pos);
	switch (le32_to_cpu(idx->blkaddr)) {
	case EROFS_NULL_ADDR:
		map->m_flags = 0;
		break;
	default:
		map->m_deviceid = le16_to_cpu(idx->device_id) &
			EROFS_SB(sb)->device_id_mask;
		map->m_pa = blknr_to_addr(le32_to_cpu(idx->blkaddr));
		map->m_flags = EROFS_MAP_MAPPED;
		break;
	}
out_unlock:
	erofs_put_metabuf(&buf);
out:
	if (!err)
		map->m_llen = map->m_plen;
	trace_erofs_map_blocks_exit(inode, map, flags, 0);
	return err;
}

int erofs_map_dev(struct super_block *sb, struct erofs_map_dev *map)
{
	struct erofs_dev_context *devs = EROFS_SB(sb)->devs;
	struct erofs_device_info *dif;
	int id;

	/* primary device by default */
	map->m_bdev = sb->s_bdev;
	map->m_fp = EROFS_SB(sb)->bootstrap;

	if (map->m_deviceid) {
		down_read(&devs->rwsem);
		dif = idr_find(&devs->tree, map->m_deviceid - 1);
		if (!dif) {
			up_read(&devs->rwsem);
			return -ENODEV;
		}
		map->m_bdev = dif->bdev;
		map->m_fp = dif->blobfile;
		up_read(&devs->rwsem);
	} else if (devs->extra_devices) {
		down_read(&devs->rwsem);
		idr_for_each_entry(&devs->tree, dif, id) {
			erofs_off_t startoff, length;

			if (!dif->mapped_blkaddr)
				continue;
			startoff = blknr_to_addr(dif->mapped_blkaddr);
			length = blknr_to_addr(dif->blocks);

			if (map->m_pa >= startoff &&
			    map->m_pa < startoff + length) {
				map->m_pa -= startoff;
				map->m_bdev = dif->bdev;
				map->m_fp = dif->blobfile;
				break;
			}
		}
		up_read(&devs->rwsem);
	}
	return 0;
}

static inline struct bio *erofs_read_raw_page(struct bio *bio,
					      struct address_space *mapping,
					      struct page *page,
					      erofs_off_t *last_block,
					      unsigned int nblocks,
					      bool ra)
{
	struct inode *const inode = mapping->host;
	struct super_block *const sb = inode->i_sb;
	erofs_off_t current_block = (erofs_off_t)page->index;
	int err;

	DBG_BUGON(!nblocks);

	if (PageUptodate(page)) {
		err = 0;
		goto has_updated;
	}

	/* note that for readpage case, bio also equals to NULL */
	if (bio &&
	    /* not continuous */
	    *last_block + 1 != current_block) {
submit_bio_retry:
		submit_bio(bio);
		bio = NULL;
	}

	if (!bio) {
		struct erofs_map_blocks map = {
			.m_la = blknr_to_addr(current_block),
		};
		struct erofs_map_dev mdev;
		erofs_blk_t blknr;
		unsigned int blkoff;

		err = erofs_map_blocks(inode, &map, EROFS_GET_BLOCKS_RAW);
		if (err)
			goto err_out;

		mdev = (struct erofs_map_dev) {
			.m_deviceid = map.m_deviceid,
			.m_pa = map.m_pa,
		};
		err = erofs_map_dev(sb, &mdev);
		if (err)
			goto err_out;

		/* zero out the holed page */
		if (!(map.m_flags & EROFS_MAP_MAPPED)) {
			zero_user_segment(page, 0, PAGE_SIZE);
			SetPageUptodate(page);

			/* imply err = 0, see erofs_map_blocks */
			goto has_updated;
		}

		/* for RAW access mode, m_plen must be equal to m_llen */
		DBG_BUGON(map.m_plen != map.m_llen);

		blknr = erofs_blknr(mdev.m_pa);
		blkoff = erofs_blkoff(mdev.m_pa);

		/* deal with inline page */
		if (map.m_flags & EROFS_MAP_META) {
			void *vsrc, *vto;
			struct erofs_buf buf = __EROFS_BUF_INITIALIZER;

			DBG_BUGON(map.m_plen > PAGE_SIZE);

			vsrc = erofs_read_metabuf(&buf, inode->i_sb,
						  blknr, EROFS_KMAP_ATOMIC);
			if (IS_ERR(vsrc)) {
				err = PTR_ERR(vsrc);
				goto err_out;
			}
			vto = kmap_atomic(page);
			memcpy(vto, vsrc + blkoff, map.m_plen);
			memset(vto + map.m_plen, 0, PAGE_SIZE - map.m_plen);
			kunmap_atomic(vto);
			flush_dcache_page(page);
			SetPageUptodate(page);

			erofs_put_metabuf(&buf);
			/* imply err = 0, see erofs_map_blocks */
			goto has_updated;
		}

		/* pa must be block-aligned for raw reading */
		DBG_BUGON(erofs_blkoff(map.m_pa));

		/* max # of continuous pages */
		if (nblocks > DIV_ROUND_UP(map.m_plen, PAGE_SIZE))
			nblocks = DIV_ROUND_UP(map.m_plen, PAGE_SIZE);
		if (nblocks > BIO_MAX_PAGES)
			nblocks = BIO_MAX_PAGES;

		bio = bio_alloc(GFP_NOIO, nblocks);

		bio->bi_end_io = erofs_readendio;
		bio_set_dev(bio, mdev.m_bdev);
		bio->bi_iter.bi_sector = (sector_t)blknr <<
			LOG_SECTORS_PER_BLOCK;
		bio->bi_opf = REQ_OP_READ | (ra ? REQ_RAHEAD : 0);
	}

	err = bio_add_page(bio, page, PAGE_SIZE, 0);
	/* out of the extent or bio is full */
	if (err < PAGE_SIZE)
		goto submit_bio_retry;

	*last_block = current_block;

	/* shift in advance in case of it followed by too many gaps */
	if (bio->bi_iter.bi_size >= bio->bi_max_vecs * PAGE_SIZE) {
		/* err should reassign to 0 after submitting */
		err = 0;
		goto submit_bio_out;
	}

	return bio;

err_out:
	/* for sync reading, set page error immediately */
	if (!ra) {
		SetPageError(page);
		ClearPageUptodate(page);
	}
has_updated:
	unlock_page(page);

	/* if updated manually, continuous pages has a gap */
	if (bio)
submit_bio_out:
		submit_bio(bio);
	return err ? ERR_PTR(err) : NULL;
}

/*
 * since we dont have write or truncate flows, so no inode
 * locking needs to be held at the moment.
 */
static int erofs_raw_access_readpage(struct file *file, struct page *page)
{
	erofs_off_t last_block;
	struct bio *bio;

	trace_erofs_readpage(page, true);

	bio = erofs_read_raw_page(NULL, page->mapping,
				  page, &last_block, 1, false);

	if (IS_ERR(bio))
		return PTR_ERR(bio);

	DBG_BUGON(bio);	/* since we have only one bio -- must be NULL */
	return 0;
}

static int erofs_raw_access_readpages(struct file *filp,
				      struct address_space *mapping,
				      struct list_head *pages,
				      unsigned int nr_pages)
{
	erofs_off_t last_block;
	struct bio *bio = NULL;
	gfp_t gfp = readahead_gfp_mask(mapping);
	struct page *page = list_last_entry(pages, struct page, lru);

	trace_erofs_readpages(mapping->host, page, nr_pages, true);

	for (; nr_pages; --nr_pages) {
		page = list_entry(pages->prev, struct page, lru);

		prefetchw(&page->flags);
		list_del(&page->lru);

		if (!add_to_page_cache_lru(page, mapping, page->index, gfp)) {
			bio = erofs_read_raw_page(bio, mapping, page,
						  &last_block, nr_pages, true);

			/* all the page errors are ignored when readahead */
			if (IS_ERR(bio)) {
				pr_err("%s, readahead error at page %lu of nid %llu\n",
				       __func__, page->index,
				       EROFS_I(mapping->host)->nid);

				bio = NULL;
			}
		}

		/* pages could still be locked */
		put_page(page);
	}
	DBG_BUGON(!list_empty(pages));

	/* the rare case (end in gaps) */
	if (bio)
		submit_bio(bio);
	return 0;
}

static sector_t erofs_bmap(struct address_space *mapping, sector_t block)
{
	struct inode *inode = mapping->host;
	struct erofs_map_blocks map = {
		.m_la = blknr_to_addr(block),
	};

	if (EROFS_I(inode)->datalayout == EROFS_INODE_FLAT_INLINE) {
		erofs_blk_t blks = i_size_read(inode) >> LOG_BLOCK_SIZE;

		if (block >> LOG_SECTORS_PER_BLOCK >= blks)
			return 0;
	}

	if (!erofs_map_blocks(inode, &map, EROFS_GET_BLOCKS_RAW))
		return erofs_blknr(map.m_pa);

	return 0;
}

/* for uncompressed (aligned) files and raw access for other files */
const struct address_space_operations erofs_raw_access_aops = {
	.readpage = erofs_raw_access_readpage,
	.readpages = erofs_raw_access_readpages,
	.bmap = erofs_bmap,
	.direct_IO = noop_direct_IO,
};
