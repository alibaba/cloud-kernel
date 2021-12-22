// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017-2018 HUAWEI, Inc.
 *             https://www.huawei.com/
 * Copyright (C) 2021, Alibaba Cloud
 */
#include "xattr.h"
#include <linux/uio.h>
#include <trace/events/erofs.h>

const struct file_operations rafs_v6_file_ro_fops;
const struct address_space_operations rafs_v6_aops;

/*
 * if inode is successfully read, return its inode page (or sometimes
 * the inode payload page if it's an extended inode) in order to fill
 * inline data if possible.
 */
static struct page *erofs_read_inode(struct inode *inode,
				     unsigned int *ofs)
{
	struct super_block *sb = inode->i_sb;
	struct erofs_sb_info *sbi = EROFS_SB(sb);
	struct erofs_inode *vi = EROFS_I(inode);
	const erofs_off_t inode_loc = iloc(sbi, vi->nid);

	erofs_blk_t blkaddr, nblks = 0;
	struct page *page;
	struct erofs_inode_compact *dic;
	struct erofs_inode_extended *die, *copied = NULL;
	unsigned int ifmt;
	int err;

	blkaddr = erofs_blknr(inode_loc);
	*ofs = erofs_blkoff(inode_loc);

	erofs_dbg("%s, reading inode nid %llu at %u of blkaddr %u",
		  __func__, vi->nid, *ofs, blkaddr);

	page = erofs_get_meta_page(sb, blkaddr);
	if (IS_ERR(page)) {
		erofs_err(sb, "failed to get inode (nid: %llu) page, err %ld",
			  vi->nid, PTR_ERR(page));
		return page;
	}

	dic = page_address(page) + *ofs;
	ifmt = le16_to_cpu(dic->i_format);

	if (ifmt & ~EROFS_I_ALL) {
		erofs_err(inode->i_sb, "unsupported i_format %u of nid %llu",
			  ifmt, vi->nid);
		err = -EOPNOTSUPP;
		goto err_out;
	}

	vi->datalayout = erofs_inode_datalayout(ifmt);
	if (vi->datalayout >= EROFS_INODE_DATALAYOUT_MAX) {
		erofs_err(inode->i_sb, "unsupported datalayout %u of nid %llu",
			  vi->datalayout, vi->nid);
		err = -EOPNOTSUPP;
		goto err_out;
	}

	switch (erofs_inode_version(ifmt)) {
	case EROFS_INODE_LAYOUT_EXTENDED:
		vi->inode_isize = sizeof(struct erofs_inode_extended);
		/* check if the inode acrosses page boundary */
		if (*ofs + vi->inode_isize <= PAGE_SIZE) {
			*ofs += vi->inode_isize;
			die = (struct erofs_inode_extended *)dic;
		} else {
			const unsigned int gotten = PAGE_SIZE - *ofs;

			copied = kmalloc(vi->inode_isize, GFP_NOFS);
			if (!copied) {
				err = -ENOMEM;
				goto err_out;
			}
			memcpy(copied, dic, gotten);
			unlock_page(page);
			put_page(page);

			page = erofs_get_meta_page(sb, blkaddr + 1);
			if (IS_ERR(page)) {
				erofs_err(sb, "failed to get inode payload page (nid: %llu), err %ld",
					  vi->nid, PTR_ERR(page));
				kfree(copied);
				return page;
			}
			*ofs = vi->inode_isize - gotten;
			memcpy((u8 *)copied + gotten, page_address(page), *ofs);
			die = copied;
		}
		vi->xattr_isize = erofs_xattr_ibody_size(die->i_xattr_icount);

		inode->i_mode = le16_to_cpu(die->i_mode);
		switch (inode->i_mode & S_IFMT) {
		case S_IFREG:
		case S_IFDIR:
		case S_IFLNK:
			vi->raw_blkaddr = le32_to_cpu(die->i_u.raw_blkaddr);
			break;
		case S_IFCHR:
		case S_IFBLK:
			inode->i_rdev =
				new_decode_dev(le32_to_cpu(die->i_u.rdev));
			break;
		case S_IFIFO:
		case S_IFSOCK:
			inode->i_rdev = 0;
			break;
		default:
			goto bogusimode;
		}
		i_uid_write(inode, le32_to_cpu(die->i_uid));
		i_gid_write(inode, le32_to_cpu(die->i_gid));
		set_nlink(inode, le32_to_cpu(die->i_nlink));

		/* extended inode has its own timestamp */
		inode->i_ctime.tv_sec = le64_to_cpu(die->i_ctime);
		inode->i_ctime.tv_nsec = le32_to_cpu(die->i_ctime_nsec);

		inode->i_size = le64_to_cpu(die->i_size);

		/* total blocks for compressed files */
		if (erofs_inode_is_data_compressed(vi->datalayout))
			nblks = le32_to_cpu(die->i_u.compressed_blocks);
		else if (vi->datalayout == EROFS_INODE_CHUNK_BASED)
			/* fill chunked inode summary info */
			vi->chunkformat = le16_to_cpu(die->i_u.c.format);
		kfree(copied);
		copied = NULL;
		break;
	case EROFS_INODE_LAYOUT_COMPACT:
		vi->inode_isize = sizeof(struct erofs_inode_compact);
		*ofs += vi->inode_isize;
		vi->xattr_isize = erofs_xattr_ibody_size(dic->i_xattr_icount);

		inode->i_mode = le16_to_cpu(dic->i_mode);
		switch (inode->i_mode & S_IFMT) {
		case S_IFREG:
		case S_IFDIR:
		case S_IFLNK:
			vi->raw_blkaddr = le32_to_cpu(dic->i_u.raw_blkaddr);
			break;
		case S_IFCHR:
		case S_IFBLK:
			inode->i_rdev =
				new_decode_dev(le32_to_cpu(dic->i_u.rdev));
			break;
		case S_IFIFO:
		case S_IFSOCK:
			inode->i_rdev = 0;
			break;
		default:
			goto bogusimode;
		}
		i_uid_write(inode, le16_to_cpu(dic->i_uid));
		i_gid_write(inode, le16_to_cpu(dic->i_gid));
		set_nlink(inode, le16_to_cpu(dic->i_nlink));

		/* use build time for compact inodes */
		inode->i_ctime.tv_sec = sbi->build_time;
		inode->i_ctime.tv_nsec = sbi->build_time_nsec;

		inode->i_size = le32_to_cpu(dic->i_size);
		if (erofs_inode_is_data_compressed(vi->datalayout))
			nblks = le32_to_cpu(dic->i_u.compressed_blocks);
		else if (vi->datalayout == EROFS_INODE_CHUNK_BASED)
			vi->chunkformat = le16_to_cpu(dic->i_u.c.format);
		break;
	default:
		erofs_err(inode->i_sb,
			  "unsupported on-disk inode version %u of nid %llu",
			  erofs_inode_version(ifmt), vi->nid);
		err = -EOPNOTSUPP;
		goto err_out;
	}

	if (vi->datalayout == EROFS_INODE_CHUNK_BASED) {
		if (!(vi->chunkformat & EROFS_CHUNK_FORMAT_ALL)) {
			erofs_err(inode->i_sb,
				  "unsupported chunk format %x of nid %llu",
				  vi->chunkformat, vi->nid);
			err = -EOPNOTSUPP;
			goto err_out;
		}
		vi->chunkbits = LOG_BLOCK_SIZE +
			(vi->chunkformat & EROFS_CHUNK_FORMAT_BLKBITS_MASK);
	}
	inode->i_mtime.tv_sec = inode->i_ctime.tv_sec;
	inode->i_atime.tv_sec = inode->i_ctime.tv_sec;
	inode->i_mtime.tv_nsec = inode->i_ctime.tv_nsec;
	inode->i_atime.tv_nsec = inode->i_ctime.tv_nsec;

	if (!nblks)
		/* measure inode.i_blocks as generic filesystems */
		inode->i_blocks = roundup(inode->i_size, EROFS_BLKSIZ) >> 9;
	else
		inode->i_blocks = nblks << LOG_SECTORS_PER_BLOCK;
	return page;

bogusimode:
	erofs_err(inode->i_sb, "bogus i_mode (%o) @ nid %llu",
		  inode->i_mode, vi->nid);
	err = -EFSCORRUPTED;
err_out:
	DBG_BUGON(1);
	kfree(copied);
	unlock_page(page);
	put_page(page);
	return ERR_PTR(err);
}

static int erofs_fill_symlink(struct inode *inode, void *data,
			      unsigned int m_pofs)
{
	struct erofs_inode *vi = EROFS_I(inode);
	char *lnk;

	/* if it cannot be handled with fast symlink scheme */
	if (vi->datalayout != EROFS_INODE_FLAT_INLINE ||
	    inode->i_size >= PAGE_SIZE) {
		inode->i_op = &erofs_symlink_iops;
		return 0;
	}

	lnk = kmalloc(inode->i_size + 1, GFP_KERNEL);
	if (!lnk)
		return -ENOMEM;

	m_pofs += vi->xattr_isize;
	/* inline symlink data shouldn't cross page boundary as well */
	if (m_pofs + inode->i_size > PAGE_SIZE) {
		kfree(lnk);
		erofs_err(inode->i_sb,
			  "inline data cross block boundary @ nid %llu",
			  vi->nid);
		DBG_BUGON(1);
		return -EFSCORRUPTED;
	}

	memcpy(lnk, data + m_pofs, inode->i_size);
	lnk[inode->i_size] = '\0';

	inode->i_link = lnk;
	inode->i_op = &erofs_fast_symlink_iops;
	return 0;
}

static int erofs_fill_inode(struct inode *inode, int isdir)
{
	struct erofs_inode *vi = EROFS_I(inode);
	struct page *page;
	unsigned int ofs;
	int err = 0;

	trace_erofs_fill_inode(inode, isdir);

	/* read inode base data from disk */
	page = erofs_read_inode(inode, &ofs);
	if (IS_ERR(page))
		return PTR_ERR(page);

	/* setup the new inode */
	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &erofs_generic_iops;
		if (inode->i_sb->s_bdev)
			inode->i_fop = &generic_ro_fops;
		else
			inode->i_fop = &rafs_v6_file_ro_fops;
		break;
	case S_IFDIR:
		inode->i_op = &erofs_dir_iops;
		inode->i_fop = &erofs_dir_fops;
		break;
	case S_IFLNK:
		err = erofs_fill_symlink(inode, page_address(page), ofs);
		if (err)
			goto out_unlock;
		inode_nohighmem(inode);
		break;
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
		inode->i_op = &erofs_generic_iops;
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
		goto out_unlock;
	default:
		err = -EFSCORRUPTED;
		goto out_unlock;
	}

	if (erofs_inode_is_data_compressed(vi->datalayout)) {
		err = z_erofs_fill_inode(inode);
		goto out_unlock;
	}
	if (inode->i_sb->s_bdev) {
		inode->i_mapping->a_ops = &erofs_raw_access_aops;
	} else if (!S_ISREG(inode->i_mode)) {
		inode_nohighmem(inode);
		inode->i_mapping->a_ops = &rafs_v6_aops;
	}
out_unlock:
	unlock_page(page);
	put_page(page);
	return err;
}

/*
 * erofs nid is 64bits, but i_ino is 'unsigned long', therefore
 * we should do more for 32-bit platform to find the right inode.
 */
static int erofs_ilookup_test_actor(struct inode *inode, void *opaque)
{
	const erofs_nid_t nid = *(erofs_nid_t *)opaque;

	return EROFS_I(inode)->nid == nid;
}

static int erofs_iget_set_actor(struct inode *inode, void *opaque)
{
	const erofs_nid_t nid = *(erofs_nid_t *)opaque;

	inode->i_ino = erofs_inode_hash(nid);
	return 0;
}

static inline struct inode *erofs_iget_locked(struct super_block *sb,
					      erofs_nid_t nid)
{
	const unsigned long hashval = erofs_inode_hash(nid);

	return iget5_locked(sb, hashval, erofs_ilookup_test_actor,
		erofs_iget_set_actor, &nid);
}

struct inode *erofs_iget(struct super_block *sb,
			 erofs_nid_t nid,
			 bool isdir)
{
	struct inode *inode = erofs_iget_locked(sb, nid);

	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (inode->i_state & I_NEW) {
		int err;
		struct erofs_inode *vi = EROFS_I(inode);

		vi->nid = nid;

		err = erofs_fill_inode(inode, isdir);
		if (!err)
			unlock_new_inode(inode);
		else {
			iget_failed(inode);
			inode = ERR_PTR(err);
		}
	}
	return inode;
}

int erofs_getattr(const struct path *path, struct kstat *stat,
		  u32 request_mask, unsigned int query_flags)
{
	struct inode *const inode = d_inode(path->dentry);

	if (erofs_inode_is_data_compressed(EROFS_I(inode)->datalayout))
		stat->attributes |= STATX_ATTR_COMPRESSED;

	stat->attributes |= STATX_ATTR_IMMUTABLE;
	stat->attributes_mask |= (STATX_ATTR_COMPRESSED |
				  STATX_ATTR_IMMUTABLE);

	generic_fillattr(inode, stat);
	return 0;
}

const struct inode_operations erofs_generic_iops = {
	.getattr = erofs_getattr,
	.listxattr = erofs_listxattr,
	.get_acl = erofs_get_acl,
};

const struct inode_operations erofs_symlink_iops = {
	.get_link = page_get_link,
	.getattr = erofs_getattr,
	.listxattr = erofs_listxattr,
	.get_acl = erofs_get_acl,
};

const struct inode_operations erofs_fast_symlink_iops = {
	.get_link = simple_get_link,
	.getattr = erofs_getattr,
	.listxattr = erofs_listxattr,
	.get_acl = erofs_get_acl,
};

static ssize_t rafs_v6_read_chunk(struct super_block *sb,
				  struct iov_iter *to, u64 off, u64 size,
				  unsigned int device_id)
{
	struct iov_iter titer;
	ssize_t read = 0;
	struct erofs_map_dev mdev = {
		.m_deviceid = device_id,
		.m_pa = off,
	};
	int err;

	err = erofs_map_dev(sb, &mdev);
	if (err)
		return err;
	off = mdev.m_pa;
	do {
		ssize_t ret;

		if (iov_iter_is_pipe(to)) {
			iov_iter_pipe(&titer, READ, to->pipe, size - read);

			ret = vfs_iter_read(mdev.m_fp, &titer, &off, 0);
			pr_debug("pipe ret %ld off %llu size %llu read %ld\n",
				 ret, off, size, read);
			if (ret <= 0) {
				pr_err("%s: failed to read blob ret %ld\n", __func__, ret);
				return ret;
			}
		} else {
			struct iovec iovec = iov_iter_iovec(to);

			if (iovec.iov_len > size - read)
				iovec.iov_len = size - read;

			pr_debug("%s: off %llu size %llu iov_len %lu blob_index %u\n",
				 __func__, off, size, iovec.iov_len, device_id);

			/* TODO async */
			iov_iter_init(&titer, READ, &iovec, 1, iovec.iov_len);
			ret = vfs_iter_read(mdev.m_fp, &titer, &off, 0);
			if (ret <= 0) {
				pr_err("%s: failed to read blob ret %ld\n", __func__, ret);
				return ret;
			} else if (ret < iovec.iov_len) {
				return read;
			}
		}
		iov_iter_advance(to, ret);
		read += ret;
	} while (read < size);

	return read;
}

static ssize_t rafs_v6_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct erofs_map_blocks map = { 0 };
	ssize_t bytes = 0;
	u64 total = min_t(u64, iov_iter_count(to),
			  inode->i_size - iocb->ki_pos);

	while (total) {
		erofs_off_t pos = iocb->ki_pos;
		u64 delta, size;
		ssize_t read;

		if (map.m_la < pos || map.m_la + map.m_llen >= pos) {
			int err;

			map.m_la = pos;
			err = erofs_map_blocks(inode, &map, EROFS_GET_BLOCKS_RAW);
			if (err)
				return err;
			if (map.m_la >= inode->i_size)
				break;
		}
		delta = pos - map.m_la;
		size = min_t(u64, map.m_llen - delta, total);
		pr_debug("inode i_size %llu pa %llu delta %llu size %llu",
			 inode->i_size, map.m_pa, delta, size);
		read = rafs_v6_read_chunk(inode->i_sb, to, map.m_pa + delta,
					  size, map.m_deviceid);
		if (read <= 0 || read < size) {
			erofs_err(inode->i_sb,
				  "short read %ld pos %llu size %llu @ nid %llu",
				  read, pos, size, EROFS_I(inode)->nid);
			return read < 0 ? read : -EIO;
		}
		iocb->ki_pos += read;
		bytes += read;
		total -= read;
	}
	return bytes;
}

static vm_fault_t rafs_v6_filemap_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct inode *inode = file_inode(vma->vm_file);
	pgoff_t npages, orig_pgoff = vmf->pgoff;
	erofs_off_t pos;
	struct erofs_map_blocks map = {0};
	struct erofs_map_dev mdev;
	struct vm_area_struct lower_vma;
	int err;
	vm_fault_t ret;

	npages = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);
	if (unlikely(orig_pgoff >= npages))
		return VM_FAULT_SIGBUS;

	memcpy(&lower_vma, vmf->vma, sizeof(lower_vma));

	/* TODO: check if chunk is available for us to read. */
	map.m_la = orig_pgoff << PAGE_SHIFT;
	pos = map.m_la;
	err = erofs_map_blocks(inode, &map, EROFS_GET_BLOCKS_RAW);
	if (err)
		return vmf_error(err);

	mdev = (struct erofs_map_dev) {
		.m_deviceid = map.m_deviceid,
		.m_pa = map.m_pa,
	};
	err = erofs_map_dev(inode->i_sb, &mdev);
	if (err)
		return vmf_error(err);

	lower_vma.vm_file = mdev.m_fp;
	vmf->pgoff = (mdev.m_pa + (pos - map.m_la)) >> PAGE_SHIFT;
	vmf->vma = &lower_vma; /* override vma temporarily */
	ret = EROFS_I(inode)->lower_vm_ops->fault(vmf);
	vmf->vma = vma;
	vmf->pgoff = orig_pgoff;
	return ret;
}

static const struct vm_operations_struct rafs_v6_vm_ops = {
	.fault	= rafs_v6_filemap_fault,
};

static int rafs_v6_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(file);
	struct erofs_inode *vi = EROFS_I(inode);
	const struct vm_operations_struct *lower_vm_ops;
	int ret;

	ret = call_mmap(EROFS_I_SB(inode)->bootstrap, vma);
	if (ret) {
		pr_err("%s: call_mmap failed ret %d\n", __func__, ret);
		return ret;
	}

	/* set fs's vm_ops which is used in fault(). */
	lower_vm_ops = vma->vm_ops;

	if (vi->lower_vm_ops && vi->lower_vm_ops != lower_vm_ops) {
		WARN_ON_ONCE(1);
		return -EOPNOTSUPP;
	}
	/* fault() must exist in order to proceed. */
	if (!lower_vm_ops || !lower_vm_ops->fault) {
		WARN_ON_ONCE(1);
		return -EOPNOTSUPP;
	}
	vi->lower_vm_ops = lower_vm_ops;
	vma->vm_flags &= ~VM_HUGEPAGE;	/* dont use huge page */
	vma->vm_ops = &rafs_v6_vm_ops;
	return 0;
}

const struct file_operations rafs_v6_file_ro_fops = {
	.llseek		= generic_file_llseek,
	.read_iter	= rafs_v6_file_read_iter,
	.mmap		= rafs_v6_file_mmap,
//	.mmap		= generic_file_readonly_mmap,
	.splice_read	= generic_file_splice_read,
};

static int rafs_v6_readpage(struct file *file, struct page *page)
{
	struct kvec iov = {
		.iov_base	= page_address(page),
	};
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	erofs_off_t pos = page->index << PAGE_SHIFT;
	struct erofs_map_blocks map = { .m_la = pos };
	struct kiocb kiocb;
	struct iov_iter iter;
	int err;

	err = erofs_map_blocks(inode, &map, EROFS_GET_BLOCKS_RAW);
	if (err)
		goto err_out;

	iov.iov_len = min_t(u64, PAGE_SIZE, map.m_plen - (pos - map.m_la));
	init_sync_kiocb(&kiocb, EROFS_SB(sb)->bootstrap);
	kiocb.ki_pos = map.m_pa + (pos - map.m_la);
//	if (!(kiocb.ki_pos & ~PAGE_MASK) && iov.iov_len == PAGE_SIZE)
//		kiocb.ki_flags |= IOCB_DIRECT;
	iov_iter_kvec(&iter, READ, &iov, 1, iov.iov_len);
	err = kiocb.ki_filp->f_op->read_iter(&kiocb, &iter);
	if (err < iov.iov_len)
		goto err_out;
	if (iov.iov_len < PAGE_SIZE)
		memset(iov.iov_base + iov.iov_len, 0,
		       PAGE_SIZE - iov.iov_len);
	SetPageUptodate(page);
	unlock_page(page);
	return 0;
err_out:
	SetPageError(page);
	unlock_page(page);
	return err;
}

const struct address_space_operations rafs_v6_aops = {
        .readpage = rafs_v6_readpage,
};
