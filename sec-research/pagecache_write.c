// SPDX-License-Identifier: GPL-2.0
/*
 * pagecache_write: deliberately-unsafe syscall for exploit-learning labs.
 *
 * Writes attacker-supplied bytes directly into the page cache of any
 * regular file, bypassing VFS write permission checks. Modified pages
 * are NOT marked dirty, so the on-disk file is untouched -- but every
 * subsequent read served from cache sees the corrupted bytes.
 *
 * This simulates the primitive offered by bugs like Dirty Pipe / Dirty
 * COW. Do NOT ship this in a real kernel.
 */
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/uaccess.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/limits.h>

#define PCW_MAX_LEN (1UL << 20)  /* cap at 1 MiB per call */

SYSCALL_DEFINE4(pagecache_write,
		const char __user *, upath,
		loff_t, offset,
		const void __user *, ubuf,
		size_t, len)
{
	char *kpath;
	struct path path;
	struct inode *inode;
	struct address_space *mapping;
	loff_t pos = offset;
	size_t remaining = len;
	size_t written = 0;
	long ret;

	if (len == 0)
		return 0;
	if (len > PCW_MAX_LEN)
		return -E2BIG;
	if (offset < 0)
		return -EINVAL;

	kpath = strndup_user(upath, PATH_MAX);
	if (IS_ERR(kpath))
		return PTR_ERR(kpath);

	ret = kern_path(kpath, LOOKUP_FOLLOW, &path);
	kfree(kpath);
	if (ret)
		return ret;

	inode = d_inode(path.dentry);
	if (!S_ISREG(inode->i_mode)) {
		ret = -EINVAL;
		goto out;
	}
	mapping = inode->i_mapping;
	if (!mapping) {
		ret = -EINVAL;
		goto out;
	}

	pr_warn_ratelimited("pagecache_write: pid=%d writing %zu bytes at %lld of %pd\n",
			    current->pid, len, (long long)offset, path.dentry);

	while (remaining) {
		pgoff_t index = pos >> PAGE_SHIFT;
		size_t page_off = pos & (PAGE_SIZE - 1);
		size_t chunk = min_t(size_t, PAGE_SIZE - page_off, remaining);
		struct folio *folio;
		void *kaddr;

		folio = filemap_grab_folio(mapping, index);
		if (IS_ERR(folio)) {
			ret = PTR_ERR(folio);
			goto out;
		}

		kaddr = kmap_local_folio(folio, 0);
		if (copy_from_user(kaddr + page_off, ubuf + written, chunk)) {
			kunmap_local(kaddr);
			folio_unlock(folio);
			folio_put(folio);
			ret = -EFAULT;
			goto out;
		}
		kunmap_local(kaddr);

		folio_unlock(folio);
		folio_put(folio);

		pos += chunk;
		written += chunk;
		remaining -= chunk;
	}

	ret = written;
out:
	path_put(&path);
	return ret;
}
