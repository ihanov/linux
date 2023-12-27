// SPDX-License-Identifier: GPL-2.0-only
/*
 * New dummy system call that copies one file
 * identified by path to another location
 * also identified by path (c-string).
 */

#include <uapi/linux/limits.h> /* PATH_MAX */
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE2(copy_file, const char __user *, src, const char __user *, dst)
{
	int ret;
	char *kernel_src;
	char *kernel_dst;
	struct file *src_file;
	struct file *dst_file;
	struct kstat *stat;
	void *buf;
	size_t buf_size;
	ssize_t rv;
	ssize_t wr;
	loff_t rv_pos;
	loff_t wr_pos;

	ret = -EINVAL;
	if (!src || !dst)
		goto out;

	kernel_src = strndup_user(src, PATH_MAX);
	ret = PTR_ERR(kernel_src);
	if (IS_ERR(kernel_src))
		goto out;

	kernel_dst = strndup_user(dst, PATH_MAX);
	ret = PTR_ERR(kernel_dst);
	if (IS_ERR(kernel_dst))
		goto free_src;

	src_file = filp_open(kernel_src, O_RDONLY, 0);
	ret = PTR_ERR(src_file);
	if (IS_ERR(src_file))
		goto free_dst;

	dst_file = filp_open(kernel_dst, O_WRONLY | O_CREAT, S_IALLUGO);
	ret = PTR_ERR(dst_file);
	if (IS_ERR(dst_file))
		goto close_src;

	ret = -ENOMEM;
	stat = kmalloc(sizeof(*stat), GFP_KERNEL);
	if (!stat)
		goto close_dst;

	ret = vfs_getattr(&src_file->f_path, stat, STATX_BASIC_STATS, 0);
	if (ret)
		goto free_stat;

	/* TODO: use vfs_fallocate to pre-allocate disk space */

	/* allocate temporary buffer (kernel should not use much memory) */
	buf_size = PAGE_SIZE;
	buf = kmalloc(buf_size, GFP_KERNEL);
	if (!buf)
		goto free_stat;

	rv_pos = 0;
	while (rv_pos != stat->size) {
		buf_size = stat->size - rv_pos;
		if (stat->size - rv_pos > PAGE_SIZE)
			buf_size = PAGE_SIZE;

		rv = kernel_read(src_file, buf, buf_size, &rv_pos);
		if (rv != buf_size) {
			ret = (rv < 0) ? rv : -EIO;
			goto free_buf;
		}

		wr = kernel_write(dst_file, buf, rv, &wr_pos);
		if (wr != rv) {
			ret = (wr < 0) ? wr : -EIO;
			goto free_buf;
		}
	}

	ret = stat->size;
free_buf:
	kfree(buf);
free_stat:
	kfree(stat);
close_dst:
	filp_close(dst_file, NULL);
close_src:
	filp_close(src_file, NULL);
free_dst:
	kfree(kernel_dst);
free_src:
	kfree(kernel_src);
out:
	return ret;
}
