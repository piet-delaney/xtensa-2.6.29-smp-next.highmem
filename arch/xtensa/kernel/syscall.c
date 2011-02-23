/*
 * arch/xtensa/kernel/syscall.c
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2001 - 2005 Tensilica Inc.
 * Copyright (C) 2000 Silicon Graphics, Inc.
 * Copyright (C) 1995 - 2000 by Ralf Baechle
 *
 * Joe Taylor <joe@tensilica.com>
 * Marc Gauthier <marc@tensilica.com, marc@alumni.uwaterloo.ca>
 * Chris Zankel <chris@zankel.net>
 * Kevin Chea
 *
 */
#include <asm/uaccess.h>
#include <asm/syscall.h>
#include <asm/unistd.h>
#include <asm/io.h>
#include <linux/linkage.h>
#include <linux/stringify.h>
#include <linux/errno.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/shm.h>

typedef void (*syscall_t)(void);

syscall_t sys_call_table[__NR_syscall_count] /* FIXME __cacheline_aligned */= {
	[0 ... __NR_syscall_count - 1] = (syscall_t)&sys_ni_syscall,

#undef __SYSCALL
#define __SYSCALL(nr,symbol,nargs) [ nr ] = (syscall_t)symbol,
#undef _XTENSA_UNISTD_H
#undef  __KERNEL_SYSCALLS__
#include <asm/unistd.h>
};

/*
 * xtensa_pipe() is the normal C calling standard for creating a pipe. It's not
 * the way unix traditional does this, though.
 */

asmlinkage long xtensa_pipe(int __user *userfds)
{
	int fd[2];
	int error;

	error = do_pipe_flags(fd, 0);
	if (!error) {
		if (copy_to_user(userfds, fd, 2 * sizeof(int)))
			error = -EFAULT;
	}
	return error;
}

asmlinkage long xtensa_mmap2(unsigned long addr, unsigned long len,
   			     unsigned long prot, unsigned long flags,
			     unsigned long fd, unsigned long pgoff)
{
	int error = -EBADF;
	struct file * file = NULL;

#if 1
	/*
	 * REMIND FIXME:
	 *
	 * We are hitting a panic when len is > 7500 pages.
	 * mm->nr_ptes is 1 and should be 0 in exit_mmap()
	 * at BUGON(). The exit is due to a NULL PTE that
	 * we are trying to use in a user 2nd level tlb fault.
	 *
	 * Fails in Linux LTP test with mmap001 -m 10000.
	 *
	 * You may want to place a conditional breakpoint 
	 * here when:
	 *	addr == XCHAL_KIO_CACHED_VADDR, or,
	 *	addr == XCHAL_KIO_BYPASS_VADDR 
	 *
	 * The addition of arch_get_unmapped_area() does
	 * NOT appear to removed the need for this workaround.
	 *
	 * This has the unfortunate current consequnce of limiting 
	 * user space malloc() calls to 29 MBytes.
	 */
	if (len > 30720000) {
		/*
		 * Users must be awair of this workaround if it's effecting them.
		 */
		printk(KERN_ERR "%s: (len:%lu > 30720000; return(EFBIG); [FIXME]\n", 
			__func__,     len);

		error = EFBIG;
		goto out;
	}
#endif

	flags &= ~(MAP_EXECUTABLE | MAP_DENYWRITE);
	if (!(flags & MAP_ANONYMOUS)) {
		file = fget(fd);
		if (!file)
			goto out;
	}

	down_write(&current->mm->mmap_sem);
	error = do_mmap_pgoff(file, addr, len, prot, flags, pgoff);
	up_write(&current->mm->mmap_sem);

	if (file)
		fput(file);
out:
	return error;
}

asmlinkage long xtensa_shmat(int shmid, char __user *shmaddr, int shmflg)
{
	unsigned long ret;
	long err;

	err = do_shmat(shmid, shmaddr, shmflg, &ret);
	if (err)
		return err;
	return (long)ret;
}

asmlinkage long xtensa_fadvise64_64(int fd, int advice, unsigned long long offset, unsigned long long len)
{
	return sys_fadvise64_64(fd, offset, len, advice);
}

