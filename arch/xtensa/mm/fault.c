// TODO VM_EXEC flag work-around, cache aliasing
/*
 * arch/xtensa/mm/fault.c
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2001 - 2010 Tensilica Inc.
 *
 * Chris Zankel <chris@zankel.net>
 * Joe Taylor	<joe@tensilica.com>
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/hardirq.h>
#include <asm/mmu_context.h>
#include <asm/cacheflush.h>
#include <asm/hardirq.h>
#include <asm/uaccess.h>
#include <asm/system.h>
#include <asm/pgalloc.h>

// #undef DEBUG_PAGE_FAULT
#define DEBUG_PAGE_FAULT

#ifdef DEBUG_PAGE_FAULT
/*
 * Enable Fault Debug Here, with .xt-gdbinit file, or via CONFIG_CMDLINE. 
 * Ex:
 *     CONFIG_CMDLINE="console=ttyS0 ... coredump_filter=0xff page_fault_debug"
 */
int page_fault_debug = 0;
static int page_fault_printks = 0;

static int __init page_fault_debug_setup(char *buf)
{
	page_fault_debug = 1;
        return 0;
}

early_param("page_fault_debug", page_fault_debug_setup);

#define dprintf(fmt, args...) ({                        \
        if (unlikely(page_fault_debug))                 \
                printk(KERN_INFO                        \
                        "PageFault::%s " fmt,           \
                        __func__, ## args);             \
})

#else
##define dprintf(fmt, args...)
#endif


void bad_page_fault(struct pt_regs*, unsigned long, int);

DEFINE_PER_CPU(unsigned long, asid_cache) = ASID_USER_FIRST;


/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 *
 * Note: does not handle Miss and MultiHit.
 */

void do_page_fault(struct pt_regs *regs)
{
	struct vm_area_struct * vma;
	struct mm_struct *mm = current->mm;
	unsigned int exccause = regs->exccause;
	unsigned int address = regs->excvaddr;
	siginfo_t info;

	int is_write, is_exec;
	int fault;

	info.si_code = SEGV_MAPERR;

	/* We fault-in kernel-space virtual memory on-demand. The
	 * 'reference' page table is init_mm.pgd.
	 */
	if (address >= TASK_SIZE && !user_mode(regs))
		goto vmalloc_fault;

	/* If we're in an interrupt or have no user
	 * context, we must not take the fault..
	 */
	if (in_atomic() || !mm) {
		bad_page_fault(regs, address, SIGSEGV);
		return;
	}

	is_write = (exccause == EXCCAUSE_STORE_CACHE_ATTRIBUTE) ? 1 : 0;
	is_exec =  (exccause == EXCCAUSE_ITLB_PRIVILEGE ||
		    exccause == EXCCAUSE_ITLB_MISS ||
		    exccause == EXCCAUSE_FETCH_CACHE_ATTRIBUTE) ? 1 : 0;

#ifdef DEBUG_PAGE_FAULT
	if (page_fault_debug) {
		if ((page_fault_printks++ % 32) == 0)
			printk("%s: cpu comm pid address exccasue pc is_write? is_exec?\n", __func__);

		dprintf("[%d %s:%d:%08x:%d:%08lx:%s%s]\n", smp_processor_id(), current->comm, current->pid,
	       		address, exccause, regs->pc, is_write? "w":"", is_exec? "x":"");
	}
#endif

	down_read(&mm->mmap_sem);
	vma = find_vma(mm, address);

	if (!vma)
		goto bad_area;
	if (vma->vm_start <= address)
		goto good_area;
	if (!(vma->vm_flags & VM_GROWSDOWN))
		goto bad_area;
	if (expand_stack(vma, address))
		goto bad_area;

	/* Ok, we have a good vm_area for this memory access, so
	 * we can handle it..
	 */

good_area:
	info.si_code = SEGV_ACCERR;

	if (is_write) {
		if (!(vma->vm_flags & VM_WRITE))
			goto bad_area;
	} else if (is_exec) {
		if (!(vma->vm_flags & VM_EXEC))
			goto bad_area;
	} else	/* Allow read even from write-only pages. */
		if (!(vma->vm_flags & (VM_READ | VM_WRITE)))
			goto bad_area;

	/* If for any reason at all we couldn't handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.
	 */
#if 0
survive:
#endif
	fault = handle_mm_fault(mm, vma, address, is_write);
	if (unlikely(fault & VM_FAULT_ERROR)) {
		if (fault & VM_FAULT_OOM)
			goto out_of_memory;
		else if (fault & VM_FAULT_SIGBUS)
			goto do_sigbus;
		BUG();
	}
	if (fault & VM_FAULT_MAJOR)
		current->maj_flt++;
	else
		current->min_flt++;

	up_read(&mm->mmap_sem);
	return;

	/* Something tried to access memory that isn't in our memory map..
	 * Fix it, but check if it's kernel or user first..
	 */
bad_area:
	up_read(&mm->mmap_sem);
	if (user_mode(regs)) {
		current->thread.bad_vaddr = address;
		current->thread.error_code = is_write;
		info.si_signo = SIGSEGV;
		info.si_errno = 0;
		/* info.si_code has been set above */
		info.si_addr = (void *) address;
		force_sig_info(SIGSEGV, &info, current);
		return;
	}
	bad_page_fault(regs, address, SIGSEGV);
	return;


	/* We ran out of memory, or some other thing happened to us that made
	 * us unable to handle the page fault gracefully.
	 */
out_of_memory:
	printk("%s: out_of_memory:\n", __func__);

	up_read(&mm->mmap_sem);
#if 0
	if (is_global_init(current)) {
		yield();
		down_read(&mm->mmap_sem);
		goto survive;
	}
	printk("VM: killing process %s\n", current->comm);
	if (user_mode(regs))
		do_group_exit(SIGKILL);
	bad_page_fault(regs, address, SIGKILL);
#else
	printk("%s: killing process '%s'\n", __func__, current->comm);
	if (!user_mode(regs))
		bad_page_fault(regs, address, SIGKILL);
	else
		pagefault_out_of_memory();
#endif
	return;

do_sigbus:
	up_read(&mm->mmap_sem);

	/* Send a sigbus, regardless of whether we were in kernel
	 * or user mode.
	 */
	current->thread.bad_vaddr = address;
	info.si_code = SIGBUS;
	info.si_errno = 0;
	info.si_code = BUS_ADRERR;
	info.si_addr = (void *) address;
	force_sig_info(SIGBUS, &info, current);

	/* Kernel mode? Handle exceptions or die */
	if (!user_mode(regs))
		bad_page_fault(regs, address, SIGBUS);
	return;

vmalloc_fault:
	{
		/* Synchronize this task's top level page-table
		 * with the 'reference' page table.
		 */
		struct mm_struct *act_mm = current->active_mm;
		int index = pgd_index(address);
		pgd_t *pgd, *pgd_k;
		pmd_t *pmd, *pmd_k;
		pte_t *pte_k;

		if (act_mm == NULL)
			goto bad_page_fault;

		pgd = act_mm->pgd + index;
		pgd_k = init_mm.pgd + index;

		if (!pgd_present(*pgd_k))
			goto bad_page_fault;

		pgd_val(*pgd) = pgd_val(*pgd_k);

		pmd = pmd_offset(pgd, address);
		pmd_k = pmd_offset(pgd_k, address);
		if (!pmd_present(*pmd) || !pmd_present(*pmd_k))
			goto bad_page_fault;

		pmd_val(*pmd) = pmd_val(*pmd_k);
		pte_k = pte_offset_kernel(pmd_k, address);

		if (!pte_present(*pte_k))
			goto bad_page_fault;
		return;
	}
bad_page_fault:
	bad_page_fault(regs, address, SIGKILL);
	return;
}

void 
bad_page_fault_bp(void) {}

void
bad_page_fault(struct pt_regs *regs, unsigned long address, int sig)
{
	extern void die(const char*, struct pt_regs*, long);
	const struct exception_table_entry *entry;
	unsigned long ps, epc, epc1, prid = 0, rasid, exsave1, exsave2;
	unsigned long exccause, ptevaddr, excvaddr, tsk, sp, ra;

	/* Are we prepared to handle this kernel fault?  */
	if ((entry = search_exception_tables(regs->pc)) != NULL) {
#ifdef DEBUG_PAGE_FAULT
		dprintf(KERN_DEBUG "Fixup Enabled Exception for current->comm:'%s'at pc:%#010lx entry:%p->fixup:0x%lx)\n",
				current->comm, regs->pc, entry, entry->fixup);
#endif
		current->thread.bad_uaddr = address;
		regs->pc = entry->fixup;
		return;
	}
	bad_page_fault_bp();

	ps = get_sr(PS);
	epc = get_sr(EPC);
	epc1 = get_sr(EPC1);

#if defined(XCHAL_HAVE_PRID)
	prid = get_sr(PRID);
#endif
	rasid = get_sr(RASID);
	exsave1 = get_sr(EXCSAVE_1);
	exsave2 = get_sr(EXCSAVE_2);
	exccause = get_sr(EXCCAUSE);
	ptevaddr = get_sr(PTEVADDR);
	excvaddr = get_sr(EXCVADDR);
	tsk = (unsigned long) current;
	sp = current->thread.sp;
	ra = current->thread.ra;

	/* Oops. The kernel tried to access some bad page. We'll have to
	 * terminate things with extreme prejudice.
	 */
	printk(KERN_ALERT "%s: Unable to handle kernel paging request at virtual "
	       "address 0x%08lx\n pc = 0x%08lx, ra = 0x%08lx\n", __func__,
	       address, regs->pc, regs->areg[0]);

	printk(KERN_ALERT "%s: ps:0X%lx, epc:0X%lx, epc1:0X%lx, prid:0X%lx, rasid:0X%lx\n", __func__,
			       ps,       epc,       epc1,       prid,       rasid);

	printk(KERN_ALERT "%s: exsave1:0X%lx, exsave2:0X%lx, exccause:0X%lx, ptevaddr:0X%lx, excvaddr:0X%lx\n", __func__,
			       exsave1,       exsave2,       exccause,       ptevaddr,       excvaddr);

	printk(KERN_ALERT "%s: tsk:0X%lx->{thread.{sp:0X%lx, ra:0X%lx}}\n", __func__,
			       tsk,                sp,       ra);

	printk(KERN_ALERT "%s: regs:%p->{ps:0X%lx, depc:0X%lx, exccause:0X%lx. excvaddr:0X%lx, debugcause:0X%lx\n", __func__,
			     regs, regs->ps, regs->depc, regs->exccause, regs->excvaddr, regs->debugcause);

	printk(KERN_ALERT "%s: regs:%p->areg[ra:r0:0X%lx, sp:r1:0X%lx, r2:0X%lx, r3:0X%lx, r4:0X%lx, r5:0X%lx, r6:0X%lx]\n", __func__,
			   regs, regs->areg[0], regs->areg[1], regs->areg[2], regs->areg[3], regs->areg[4], regs->areg[5], regs->areg[5]);

	printk(KERN_ALERT "%s: regs:%p->areg[r7:0X%lx, r8:0X%lx, r9:0X%lx, r10:0X%lx, r11:0X%lx, r12:0X%lx]\n", __func__,
			  regs, regs->areg[7], regs->areg[8], regs->areg[9], regs->areg[10], regs->areg[11], regs->areg[12]);
#if 0
	dump_stack();
#else
	show_stack((struct task_struct *) tsk, (unsigned long *) regs->areg[1]);
#endif

	die("Oops", regs, sig);
	do_exit(sig);
}

#ifdef CONFIG_DEBUG_PAGEALLOC
/* 
 * FROM: avt32/mm/fault.c:
 *
 * This functionality is currently not possible to implement because
 * we're using segmentation to ensure a fixed mapping of the kernel
 * virtual address space.
 *
 * It would be possible to implement this, but it would require us to
 * disable segmentation at startup and load the kernel mappings into
 * the TLB like any other pages. There will be lots of trickery to
 * avoid recursive invocation of the TLB miss handler, though...
 */
void kernel_map_pages(struct page *page, int numpages, int enable)
{

}
EXPORT_SYMBOL(kernel_map_pages);
#endif

