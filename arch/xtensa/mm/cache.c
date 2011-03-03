/*
 * arch/xtensa/mm/cache.c
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2001-2009 Tensilica Inc.
 *
 * Chris Zankel	<chris@zankel.net>
 * Joe Taylor <joe@tensilica.com>
 * Marc Gauthier <marc@tensilica.com
 * Pete Delaney <piet@tensilica.com.
 */

#include <linux/init.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/bootmem.h>
#include <linux/swap.h>
#include <linux/pagemap.h>

#include <asm/bootparam.h>
#include <asm/mmu_context.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>

//#define printd(x...) printk(x)
#define printd(x...) do { } while(0)

/*
 * Workaround for our current implementation of the 
 * Lazy TLB algorithm. Prevents TLB from getting out
 * of sync with memory based PTEs.
 */
#ifdef CONFIG_IGNORE_MM_CONTEXT_ASID
int config_ignore_mm_context_asid = 1;
#else
int config_ignore_mm_context_asid = 0;
#endif

/*
 * Workaround for SMP to prevent PG_arch_1
 * bit being used for lazy cache and tlb
 * flushed.
 */
#ifdef CONFIG_IGNORE_PAGE_ARCH_1_BIT
int config_ignore_PG_arch_1 = 1;
#else
int config_ignore_PG_arch_1 = 0;
#endif

/* 
 * Note:
 * The kernel provides one architecture bit PG_arch_1 in the page flags that 
 * can be used for cache coherency.
 *
 * I$-D$ coherency.
 *
 * The Xtensa architecture doesn't keep the instruction cache coherent with
 * the data cache. We use the architecture bit to indicate if the caches
 * are coherent. The kernel clears this bit whenever a page is added to the
 * page cache. At that time, the caches might not be in sync. We, therefore,
 * define this flag as 'clean' if set.
 *
 * D-cache aliasing.
 *
 * With cache aliasing, we have to always flush the cache when pages are
 * unmapped (see tlb_start_vma(). So, we use this flag to indicate a dirty
 * page.
 * 
 *
 *
 */

#if defined(DCACHE_ALIASING_POSSIBLE) || (defined(CONFIG_SMP) && defined(CONFIG_ARCH_HAS_SMP))

/*
 * Any time the kernel writes to a user page cache page, or it is about to
 * read from a page cache page this routine is called.
 */
void flush_dcache_page(struct page *page)
{
	struct address_space *mapping = page_mapping(page);

	/*
	 * If we have a mapping but the page is not mapped to user-space
	 * yet, we simply mark this page dirty and defer flushing the 
	 * caches until update_mmu().
	 */

	if (mapping && !config_ignore_PG_arch_1 && !mapping_mapped(mapping)) {
		if (!test_bit(PG_arch_1, &page->flags))
			set_bit(PG_arch_1, &page->flags);
		return;

	} else {
		unsigned long phys = page_to_phys(page);
		unsigned long temp = page->index << PAGE_SHIFT;
		unsigned long mask = DCACHE_ALIAS_MASK;
		unsigned long alias = !(DCACHE_ALIAS_EQ(temp, phys));
		unsigned long virt;
		void *vaddr = 0;
#ifdef CONFIG_HIGHMEM
		int is_preemptible = preemptible();
		int need_to_kunmap_atomic = 0;
		int need_to_kunmap = 0;
#endif

		/* 
		 * Flush the page in kernel space and user space.
		 * Note that we can omit that step if aliasing is not
		 * an issue, but we do have to synchronize I$ and D$
		 * if we have a user-space mapping.
		 */
		if (!alias && !mapping)
			return;

		/* 
 		 * Flush page in kernel space. For HIGHMEM
 		 * with cache alias we will be getting back
 		 * a virtual address with the same alias bits
 		 * as physical memory. So all HIGHMEM kernel
 		 * addresses have the same alias bit.
 		 */
#ifdef CONFIG_HIGHMEM
		 if (PageHighMem(page)) {
			if (is_preemptible)
				vaddr =  kmap_high_get(page);
			
			if (vaddr == NULL) {
				vaddr = kmap_atomic(page, KM_FLUSH_DCACHE_PAGE);
				 need_to_kunmap_atomic = 1;
			} else
				 need_to_kunmap = 1;
		}
#else
		vaddr = page_address(page);
#endif
		__flush_invalidate_dcache_page((long)vaddr);

		virt = TLBTEMP_BASE_1 + (temp & mask);

		if (alias)
			__flush_invalidate_dcache_page_alias(virt, phys);

		if (mapping)
			__invalidate_icache_page_alias(virt, phys);

#ifdef CONFIG_HIGHMEM
		/*
		 * Drop Highmem mapings if we had to use one.
		 */ 
		if (need_to_kunmap_atomic) 
			 kunmap_atomic(vaddr, KM_FLUSH_DCACHE_PAGE);
		else if (need_to_kunmap)
			 kunmap_high(page);
#endif
	}

	/* There shouldn't be an entry in the cache for this page anymore. */
}
#endif /* DCACHE_ALIASING_POSSIBLE */

/*
 * Flush an anonymous page so that users of get_user_pages()
 * can safely access the data.  The expected sequence is:
 *
 *  get_user_pages()
 *    -> flush_anon_page
 *  memcpy() to/from page
 *  if written to page, flush_dcache_page()
 *
 * NOTE:
 *	Currently get_user_pages() always calls flush_dcache_page()
 *	after calling flush_anon_page(). So for a VIPT cache this
 *	function ends up doing the same thing as flush_dcache_page()
 *	and shouldn't be necessary.
 */
void __flush_anon_page(struct vm_area_struct *vma, struct page *page, unsigned long vmaddr)
{
	unsigned long pfn;
#ifdef CONFIG_HIGHMEM
	int is_preemptible;
	int need_to_kunmap_atomic = 0;
	int need_to_kunmap = 0;
#endif
	void *page_kaddr = 0;	/* Permaniant, Persistant, or Dynamic ...
				  ... kernel virtual address of page */

	/* VIPT non-aliasing caches need do nothing */
	if (cache_is_vipt_nonaliasing())
		return;

	
	/* 
 	 * Flush page in kernel space. For HIGHMEM
 	 * with cache alias we will be getting back
 	 * a virtual address with the same alias bits
 	 * as physical memory. So all HIGHMEM kernel
 	 * addresses have the same alias bit.
 	 */
#ifdef CONFIG_HIGHMEM
	is_preemptible = preemptible();
	 if (PageHighMem(page)) {
		if (is_preemptible)
			page_kaddr =  kmap_high_get(page);
		
		if (page_kaddr == NULL) {
			/* Dynamic Kernal Address */
			page_kaddr = kmap_atomic(page, KM_FLUSH_ANON_PAGE);
			 need_to_kunmap_atomic = 1;
		} else 
			/* Got a Persistant Kernela Address */
			 need_to_kunmap = 1;
	}
#else
	/* Use a permanant kernel address */
	page_kaddr = page_address(page);
#endif

	/*
	 * Write back and invalidate userspace mapping.
	 */
	if (cache_is_vivt()) {
		pfn = page_to_pfn(page);
		flush_cache_page(vma, vmaddr, pfn);
	} else {
		unsigned long phys = page_to_phys(page);
		unsigned long temp = page->index << PAGE_SHIFT;
		unsigned long virt;

		virt = TLBTEMP_BASE_1 + (temp & DCACHE_ALIAS_MASK);
		/*
		 * For aliasing VIPT, we can flush an alias of the
		 * userspace address only.
		 */
		 __flush_invalidate_dcache_page_alias(virt, phys);
	}

	/*
	 * Invalidate kernel mapping.  No data should be contained
	 * in this mapping of the page.  FIXME: this is overkill
	 * since we actually ask for a write-back and invalidate.
	 */
	__flush_invalidate_dcache_page((long) page_kaddr);

#ifdef CONFIG_HIGHMEM
	/*
	 * Drop Highmem kernel mapings if we had to use one.
	 */ 
	if (need_to_kunmap_atomic) 
		 kunmap_atomic(page_kaddr, KM_FLUSH_ANON_PAGE);
	else if (need_to_kunmap)
		 kunmap_high(page);
#endif
}

#if defined(DCACHE_ALIASING_POSSIBLE) || (defined(CONFIG_SMP) && defined(CONFIG_ARCH_HAS_SMP))
/*
 * For now, flush the whole cache on the local CPU. FIXME??
 */

void local_flush_cache_range(struct vm_area_struct* vma, 
		       unsigned long start, unsigned long end)
{
#if 0
	/* 
	 * REMIND: Why does this cause severe problems
	 * at do_illegal_instruction() when starting the
	 * 1st process?
	 */
	__flush_invalidate_dcache_range(start, end);
	__invalidate_icache_range(start, end);
#else
	__flush_invalidate_dcache_all();
	__invalidate_icache_all();
#endif
}

/* 
 * Remove any entry in the local CPU's cache for this physical page. 
 *
 * Note that this function is only called for user pages, so use the
 * alias versions of the cache flush functions.
 *
 * This is called when changing a pte, the pte will be flushed by
 * set_pte(). Here we make sure the data currently mapped by
 * the pte is flushed and invalidated prior to changeing the pte.
 *
 * Often the user_address will not yet be mapped, and we can't
 * make a TLB entry with the same virtual and physical addresses,
 * as that would cause a multi-hit. So we use it's kernel alias 
 * equivalent to flush page. The alias address uses the same cache 
 * lines, so flushing it is equivalent.
 */

void local_flush_cache_page(struct vm_area_struct* vma, unsigned long user_address,
    		      unsigned long pfn)
{
	/* 
	 * Note that we have to use the 'alias' address to avoid 
	 * multi-hit (#17) or TLB Miss (#24).
 	 */
	unsigned long phys = page_to_phys(pfn_to_page(pfn));
	unsigned long virt = TLBTEMP_BASE_1 + (user_address & DCACHE_ALIAS_MASK);

	/*
	 * The functions below will dynamicly create TLB entrys
	 * prior to doing the flushes and then invalidate the
	 * the tlb entry that they just created.
	 */
	__flush_invalidate_dcache_page_alias(virt, phys);
	__invalidate_icache_page_alias(virt, phys);
}

#endif /* defined(DCACHE_ALIASING_POSSIBLE) || defined(CONFIG_SMP) */

void
update_mmu_cache(struct vm_area_struct * vma, unsigned long addr, pte_t pte)
{
	unsigned long pfn = pte_pfn(pte);
	struct page *page;
	unsigned long page_vaddr;
	void *vaddr;
	int icache_page_flushed = 0;
	int need_to_kunmap_atomic = 0;
	int need_to_kunmap = 0;
	int highmem_addr = 0;

	/* 
 	 * Invalidate old or bogus entry in TLBs.  If a pte is invalid, Ex: PTE_NONE, and
 	 * it's accesses the invalid pte is loaded  into the TLB. After mapping the page
 	 * this is called and we here remove the bogus entry from the TLB.
 	 */
	invalidate_itlb_mapping(addr);
	invalidate_dtlb_mapping(addr);

	BUG_ON(!pfn_valid(pfn));

	page = pfn_to_page(pfn);

#ifdef CONFIG_HIGHMEM
	 if (PageHighMem(page)) {
		highmem_addr = 1;
		vaddr =  kmap_high_get(page);
		if (vaddr == NULL) {
			vaddr = kmap_atomic(page, KM_TLB_CACHE_FLUSH);
			need_to_kunmap_atomic = 1;
		} else {
			need_to_kunmap = 1;
		}
	} else {
		/* Just a normal non-HIGHMEM address */
		vaddr = page_address(page);
	}
#else
	vaddr = page_address(page);
#endif

	page_vaddr = (unsigned long) vaddr;
	BUG_ON(page_vaddr == 0);

#if defined(DCACHE_ALIASING_POSSIBLE) || defined(CONFIG_SMP)

	if (!PageReserved(page) && (config_ignore_PG_arch_1 || test_bit(PG_arch_1, &page->flags))) {

		unsigned long vaddr = TLBTEMP_BASE_1 + (addr & DCACHE_ALIAS_MASK);
		unsigned long phys = page_to_phys(page);

		__flush_invalidate_dcache_page(page_vaddr);

		__flush_invalidate_dcache_page_alias(vaddr, phys);
		__invalidate_icache_page_alias(vaddr, phys);

		clear_bit(PG_arch_1, &page->flags);
	}
#else
	if (!PageReserved(page) && (config_ignore_PG_arch_1 || !test_bit(PG_arch_1, &page->flags))
	    && (vma->vm_flags & VM_EXEC) != 0) {
		__flush_dcache_page(page_vaddr);
		 if ( !highmem_addr && vma->vm_flags & VM_EXEC) {
			__invalidate_icache_page(page_vaddr);
			icache_page_flushed = 1;
		}
		set_bit(PG_arch_1, &page->flags);
	}
#endif

	if (!icache_page_flushed && !highmem_addr && vma->vm_flags & VM_EXEC) 
		__invalidate_icache_page(page_vaddr);

#ifdef CONFIG_HIGHMEM
	/*
	 * Drop Highmem mapings if we had to use one.
	 */ 
	if (need_to_kunmap_atomic) 
		 kunmap_atomic(vaddr, KM_TLB_CACHE_FLUSH);
	else if (need_to_kunmap)
		 kunmap_high(page);
#endif
}

/*
 * access_process_vm() has called get_user_pages(), which has done a
 * flush_dcache_page() on the page.
 */

#if defined(DCACHE_ALIASING_POSSIBLE) || defined(CONFIG_SMP)

void copy_to_user_page(struct vm_area_struct *vma, struct page *page, 
		unsigned long vaddr, void *dst, const void *src,
		unsigned long len)
{
	unsigned long phys = page_to_phys(page);
	unsigned long alias = !(DCACHE_ALIAS_EQ(vaddr, phys));

	/* Flush and invalidate user page if aliased. */

	if (alias) {
		unsigned long temp = TLBTEMP_BASE_1 + (vaddr & DCACHE_ALIAS_MASK);
		__flush_invalidate_dcache_page_alias(temp, phys);
	}

	/* Copy data */
	
	memcpy(dst, src, len);

	/*
	 * Flush and invalidate kernel page if aliased and synchronize 
	 * data and instruction caches for executable pages. 
	 */

	if (alias) {
		unsigned long temp = TLBTEMP_BASE_1 + (vaddr & DCACHE_ALIAS_MASK);

		__flush_invalidate_dcache_range((unsigned long) dst, len);
		if ((vma->vm_flags & VM_EXEC) != 0) {
			__invalidate_icache_page_alias(temp, phys);
		}

	} else if ((vma->vm_flags & VM_EXEC) != 0) {
		__flush_dcache_range((unsigned long)dst,len);
		__invalidate_icache_range((unsigned long) dst, len);
	}
}

extern void copy_from_user_page(struct vm_area_struct *vma, struct page *page,
		unsigned long vaddr, void *dst, const void *src,
		unsigned long len)
{
	unsigned long phys = page_to_phys(page);
	unsigned long alias = !(DCACHE_ALIAS_EQ(vaddr, phys));

	/*
	 * Flush user page if aliased. 
	 * (Note: a simply flush would be sufficient) 
	 */

	if (alias) {
		unsigned long temp = TLBTEMP_BASE_1 + (vaddr & DCACHE_ALIAS_MASK);
		__flush_invalidate_dcache_page_alias(temp, phys);
	}

	memcpy(dst, src, len);
}

#endif
