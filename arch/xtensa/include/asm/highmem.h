/*
 * arch/xtensa/include/asm/highmem.h
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file "COPYING" in the main directory of
 * this archive for more details.
 *
 * Copyright (C) 2003 - 2011 Tensilica Inc.
 * Copyright (C) 2011 Pete Delaney
 */

#ifndef _XTENSA_HIGHMEM_H
#define _XTENSA_HIGHMEM_H

#ifdef __KERNEL__

#include <linux/interrupt.h>
#include <asm/kmap_types.h>
#include <asm/fixmap.h>

/*
 * Right now we initialize only a single PMD entry and it's associated single page of
 * PTE entries. The pkmap_page_dir array pointed to by pointer pkmap_page_table It 
 * can be extended  easily, subsequent pte tables have to be allocated in one physical
 * chunk of RAM. 
 *
 * So the the 4 Mbytes is shared between the interrupt time FIXED_MAPPINGS and 
 * the normal interruptable PERSISTANT mappings.
 *
 * For now, to keep it simple  we just split the area in about half; leaving 8 unused entries
 * between the persistand and temporary entries.
 *
 * Later We'll try a tigher setting of:
 * 
 * 	LAST_PKMAP = PTRS_PER_PTE - FIX_KMAP_END
 *
 * See diagram in arch/xtensa/include/asm/fixmap.h
 */
#define PKMAP_BASE              (FIXADDR_TOP - PMD_SIZE)
#define LAST_PKMAP 		((PTRS_PER_PTE/2) - 8)		/* 512 - 8 */
#define LAST_PKMAP_MASK 	(LAST_PKMAP-1)
#define PKMAP_NR(virt)  	((virt-PKMAP_BASE) >> PAGE_SHIFT)
#define PKMAP_ADDR(nr)  	(PKMAP_BASE + ((nr) << PAGE_SHIFT))

#define KMAP_PROT               PAGE_KERNEL

extern pte_t 		*pkmap_page_table;	/* Actually points to an array of pte's */
extern pte_dir_t 	 pkmap_page_dir;	/* Array of 1024 pte's */

#define ARCH_NEEDS_KMAP_HIGH_GET

extern void *kmap_high(struct page *page);
extern void *kmap_high_get(struct page *page);
extern void kunmap_high(struct page *page);

extern int highmem_debug;			/* Enables Xtensa HighMem Debug */

#if 0
/*
 * We may want to inline these functions later
 * for better performace. X86 doesn't seem
 * to bother.
 */
static inline void *kmap(struct page *page)
{
	BUG_ON(in_interrupt());
	if (!PageHighMem(page))
		return page_address(page);
	return kmap_high(page);
}

static inline void kunmap(struct page *page)
{
	BUG_ON(in_interrupt());
	if (!PageHighMem(page))
		return;
	kunmap_high(page);
}
#else
void *kmap(struct page *page);
void kunmap(struct page *page);
#endif

extern void *kmap_atomic(struct page *page, enum km_type type);
extern void kunmap_atomic(void *kvaddr, enum km_type type);
extern struct page *kmap_atomic_to_page(void *vaddr);

#define flush_cache_kmaps()	flush_cache_all()

#endif /* __KERNEL__ */
#endif /* _XTENSA_HIGHMEM_H */
