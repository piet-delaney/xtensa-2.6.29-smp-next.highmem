/*
 * arch/xtensa/include/asm/highmem.h
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file "COPYING" in the main directory of
 * this archive for more details.
 *
 * Copyright (C) 2003 - 2011 Tensilica Inc.
 */

#ifndef _XTENSA_HIGHMEM_H
#define _XTENSA_HIGHMEM_H

#ifdef __KERNEL__

#include <linux/interrupt.h>
#include <asm/kmap_types.h>

/*
 * Right now we initialize only a single pte table. It can be extended
 * easily, subsequent pte tables have to be allocated in one physical
 * chunk of RAM.
 */
#define PKMAP_BASE              (PAGE_OFFSET - PMD_SIZE)
#define LAST_PKMAP 		PTRS_PER_PTE				/* 1024 */
#define LAST_PKMAP_MASK 	(LAST_PKMAP-1)
#define PKMAP_NR(virt)  	((virt-PKMAP_BASE) >> PAGE_SHIFT)
#define PKMAP_ADDR(nr)  	(PKMAP_BASE + ((nr) << PAGE_SHIFT))

#define kmap_prot               PAGE_KERNEL

extern pte_t *pkmap_page_table;


extern void *kmap_high(struct page *page);
extern void kunmap_high(struct page *page);

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

extern void *kmap_atomic(struct page *page, enum km_type type);
extern void kunmap_atomic(void *kvaddr, enum km_type type);
extern struct page *kmap_atomic_to_page(void *vaddr);

#define flush_cache_kmaps()	flush_cache_all()

#endif /* __KERNEL__ */
#endif /* _XTENSA_HIGHMEM_H */
