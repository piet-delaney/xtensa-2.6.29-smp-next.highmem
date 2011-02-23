/*
 * arch/xtensa/include/asm/page.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version2 as
 * published by the Free Software Foundation.
 *
 * Copyright (C) 2001 - 2010 Tensilica Inc.
 */

#ifndef _XTENSA_PAGE_H
#define _XTENSA_PAGE_H

#include <asm/processor.h>
#include <asm/types.h>
#include <asm/cache.h>
#include <platform/hardware.h>

/*
 * Fixed TLB translations in the processor.
 */

#define XCHAL_KSEG_CACHED_VADDR 0xd0000000
#define XCHAL_KSEG_BYPASS_VADDR 0xd8000000
#define XCHAL_KSEG_PADDR        0x00000000
#define XCHAL_KSEG_SIZE         0x08000000

/*
 * Extended memory option.
 * Because of the static mapping, we can usually only use up to 128MB memory.
 * The extended option allows to extend that space up to 128MB+192MB in 
 * increments of 64MB.
 * (we currently need to reserve some memory for virtual kernel space)
 */

// FIXME test
#define PLATFORM_EXT_MEM_START 0xcc000000

#if defined(CONFIG_MMU) && defined(CONFIG_EXTENDED_MEMORY)
# ifdef PLATFORM_EXT_MEM_START
#  define EXT_MEM_START		PLATFORM_EXT_MEM_START
# else
#  define EXT_MEM_START		0xc8000000
# endif
# define EXT_MEM_SIZE		(XCHAL_KSEG_CACHED_VADDR - (EXT_MEM_START))
#endif

/*
 * PAGE_SHIFT determines the page size
 */

#define PAGE_SHIFT	12
#define PAGE_SIZE	(__XTENSA_UL_CONST(1) << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))

#ifdef CONFIG_MMU
#ifdef CONFIG_EXTENDED_MEMORY
#define PAGE_OFFSET	(EXT_MEM_START)
#define MAX_MEM_PFN	(XCHAL_KSEG_SIZE + EXT_MEM_SIZE)
#else
#define PAGE_OFFSET	XCHAL_KSEG_CACHED_VADDR
#define MAX_MEM_PFN	XCHAL_KSEG_SIZE
# endif
#else
#define PAGE_OFFSET	0
#define MAX_MEM_PFN	(PLATFORM_DEFAULT_MEM_START + PLATFORM_DEFAULT_MEM_SIZE)
#endif

#define PGTABLE_START	0x80000000	/* Loaded into $ptevaddr during mmu initialization */

/*
 * Cache aliasing:
 *
 * If the cache size for one way is greater than the page size, we have to
 * deal with cache aliasing. The cache index is wider than the page size:
 *
 *     +--- PAGE_MASK
 *     |
 * |<--+->|
 * |    |cache| cache index
 * | pfn  |off|	virtual address
 * |xxxx:X|zzz|
 * |    : |   |
 * | \  / |   |
 * |trans.|   |
 * | /  \ |   |
 * |yyyy:Y|zzz|	physical address
 *       ^
 *       |
 *       +---- DCACHE_ALIAS_MASK
 *
 * When the page number is translated to the physical page address, the lowest
 * bit(s) (X) that are part of the cache index are also translated (Y).
 * If this translation changes bit(s) (X), the cache index is also affected,
 * thus resulting in a different cache line than before.
 *
 * The kernel does not provide a mechanism to ensure that the page color
 * (represented by this bit) remains the same when allocated or when pages
 * are remapped. When user pages are mapped into kernel space, the color of
 * the page might also change.
 *
 * We use the address space VMALLOC_END ... VMALLOC_END + DCACHE_WAY_SIZE * 2
 * to temporarily map a patch so we can match the color. 
 *
 * Using SPARC convention of using #if DCACHE_ALIASING_POSSIBLE...#endif
 * See arch/sparc/include/asm/page_64.h example.
 *
 * We use the following macros to work in determining if a user page is
 * using an alias with the kernel addresses. 
 */

#if DCACHE_WAY_SIZE > PAGE_SIZE && XCHAL_DCACHE_IS_WRITEBACK
# define DCACHE_ALIASING_POSSIBLE
# define DCACHE_ALIAS_ORDER	(DCACHE_WAY_SHIFT - PAGE_SHIFT)
# define DCACHE_ALIAS_MASK	(PAGE_MASK & (DCACHE_WAY_SIZE - 1))
# define DCACHE_ALIAS(a)	(((a) & DCACHE_ALIAS_MASK) >> PAGE_SHIFT)
# define DCACHE_ALIAS_EQ(a,b)	((((a) ^ (b)) & DCACHE_ALIAS_MASK) == 0)
#else
# define DCACHE_ALIAS_ORDER	0	/* Number of alias bits */
# define DCACHE_ALIAS_MASK	0	/* Mask out just the alias bits */
# define DCACHE_ALIAS(a)        0	/* Alias bits in LSB */
# define DCACHE_ALIAS_EQ(a,b)   0 	/* True is aliasing isn't a problem */
#endif

#if ICACHE_WAY_SIZE > PAGE_SIZE
# define ICACHE_ALIASING_POSSIBLE
# define ICACHE_ALIAS_ORDER	(ICACHE_WAY_SHIFT - PAGE_SHIFT)
# define ICACHE_ALIAS_MASK	(PAGE_MASK & (ICACHE_WAY_SIZE - 1))
# define ICACHE_ALIAS(a)	(((a) & ICACHE_ALIAS_MASK) >> PAGE_SHIFT)
# define ICACHE_ALIAS_EQ(a,b)	((((a) ^ (b)) & ICACHE_ALIAS_MASK) == 0)
#else
# define ICACHE_ALIAS_ORDER	0
# define ICACHE_ALIAS_MASK      0
# define ICACHE_ALIAS(a)        0
# define ICACHE_ALIAS_EQ(a,b)   0
#endif

#if defined(DCACHE_ALIASING_POSSIBLE) || defined(ICACHE_ALIASING_POSSIBLE)
# define CACHE_ALIASING_POSSIBLE
#endif

#ifdef __ASSEMBLY__

#define __pgprot(x)	(x)

#else

/*
 * These are used to make use of C type-checking..
 * It's also usefull for debugging to show bit more clearly with gdb.
 */
typedef enum {
	bypass = 0,
	wrback = 1,
	wrthru = 2,
	invalid = 3
} cache_attr_t;

typedef enum {
	kern = 0,
	user = 1,
	ring2 = 2,
	ring3 = 3
} ring_t;

typedef union  { 
	unsigned long pte;
	struct {				/* Little Endian Form */
		unsigned int x:1;		/* Bit 0: executable */
		unsigned int w:1;		/* Bit 1: writable */
		cache_attr_t attr:2;		/* Bit 2...3: cache attr */
		ring_t ring:2;			/* Bits 4...5: Ring */
		unsigned int present:1;		/* Bit 6: present */
		unsigned int dirty:1;		/* Bit 7: dirty */
		unsigned int accessed:1;	/* Bit 8: Accessed */
		unsigned int writable:1;	/* Bit 9: Writeable */
		unsigned int _unused:2;		/* Bit 10...11: <Available> */
		unsigned int ppn:20;		/* Bits 12...31: Page Number */
	} bit_fields;
} pte_t;					/* page table entry */

#if 1
typedef struct {
	pte_t	pte[1024];		 	/* A PTE Table */
} pte_table_t;
#endif

typedef pte_t pte_dir_t[1024];

typedef union { 
	unsigned long pgd; 
	pte_table_t *page_table;		/* Pointer to a page of pte entries */
	struct {				/* Little Endian Form */
		unsigned int _unused:12;	/* Bit 1...11: <Not Used> */
		unsigned int vpn:20;		/* Bits 12...31: Virtual Page Number */
	} bit_fields;
} pgd_t;					/* PGD table entry */



#if 1
typedef struct {
	pte_t	pmd[1024];			/* A PMD Table, which was folded from pgd entries */
} pmd_table_t;


typedef struct {
	pgd_t	pmd[1024];			/* A PGD Table, which is folded twice into an array of pmd entries */
} pud_table_t;

typedef struct {
	pgd_t	segment_0_hole[1];				/* Segment 0: Hole, Program Starts at 0x40,0000, ... */
	pgd_t	segment_0_and_1_program_pmd_entries[127];	/* Segments 0, 1:  ... seen often at mm->mmap->vm_start */
	pgd_t	segment_2_mmaped_pmd_entries[64];		/* Segment 2 */
	pgd_t	segment_3_program_stack_pmd_entries[64];	/* Segment 3 */
	pgd_t	segment_4_unused_pmd_entries[64];		/* Segment 4 */
	pgd_t	segment_5_unused_pmd_entries[64];		/* Segment 5 */
	pgd_t	segment_6_unused_pmd_entries[64];		/* Segment 6 */
	pgd_t	segment_7_unused_pmd_entries[64];		/* Segment 7 */
	pgd_t	segment_8_unused_pmd_entries[64];		/* Segment 8 */
	pgd_t	segment_9_unused_pmd_entries[64];		/* Segment 9 */
	pgd_t	segment_A_unused_pmd_entries[64];		/* Segment A */
	pgd_t	segment_B_unused_pmd_entries[64];		/* Segment B */
	pgd_t	segment_C_vmalloc_pmd_entries[28];		/* Segment C */
	pgd_t	segment_C_PKMAP_pmd_entries[1];			/* Segment C */
	pgd_t	segment_C_unused_pmd_entries[3];		/* Segment C */
	pgd_t	segment_C_ExtMemory_pmd_entries[32];		/* Segment C */
	pgd_t	segment_D_KSEG_cached_pmd_entries[32];		/* Segment D */
	pgd_t	segment_D_KSEG_uncached_pmd_entries[64];	/* Segment D */
	pgd_t	segment_E_KIO_Cached_pmd_entries[64];		/* Segment E */
	pgd_t	segment_F_KIO_Bypess_pmd_entries[64];		/* Segment E */
} pgd_table_t;
#endif

typedef pgd_t pmd_dir_t[1024];
typedef pgd_t pud_dir_t[1024];
typedef pgd_t pgd_dir_t[1024];

typedef struct { unsigned long pgprot; } pgprot_t;
typedef struct page *pgtable_t;

#define pte_val(x)	((x).pte)
#define pgd_val(x)	((x).pgd)
#define pgprot_val(x)	((x).pgprot)

#define __pte(x)	((pte_t) { (x) } )
#define __pgd(x)	((pgd_t) { (x) } )
#define __pgprot(x)	((pgprot_t) { (x) } )

/*
 * Pure 2^n version of get_order
 * Use 'nsau' instructions if supported by the processor or the generic version.
 */

#if XCHAL_HAVE_NSA

static inline __attribute_const__ int get_order(unsigned long size)
{
	int lz;
	asm ("nsau %0, %1" : "=r" (lz) : "r" ((size - 1) >> PAGE_SHIFT));
	return 32 - lz;
}

#else

# include <asm-generic/getorder.h>

#endif

struct page;
extern void clear_page(void *page);
extern void copy_page(void *to, void *from);

/*
 * If we have cache aliasing and writeback caches, we might have to do
 * some extra work
 */

#if defined(DCACHE_ALIASING_POSSIBLE) 
extern void clear_user_page(void*, unsigned long, struct page*);
extern void copy_user_page(void*, void*, unsigned long, struct page*);
#else
# define clear_user_page(page, vaddr, pg)	clear_page(page)
# define copy_user_page(to, from, vaddr, pg)	copy_page(to, from)
#endif

/*
 * This handles the memory map.  We handle pages at
 * XCHAL_KSEG_CACHED_VADDR for kernels with 32 bit address space.
 * These macros are for conversion of kernel address, not user
 * addresses.
 */

#define ARCH_PFN_OFFSET		(PLATFORM_DEFAULT_MEM_START >> PAGE_SHIFT)


#ifdef CONFIG_EXTENDED_MEMORY
#define __pa(x) xtensa_pa((unsigned long) (x))
#define __va(x) xtensa_va((unsigned long) (x))
/* 
 * With the extended memory option, we map the lower physical memory to the
 * higher virtual address starting at 0xd000_0000 (XCHAL_KSEG_CACHED_VADDR)
 * and the higher physical memory to the lower virtual address (EXT_MEM_START).
 */
static inline  unsigned long xtensa_pa(unsigned long vaddr) {
	unsigned long paddr;

#ifdef CONFIG_DEBUG_KERNEL
	if (vaddr <  EXT_MEM_START || 
	    vaddr >=  XCHAL_KSEG_CACHED_VADDR + XCHAL_KSEG_SIZE) {
		extern void panic(const char *fmt, ...);

		panic(__func__);
	}
#endif
	if (vaddr >= XCHAL_KSEG_CACHED_VADDR)
		paddr = vaddr - XCHAL_KSEG_CACHED_VADDR;
	else
 		paddr = vaddr - EXT_MEM_START + XCHAL_KSEG_SIZE;

	return(paddr);
}

static inline  void *xtensa_va(unsigned long paddr) {
	unsigned long vaddr;

	if (paddr >= XCHAL_KSEG_SIZE)
		vaddr = paddr - XCHAL_KSEG_SIZE + EXT_MEM_START;
	else
	 	vaddr = paddr + XCHAL_KSEG_CACHED_VADDR;

	return((void *) vaddr);
}
#else
#define __pa(x)			((unsigned long) (x) - PAGE_OFFSET)
#define __va(x)			((void *)((unsigned long) (x) + PAGE_OFFSET))
#endif

#define pfn_valid(pfn)		((pfn) >= ARCH_PFN_OFFSET && ((pfn) - ARCH_PFN_OFFSET) < max_mapnr)
#ifdef CONFIG_DISCONTIGMEM
# error CONFIG_DISCONTIGMEM not supported
#endif

#define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)
#define page_to_virt(page)	__va(page_to_pfn(page) << PAGE_SHIFT)
#define virt_addr_valid(kaddr)	pfn_valid(__pa(kaddr) >> PAGE_SHIFT)
#define page_to_phys(page)	(page_to_pfn(page) << PAGE_SHIFT)

#ifdef CONFIG_MMU
/* 
 * Enable non-HIGHMEM kernel address of pages to be stored in page->virtual.  
 * For HIGHMEM pages the kernel virtual address is calculated dynamically.
 * See for example update_mmu_cache().
 */
#define WANT_PAGE_VIRTUAL	
#endif

#endif /* __ASSEMBLY__ */

#define VM_DATA_DEFAULT_FLAGS	(VM_READ | VM_WRITE | VM_EXEC | \
				 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)

#include <asm-generic/memory_model.h>
#endif /* _XTENSA_PAGE_H */
