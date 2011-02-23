/*
 * arch/xtensa/mm/mmu.c"
 *
 * Some of Xtensa's strictly mmu related stuff.
 *
 * This MMU code was originally extracted from arch/xtensa/mm/init.c by Johannes 
 * Weiner to support MMU-less (uClinux) kernels and then further derived from MIPS
 * and X86 by Pete Delaney to support HIGHMEM. Werner set up the mm/Makefile to
 * always compile the early physical memory initialization code in mm/init.c but 
 * to only compile the MMU related code that's here if CONFIG_MMU was selected. 
 * This makes it possible to compile Xtensa-Linux on very small embedded systems 
 * configured without an MMU.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2001 - 2011 Tensilica Inc.
 *
 * Pete Delaney <piet@tensilica.com>
 * Chris Zankel <chris@zankel.net
 * Johannes Weiner <jw@emlix.com>
 * Joe Taylor   <joe@tensilica.com>
 */
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/cache.h>

#include <linux/highmem.h>
#include <linux/bootmem.h>

#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <asm/page.h>

#include <asm/fixmap.h>


DEFINE_PER_CPU(struct mmu_gather, mmu_gathers);

#ifdef CONFIG_HIGHMEM

extern int highmem_debug;

#define hm_dprintf(fmt, args...) ({                     \
        if (unlikely(highmem_debug))                    \
                printk(KERN_INFO                        \
                        "HighMem::%s " fmt,             \
                        __func__, ## args);             \
})


pte_dir_t pkmap_page_dir  __attribute__((aligned(PAGE_SIZE)));

/*
 * This initializes one Page Middle Directory,
 * which spans 1024 Pages or 4MegBytes of kernel
 * virtual address space; which is 0x40,0000 bytes.
 *
 * HIGHMEM-REMIND: Remove remaining DEBUG code.
 */
static void __init permanent_kmaps_init(pgd_t *pgd_base)
{
	unsigned long base_vaddr, top_vaddr;
	pgd_t *base_pgdp, *top_pgdp;
	pud_t *base_pudp, *top_pudp;
	pmd_t *base_pmdp, *top_pmdp;
	pte_t *base_ptep, *top_ptep;
	pte_t *pte;
	unsigned long vaddr;
	int i;

	static pgd_table_t *kmap_pgd_dir;
	static pud_table_t *kmap_pud_dir;
	static pmd_table_t *kmap_pmd_dir;
	static pte_table_t *base_pte_dir;
	static pte_table_t *top_pte_dir;
	static int pkmap_base_index;
	static int pkmap_top_index;

	base_vaddr = PKMAP_BASE;
	top_vaddr = FIXADDR_TOP - PAGE_SIZE;

#if 0	
	/* Better, less wastefull */
	pkmap_page_table = alloc_bootmem_pages(1);
	pkmap_page_dir = (pte_table_t *) pkmap_page_table;
#else
	/* Easier while debugging */
	pkmap_page_table = &pkmap_page_dir[0];
	memset(&pkmap_page_dir[0], 0, sizeof(pkmap_page_dir));
#endif

	pkmap_base_index = pgd_index(base_vaddr);
	pkmap_top_index  = pgd_index(top_vaddr);

	base_pgdp = &swapper_pg_dir[pkmap_base_index];
	top_pgdp =  &swapper_pg_dir[pkmap_top_index];


	base_pudp = pud_offset(base_pgdp, base_vaddr);
	top_pudp =  pud_offset(top_pgdp,  top_vaddr);

	base_pmdp = pmd_offset(base_pudp, base_vaddr);
	top_pmdp =  pmd_offset(top_pudp, top_vaddr);

	kmap_pgd_dir = (pgd_table_t *) base_pgdp;
	kmap_pud_dir = (pud_table_t *) base_pudp;
	kmap_pmd_dir = (pmd_table_t *) base_pmdp;

	/*  
   	 * Xtensa PMD entries are Virtual pointers to pte tables, ie: VPN and not a PPN.
   	 * Unused bits are zero, so VPN can also be used as a pointer to the pte table.
   	 */
	set_pmd(base_pmdp, __pmd(((unsigned long) pkmap_page_table) ));

	base_ptep = pte_offset_kernel(base_pmdp, base_vaddr);
	base_pte_dir = (pte_table_t *) base_ptep;

	top_ptep = pte_offset_kernel(top_pmdp, top_vaddr);
	top_pte_dir = (pte_table_t *) top_ptep;

	hm_dprintf("base_pmdp:0x%p, base_ptep:0x%p, &pkmap_page_dir[0]:0x%p\n",
	            base_pmdp,      base_ptep,      &pkmap_page_dir[0]);

	hm_dprintf(" top_pmdp:0x%p,  top_ptep:0x%p, &pkmap_page_dir[PTRS_PER_PTE:%d - 1]:0x%p\n",
		     top_pmdp,       top_ptep,      PTRS_PER_PTE, &pkmap_page_dir[PTRS_PER_PTE - 1]);

	/*
	 * Initialize KMAP PTE's
	 */
	vaddr = 0;
	for(i = 0; i < PTRS_PER_PTE; i++) {
		pte = &pkmap_page_table[i];
		pte_clear(&init_mm, vaddr, pte);	/* set pte as having no mapping */
	}
		
}

#else /* !CONFIG_HIGHMEM */

static inline void x86_permanent_kmaps_init(pgd_t *pgd_base)
{
}

static inline void permanent_kmaps_init(pgd_t *pgd_base)
{
}

#endif /* CONFIG_HIGHMEM */

static void __init pagetable_init(void)
{
	pgd_t *pgd_base = swapper_pg_dir;

	/* 
 	 * Initialize all pgd entries as not being Present:
 	 *    attr:bypass, ring:kern, present:0 
 	 */
	memset(swapper_pg_dir, 0, PAGE_SIZE);

	permanent_kmaps_init(pgd_base);
}

#ifdef CONFIG_HIGHMEM
pgprot_t kmap_prot;
pte_t *kmap_pte;

static inline pte_t *kmap_get_fixmap_pte(unsigned long vaddr)
{
#if 1
	/* DEBUG VERSION */
	pgd_t *pgd = pgd_offset_k(vaddr);
	pud_t *pud = pud_offset(pgd, vaddr);
	pmd_t *pmd = pmd_offset(pud, vaddr);
	pte_t *pte = pte_offset_kernel(pmd, vaddr);
#else
	pte = pte_offset_kernel(pmd_offset(pud_offset(pgd_offset_k(vaddr), vaddr), vaddr), vaddr);
#endif
	return(pte);
}

static void __init kmap_init(void)
{
	unsigned long kmap_vstart;

	/*
	 * Cache the first kmap pte:
	 */
	kmap_vstart = __fix_to_virt(FIX_KMAP_BEGIN);
	kmap_pte = kmap_get_fixmap_pte(kmap_vstart);

	hm_dprintf("kmap_vstart = 0X%lx, kmap_pte = %p\n",
		    kmap_vstart,         kmap_pte);

	kmap_prot = PAGE_KERNEL;
}
#else
static void __init kmap_init(void)
{
}
#endif

void __init paging_init(void)
{
	pagetable_init();

	kmap_init();
}

/*
 * Flush the mmu and reset associated register to default values.
 */
void __init init_mmu(void)
{
#if XCHAL_HAVE_PTP_MMU && XCHAL_HAVE_SPANNING_WAY
	/* 
	 * We have a V3 MMU, the TLB was initialized with  virtual == physical 
	 * mappings on a hardware reset. This was done by the hardware by 
	 * presetting idenity mapping in Way 6:
	 *
         *  vaddr=0x00000000 asid=0x01  paddr=0x00000000  ca=3  ITLB way 6 (512 MB)
         *  vaddr=0x20000000 asid=0x01  paddr=0x20000000  ca=3  ITLB way 6 (512 MB)
         *  vaddr=0x40000000 asid=0x01  paddr=0x40000000  ca=3  ITLB way 6 (512 MB)
         *  vaddr=0x60000000 asid=0x01  paddr=0x60000000  ca=3  ITLB way 6 (512 MB)
         *  vaddr=0x80000000 asid=0x01  paddr=0x80000000  ca=3  ITLB way 6 (512 MB)
         *  vaddr=0xa0000000 asid=0x01  paddr=0xa0000000  ca=3  ITLB way 6 (512 MB)
         *  vaddr=0xc0000000 asid=0x01  paddr=0xc0000000  ca=3  ITLB way 6 (512 MB)
         *  vaddr=0xe0000000 asid=0x01  paddr=0xe0000000  ca=4  ITLB way 6 (512 MB)
	 * 
	 * For the Primary CPU The reset vector code or _start code in head.S 
	 * remapped KSEG (0xD000000) to map physical memory in way 5 and changed 
	 * the page size to in way 6 to 256 MB by setting the TLB config register, 
	 * It removed the (virtual == physical) mappings by setting the ASID fields 
	 * to zero in way 6 and set up the KIO mappings; Un-Cached at 0xF0000000 
	 * and Cached at 0xE000000.
	 *
	 * Way 5
	 *   vaddr=0x40000000 asid=0x00  paddr=0xf8000000  ca=3  ITLB way 5 (128 MB)
	 *   vaddr=0x08000000 asid=0x00  paddr=0x00000000  ca=0  ITLB way 5 (128 MB)
	 *   vaddr=0xd0000000 asid=0x01  paddr=0x00000000  ca=7  ITLB way 5 (128 MB)
	 *   vaddr=0xd8000000 asid=0x01  paddr=0x00000000  ca=3  ITLB way 5 (128 MB)
	 *
	 * Way 6
	 *   vaddr=0x00000000 asid=0x00  paddr=0x00000000  ca=3  ITLB way 6 (256 MB)
	 *   vaddr=0x10000000 asid=0x00  paddr=0x20000000  ca=3  ITLB way 6 (256 MB)
	 *   vaddr=0x20000000 asid=0x00  paddr=0x40000000  ca=3  ITLB way 6 (256 MB)
	 *   vaddr=0x30000000 asid=0x00  paddr=0x60000000  ca=3  ITLB way 6 (256 MB)
	 *   vaddr=0x40000000 asid=0x00  paddr=0x80000000  ca=3  ITLB way 6 (256 MB)
	 *   vaddr=0x50000000 asid=0x00  paddr=0xa0000000  ca=3  ITLB way 6 (256 MB)
	 *   vaddr=0xe0000000 asid=0x01  paddr=0xf0000000  ca=7  ITLB way 6 (256 MB)
	 *   vaddr=0xf0000000 asid=0x01  paddr=0xf0000000  ca=3  ITLB way 6 (256 MB)
	 * 
	 *   See arch/xtensa/boot/boot-elf/bootstrap for details.
	 */
#else
	/* 
	 * Writing zeros to the instruction and data TLBCFG special 
	 * registers ensure that valid values exist in the register.  
	 *
	 * For existing PGSZID<w> fields, zero selects the first element 
	 * of the page-size array.  For nonexistent PGSZID<w> fields, 
	 * zero is the best value to write.  Also, when changing PGSZID<w>
	 * fields, the corresponding TLB must be flushed.
	 */
	set_itlbcfg_register(0);
	set_dtlbcfg_register(0);
#endif

	local_flush_tlb_all();	/* Flush the Auto-Refill TLB Ways (0...3) */

	/* Set rasid register to a known value. */

	set_rasid_register(ASID_INSERT(ASID_USER_FIRST));

	/* 
 	 * Set $PTEVADDR special register to the start of the page
	 * table, which is in kernel mappable space (ie. not
	 * statically mapped).  This register's value is undefined on
	 * reset.
	 *
	 * fast_second_level_miss() in entry.S will load ways
	 * 7, 8, and 9 with Page Global Directory (PGD) Entrys. 
	 *
	 * This is seen easily with dtshow use-defined gdb macro defined
	 * in the Documentation/xtensa/gdbmacros/showtlb.gdb file:
	 *
	 *   vaddr=0x80001000 asid=0x01  paddr=0x07cbe000  ca=0  DTLB way 7 
	 *   vaddr=0x80080000 asid=0x01  paddr=0x07c40000  ca=0  DTLB way 8
	 *   vaddr=0x800fe000 asid=0x01  paddr=0x07c60000  ca=0  DTLB way 9 
	 *
	 *   The paddr's loaded into the TLB entries are the physical
	 *   addresses of the PGD's pointed to by $current->mm.mm_pgd.
	 */
	set_ptevaddr_register(PGTABLE_START);
}

struct kmem_cache *pgtable_cache __read_mostly;

/*
 * Constructor to initializing a page global directory (pgd).
 * Called by slab allocator for allocations from the page
 * table cache which is initialized below.
 */
static void pgd_ctor(void *addr)
{
	pte_t *ptep = (pte_t *)addr;
	int i;

	for (i = 0; i < 1024; i++, ptep++)
		pte_clear(NULL, 0, ptep);
}

/*
 * Initialize slab cache from which page tables of PTEs 
 * can be allocated dynamically.
 *
 * Called by start_kernel well into startup. 
 */
void __init pgtable_cache_init(void)
{
	pgtable_cache = kmem_cache_create("pgd",
			PAGE_SIZE, PAGE_SIZE,
			SLAB_HWCACHE_ALIGN,
			pgd_ctor);
}
