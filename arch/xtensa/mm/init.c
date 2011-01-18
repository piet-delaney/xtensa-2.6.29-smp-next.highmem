/*
 * arch/xtensa/mm/init.c
 *
 * Derived from MIPS, PPC.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2001 - 2009 Tensilica Inc.
 *
 * Chris Zankel	<chris@zankel.net>
 * Joe Taylor	<joe@tensilica.com>
 * Marc Gauthier <marc@tensilica.com>
 * Pete Delaney <piet@tensilica.com>
 * Johannes Weiner <jw@emlix.com>
 * Kevin Chea
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/bootmem.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/nodemask.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include <asm/bootparam.h>
#include <asm/page.h>
#include <asm/setup.h>

#ifdef __XCC__
/*
 * Functions that gcc optimizes away but has extern statements for.
 * XCC doesn't optimize them away via the GCC frontend; sigh.
 */
void __attribute__ ((weak)) __get_user_bad(void) 			{ panic(__func__); }
void __attribute__ ((weak)) __put_user_bad(void) 			{ panic(__func__); }
void __attribute__ ((weak)) _NSIG_WORDS_is_unsupported_size(void) 	{ panic(__func__); }
void __attribute__ ((weak)) __bad_unaligned_access_size(void) 		{ panic(__func__); }

int __attribute__ ((weak)) verify_compat_iovec(void)			{ panic(__func__); }
int __attribute__ ((weak)) cmsghdr_from_user_compat_to_kern(void)	{ panic(__func__); }
int __attribute__ ((weak)) get_compat_msghdr(void)			{ panic(__func__); }
int __attribute__ ((weak)) put_cmsg_compat(void)			{ panic(__func__); }
int __attribute__ ((weak)) scm_detach_fds_compat(void)			{ panic(__func__); }
int __attribute__ ((weak)) cookie_v4_init_sequence(void)		{ panic(__func__); }
#endif

/* References to section boundaries */

extern char _ftext, _etext, _fdata, _edata, _rodata_end;
extern char __init_begin, __init_end;

/*
 * mem_reserve(start, end, must_exist)
 *
 * Reserve some memory from the memory pool.
 *
 * Parameters:
 *  start	Start of region,
 *  end		End of region,
 *  must_exist	Must exist in memory pool.
 *
 * Returns:
 *  0 (memory area couldn't be mapped)
 * -1 (success)
 */

int __init mem_reserve(unsigned long start, unsigned long end, int must_exist)
{
	int i;

	if (start == end)
		return 0;

	start = start & PAGE_MASK;
	end = PAGE_ALIGN(end);

	for (i = 0; i < sysmem.nr_banks; i++)
		if (start < sysmem.bank[i].end
		    && end >= sysmem.bank[i].start)
			break;

	if (i == sysmem.nr_banks) {
		if (must_exist)
			printk (KERN_WARNING "mem_reserve: [0x%0lx, 0x%0lx) "
				"not in any region!\n", start, end);
		return 0;
	}

	if (start > sysmem.bank[i].start) {
		if (end < sysmem.bank[i].end) {
			/* split entry */
			if (sysmem.nr_banks >= SYSMEM_BANKS_MAX)
				panic("meminfo overflow\n");
			sysmem.bank[sysmem.nr_banks].start = end;
			sysmem.bank[sysmem.nr_banks].end = sysmem.bank[i].end;
			sysmem.nr_banks++;
		}
		sysmem.bank[i].end = start;
	} else {
		if (end < sysmem.bank[i].end)
			sysmem.bank[i].start = end;
		else {
			/* remove entry */
			sysmem.nr_banks--;
			sysmem.bank[i].start = sysmem.bank[sysmem.nr_banks].start;
			sysmem.bank[i].end   = sysmem.bank[sysmem.nr_banks].end;
		}
	}
	return -1;
}


/*
 * Initialize the bootmem system and give it all the memory we have available.
 *
 *                               <-- ZONE NORMAL -->
 *                <-- ZONE DMA -->                  <-- Zone HIGHMEM -->
 *   +---------+--+---------------+-----------------+------------------+
 *   |         |  |               :                 |                  |
 *   |         |  |      RAM      : EXTENDED MEMORY |     HIGHMEM      |
 *   |         |  |               :                 |                  |
 *   +---------+--+---------------+-----------------+------------------+
 *   |         |  |               |                 |                  |
 *   +- PFN 0  |  +- min_low_pfn  |                 +- max_low_pfn     +- max_pfn
 *             |                  +- PLATFORM_DEFAULT_MEM_SIZE
 *             +- ARCH_PFN_OFFSET
 *             +- PLATFORM_DEFAULT_MEM_START >> PAGE_SIZE
 *
 * Note that the extended memory is mapped below the 'regular' memory in
 * virtual space.
 *
 * FIXME:
 *   Need to investigate if we should always reserve PFN 0, so we won't allocate
 *   contiguous memory across the 'regular'/extended memory boundary.
 */

void __init bootmem_init(void)
{
	unsigned long pfn;
	unsigned long bootmap_start, bootmap_size;
	int i;

	max_low_pfn = max_pfn = 0;
	min_low_pfn = ~0;

	for (i = 0; i < sysmem.nr_banks; i++) {
		printk("%s: sysmem.bank[i:%d].{type:%lx, start:0x%lx, end:0x%lx}\n", __func__, i,
			    sysmem.bank[i].type, 
			    sysmem.bank[i].start, 
			    sysmem.bank[i].end);

		pfn = PAGE_ALIGN(sysmem.bank[i].start) >> PAGE_SHIFT;
		if (pfn < min_low_pfn)
			min_low_pfn = pfn;
		pfn = PAGE_ALIGN(sysmem.bank[i].end - 1) >> PAGE_SHIFT;
		if (pfn > max_pfn)
			max_pfn = pfn;
	}

	if (min_low_pfn > max_pfn)
		panic("No memory found!\n");

	max_low_pfn = max_pfn < (MAX_MEM_PFN >> PAGE_SHIFT) ?
		max_pfn : MAX_MEM_PFN >> PAGE_SHIFT;

	printk("%s: min_low_pfn:0x%lx, max_low_pfn:0x%lx, max_pfn:0x%lx\n", __func__,
		    min_low_pfn,       max_low_pfn,       max_pfn);

	/* Find an area to use for the bootmem bitmap. */

	bootmap_size = bootmem_bootmap_pages(max_low_pfn - min_low_pfn);
	bootmap_size <<= PAGE_SHIFT;
	bootmap_start = ~0;

	for (i = 0; i < sysmem.nr_banks; i++)
		if (sysmem.bank[i].end - sysmem.bank[i].start >= bootmap_size) {
			bootmap_start = sysmem.bank[i].start;
			break;
		}

	if (bootmap_start == ~0UL)
		panic("Cannot find %ld bytes for bootmap\n", bootmap_size);

	/* Reserve the bootmem bitmap area */

	mem_reserve(bootmap_start, bootmap_start + bootmap_size, 1);
	bootmap_size = init_bootmem_node(NODE_DATA(0),
					 bootmap_start >> PAGE_SHIFT,
					 min_low_pfn,
					 max_low_pfn);

	/* Add all remaining memory pieces into the bootmem map */

	for (i = 0; i < sysmem.nr_banks; i++)
		free_bootmem(sysmem.bank[i].start,
			     sysmem.bank[i].end - sysmem.bank[i].start);
}


void __init zones_init(void)
{
	unsigned long zones_size[MAX_NR_ZONES];
	int i;

	for (i = 0; i < MAX_NR_ZONES; i++)
		zones_size[i] = 0;

#ifdef CONFIG_EXTENDED_MEMORY
	/* Set up a DMA zone if we have more than XCHAL_KSEG_SIZE phys. memory. */
	if (max_low_pfn > (XCHAL_KSEG_SIZE >> PAGE_SHIFT) - ARCH_PFN_OFFSET)
		zones_size[ZONE_DMA] = (PLATFORM_DEFAULT_MEM_SIZE >> PAGE_SHIFT)
					- ARCH_PFN_OFFSET;

	zones_size[ZONE_NORMAL] = (max_low_pfn - ARCH_PFN_OFFSET) 
				  - zones_size[ZONE_DMA];
#else
	// FIXME: Disable zone-dma when we don't need it
	zones_size[ZONE_DMA] = max_low_pfn - ARCH_PFN_OFFSET;
#endif

#ifdef CONFIG_HIGHMEM
	zones_size[ZONE_HIGHMEM] = max_pfn - max_low_pfn;
#endif

	free_area_init_node(0, zones_size, ARCH_PFN_OFFSET, NULL);
}

/*
 * Initialize memory pages.
 */

void __init mem_init(void)
{
	unsigned long codesize, reservedpages, datasize, initsize;
	unsigned long highmemsize, tmp, ram;

	max_mapnr = num_physpages = max_low_pfn - ARCH_PFN_OFFSET;
	high_memory = (void *) __va(max_low_pfn << PAGE_SHIFT);
	highmemsize = 0;

#ifdef CONFIG_HIGHMEM
#error HIGHGMEM not implemented in init.c
#endif

	totalram_pages += free_all_bootmem();

	reservedpages = ram = 0;
	for (tmp = 0; tmp < max_mapnr; tmp++) {
		ram++;
		if (PageReserved(mem_map+tmp))
			reservedpages++;
	}

	codesize =  (unsigned long) &_etext - (unsigned long) &_ftext;
	datasize =  (unsigned long) &_edata - (unsigned long) &_fdata;
	initsize =  (unsigned long) &__init_end - (unsigned long) &__init_begin;

	printk("Memory: %luk/%luk available (%ldk kernel code, %ldk reserved, "
	       "%ldk data, %ldk init %ldk highmem)\n",
	       (unsigned long) nr_free_pages() << (PAGE_SHIFT-10),
	       ram << (PAGE_SHIFT-10),
	       codesize >> 10,
	       reservedpages << (PAGE_SHIFT-10),
	       datasize >> 10,
	       initsize >> 10,
	       highmemsize >> 10);
}

void
free_reserved_mem(void *start, void *end)
{
	for (; start < end; start += PAGE_SIZE) {
		ClearPageReserved(virt_to_page(start));
		init_page_count(virt_to_page(start));
		free_page((unsigned long)start);
		totalram_pages++;
	}
}

#ifdef CONFIG_BLK_DEV_INITRD
extern int initrd_is_mapped;

void free_initrd_mem(unsigned long start, unsigned long end)
{
	if (initrd_is_mapped) {
		free_reserved_mem((void*)start, (void*)end);
		printk ("Freeing initrd memory: %ldk freed\n",(end-start)>>10);
	}
}
#endif

/*
 * This can be patched by xt-gdb while placing 
 * breakpoints in init code that would normally
 * be made free.
 */
volatile int  skip_free_of_initmem = 0;

void free_initmem(void)
{
	if (skip_free_of_initmem) {
		printk("%s: Skip Freeing of init memory; avoiding issues with breakpoints.\n", __func__);
	} else {
		printk("%s: Freeing unused/init kernel memory: ...", __func__);

		free_reserved_mem(&__init_begin, &__init_end);

		printk(" %dk freed\n", (&__init_end - &__init_begin) >> 10); 
	}
}
