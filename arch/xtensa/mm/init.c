/*
 * arch/xtensa/mm/init.c
 *
 * Derived from MIPS, PPC.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2001 - 2011 Tensilica Inc.
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
 * Enable MEM_INIT Debug Here, with .xt-gdbinit file, or via CONFIG_CMDLINE. 
 * Ex:
 *     CONFIG_CMDLINE="console=ttyS0 ... bootmem_debug mem_init_debug"
 */
static int mem_init_debug = 1;

static int __init mem_init_debug_setup(char *buf)
{
	mem_init_debug = 1;
        return 0;
}

/* Set in CONFIG_CMDLINE, Ex: mem_init_debug=1 */
early_param("mem_init_debug", mem_init_debug_setup);

#define dprintf(fmt, args...) ({                        \
        if (unlikely(mem_init_debug))                   \
                printk(KERN_INFO                        \
                        "MemInit::%s " fmt,             \
                        __func__, ## args);             \
})

/*
 * mem_reserve(start, end, must_exist)
 *
 * Reserve some memory from the memory pool.
 * Used for example to reserve the memory used by exception vectors.
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

	dprintf("(start:0X%lx, end:0X%lx, must_exist:%d)\n",
		  start,       end,       must_exist);


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
			printk (KERN_WARNING "MEM_INIT::mem_reserve: [0x%0lx, 0x%0lx) "
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
 *             |<--- ZONE DMA --->|<--ZONE NORMAL-->||<--Zone HIGHMEM--> |
 *   +---------+--+---------------+-----------------++-------------------+
 *   |         |  |               :                 ||                   |
 *   |         |  |      RAM      : EXTENDED MEMORY ||    HIGHMEM        |
 *   |         |  |               :                 ||                   |
 *   +---------+--+---------------+-----------------++-------------------+
 *   |         |  |               |                 ||                   |
 *   |         |  |               |                 |+- max_low_pfn + 1  |
 *   +- PFN 0  |  +- min_low_pfn  |                 +- max_low_pfn       +- max_pfn
 *             |                  +- XCHAL_KSEG_SIZE
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

long reserved_pages = 0;

void __init bootmem_init(void)
{
	unsigned long pfn;
	unsigned long total_pfns = 0;
	unsigned long type;
	unsigned long start;
	unsigned long end;
	unsigned long bootmap_start, bootmap_size, bootmap_pages;
	int i;

	max_low_pfn = max_pfn = 0;
	min_low_pfn = ~0;

	for (i = 0; i < sysmem.nr_banks; i++) {
		type = sysmem.bank[i].type;
		start = sysmem.bank[i].start;
		end = sysmem.bank[i].end;

		dprintf("sysmem.bank[i:%d].{type:%lx, start:0x%08lx, end:0x%08lx}\n",
			             i,     type,     start,        end); 

		pfn = PAGE_ALIGN(start) >> PAGE_SHIFT;
		if (pfn < min_low_pfn)
			min_low_pfn = pfn;
		pfn = (PAGE_ALIGN(end - 1) >> PAGE_SHIFT);
		if (pfn > max_pfn)
			max_pfn = pfn;

		dprintf("total_pfns:%lu += ((end:0X%lx - start:0X%lx):0X%lx:%lu >> PAGESHIFT):0X%lx:%lu\n",
	            	 total_pfns,         end,        start, 
			 	            (end - start), (end - start),
					   ((end - start) >> PAGE_SHIFT),
					   ((end - start) >> PAGE_SHIFT) );

		total_pfns += ((end - start)  >> PAGE_SHIFT);
	}

	if (min_low_pfn > max_pfn)
		panic("No memory found!\n");

	max_low_pfn = max_pfn < (MAX_MEM_PFN >> PAGE_SHIFT) ?
		max_pfn : MAX_MEM_PFN >> PAGE_SHIFT;

	reserved_pages = (max_pfn - min_low_pfn) - total_pfns;
	BUG_ON(reserved_pages < 0);

	dprintf("reserved_pages = %ld = (max_low_pfn:0x%lx - min_low_pfn:0x%lx):0x%lx:%lu - total_pfns:%lu;\n",
		 reserved_pages,         max_low_pfn,        min_low_pfn,   
			                (max_low_pfn - min_low_pfn),                        
				        (max_low_pfn - min_low_pfn),                        total_pfns);

	dprintf("min_low_pfn:0x%lx, max_low_pfn:0x%lx, max_pfn:0x%lx\n",
		 min_low_pfn,       max_low_pfn,       max_pfn);

	/* Find an area to use for the bootmem bitmap. */

	bootmap_pages = bootmem_bootmap_pages(max_pfn - min_low_pfn);		/* Memory Bitmap includes HighMem */
	bootmap_size = bootmap_pages << PAGE_SHIFT;
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

	dprintf("reserved_pages:%ld += bootmap_pages:%lu;\n",
		 reserved_pages,       bootmap_pages);

	reserved_pages += bootmap_pages;

	bootmap_size = init_bootmem_node(NODE_DATA(0),
					 bootmap_start >> PAGE_SHIFT,
					 min_low_pfn,
					 max_pfn);

	/* Add all remaining memory pieces into the bootmem map */

	for (i = 0; i < sysmem.nr_banks; i++)
		free_bootmem(sysmem.bank[i].start,
			     sysmem.bank[i].end - sysmem.bank[i].start);
}


/*
 * Called during setup_arch()
 */
void __init zones_init(void)
{
	unsigned long zones_size[MAX_NR_ZONES];
	unsigned long zones_hole[MAX_NR_ZONES];

	memset(zones_size, 0, sizeof(zones_size));
	memset(zones_hole, 0, sizeof(zones_hole));

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

	dprintf("zones_size[ZONE_DMA]     = %ld\n",  zones_size[ZONE_DMA]);
	dprintf("zones_size[ZONE_NORMAL]  = %ld\n",  zones_size[ZONE_NORMAL]);

#ifdef CONFIG_HIGHMEM
	zones_size[ZONE_HIGHMEM] = max_pfn - max_low_pfn;

	dprintf("zones_size[ZONE_HIGHMEM] = %ld\n",  zones_size[ZONE_HIGHMEM]);
#endif
	/* 
 	 * Removed any pages starting from ARCH_PFN_OFFSET that weren't entered into the bootmem.
 	 * 'reserved_pages' is the total of pages that were reserved from going into the bootmem bitmap.
 	 */
	zones_hole[ZONE_DMA] = reserved_pages + (min_low_pfn - ARCH_PFN_OFFSET);

	dprintf("zones_hole[ZONE_DMA]     = %ld;   reserved_pages:%ld\n",  
	         zones_hole[ZONE_DMA],             reserved_pages);

	/*
	 * Initializes mem_map page table. The call to free_area_init_node() below
	 * Ends up calling free_area_init_core() [free_all_bootmem()]
	 * which puts ALL of memory onto the zone page freelists. 
	 *
	 * mem_map[] will be set to contig_page_data->node_mem_map. 
	 * This zone information will be used to calculate important 
	 * contig_page_data structure constants:
	 *
	 * 	contig_page_data.node_spanned_pages;		// ALl Zone pages in the zones 
	 *	contig_page_data.node_present_pages;		// All Zine pages less Zone holes
	 *
	 * Because CONFIG_FLAT_NODE_MEM_MAP is defined, alloc_node_mem_map() will allocate
	 * space for an array of struct page the size of all zone pages (node_spanned_pages).
	 *
	 * Each zone will have it's array of pages, mem_map, initialized with the
	 * pages marked as reserved:
	 * 	zones_init()
	 * 	    free_area_init_node()
	 * 	        free_area_init_core()
	 * 	            memmap_init_zone()
	 *
	 * If WANT_PAGE_VIRTUAL has been selected each page->virtual will be set with
	 * it's virtual address via the __va() function; which interestingly are NOT 
	 * correct for ZONE_HIGHMEM. 
	 *
	 * After returning each HIGHMEM page will be set with non-NULL values of:
	 *
	 * 	flags = 0x80000400, 
	 * 	_count.counter = 0x1,
	 * 	_mapcount.counter = 0xffffffff.
	 * 	inuse = 0xffff, 
	 * 	objects = 0xffff
	 */
	free_area_init_node(0, zones_size, ARCH_PFN_OFFSET, zones_hole);
}

typedef struct page  page_dir[0x10000];
static page_dir *xtemsa_mem_map;

/*
 * Initialize memory pages.
 * Called during general kernel startup, much later that setup_arch().
 * By the time this is called the above call to free_area_init() has
 * already allocated the mem_map[].
 */
void __init mem_init(void)
{
	unsigned long codesize, reservedpages, datasize, initsize;
	unsigned long highmem_size, tmp, ram;
	xtemsa_mem_map = (page_dir *) mem_map;

#if defined(CONFIG_HIGHMEM)
	/* 
 	 * Most ARCH's set max_mapnr to the end of HIGHMEM.
 	 *
 	 * NOTE: 
 	 *    Used by pfn_valid(), for example, in update_mmu_cache().
 	 */
	max_mapnr = num_physpages = max_pfn - ARCH_PFN_OFFSET;
#else
	max_mapnr = num_physpages = max_low_pfn - ARCH_PFN_OFFSET;
#endif

	high_memory = (void *) __va(max_low_pfn << PAGE_SHIFT);		/* Begininig of HIGHMEM */
	highmem_size = (max_pfn - max_low_pfn) * PAGE_SIZE;

	/* This will put all memory onto the zone freelists */
	totalram_pages += free_all_bootmem();

	/*
	 * Find out how many pages are currently reserved so
	 * we can print it out in Memory summary.
	 */ 
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
	       "%ldk data, %ldk init, %ldk highmem)\n",
	       (unsigned long) nr_free_pages() << (PAGE_SHIFT-10),
	       ram << (PAGE_SHIFT-10),
	       codesize >> 10,
	       reservedpages << (PAGE_SHIFT-10),
	       datasize >> 10,
	       initsize >> 10,
	       highmem_size >> 10);
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
 *
 * REMIND:
 * 	Skip freeing init memory until:
 *
 * 		 make CONFIG_DEBUG_SECTION_MISMATCH=y
 *
 *	compile the kernel without any non__init reference to 
 *	__init code/data.
 */
volatile int  skip_free_of_initmem = 1;

void free_initmem(void)
{
	if (skip_free_of_initmem) {
		printk("%s: Skip Freeing of %dk of __init memory; avoiding issues with breakpoints and ...\n", __func__,
		                              (&__init_end - &__init_begin) >> 10);

		printk("%s: ... __init Problems, mentioned by 'make CONFIG_DEBUG_SECTION_MISMATCH=y', have been fixed\n", __func__);
	} else {
		printk("%s: Freeing unused/init kernel memory: ...", __func__);

		free_reserved_mem(&__init_begin, &__init_end);

		printk(" %dk freed\n", (&__init_end - &__init_begin) >> 10); 
	}
}
