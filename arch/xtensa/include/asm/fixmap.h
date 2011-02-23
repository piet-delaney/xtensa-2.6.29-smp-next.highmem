/*
 * fixmap.h: compile-time virtual memory allocation
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1998 Ingo Molnar
 * Copyright (C) 2011 Pete Delaney
 * Copyright (C) 2011 Tensilica Inc.
 *
 * Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *
 * Initially derived from mips implementation.
 */

#ifndef _ASM_XTENSA_FIXMAP
#define _ASM_XTENSA_FIXMAP

#include <asm/page.h>
#ifdef CONFIG_HIGHMEM
#include <linux/threads.h>
#include <asm/kmap_types.h>
#endif

extern pte_t *kmap_pte;
extern pgprot_t kmap_prot;

/*
 * Here we define all the compile-time 'special' virtual
 * addresses. The point is to have a constant address at
 * compile time, but to set the physical address only
 * in the boot process. With the V2 MMU we allocate these 
 * special addresses from the end of virtual memory currenty being
 * used (0xB000F000) backwards.
 *
 * Also this lets us do fail-safe (?) vmalloc(), we
 * can guarantee that these special addresses and
 * vmalloc()-ed addresses never overlap.
 *
 * These 'compile-time allocated' memory buffers are
 * fixed-size 4k pages. (or larger if used with an increment
 * highger than 1) use fixmap_set(idx,phys) to associate
 * physical memory with fixmap indices.
 *
 * TLB entries of such buffers will not be flushed across
 * task switches.
 */

/* HIGHMEM-REMIND:
 * On UP currently we will have no trace of the fixmap mechanizm,
 * no page table allocations, etc. This might change in the
 * future, say framebuffers for the console driver(s) could be
 * fix-mapped?
 */
enum fixed_addresses {
	FIX_HOLE,		/* NOT MAPPED */
#ifdef CONFIG_HIGHMEM
	/* reserved pte's for temporary kernel mappings */
	FIX_KMAP_BEGIN,
	FIX_KMAP_END = FIX_KMAP_BEGIN+(KM_TYPE_NR*NR_CPUS)-1,
#endif
	__end_of_fixed_addresses
};

/*
 *                                           Xtensa V2 MMU        
 *                             4 Giga Byte Kernel Virtual Address Space (KAS)
 *
 *                 0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
 *                 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+        16
 *                 |       |   |   | U N U S E D   |   |  UNUSED   |   |   |   |   | 256 MegByte SEGMENTS.
 *                 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+  64 PGD Entries
 *                 |       |   |   |               |   |           ^   ^   ^   ^      per Segment
 *                 |      /|  /|  /                ^\ /            |   |   |   |
 *                  \    /  \/  \/                 | v             |   |   |   |
 *                   \  /    |   |  PGTABLE_START -+ |             |   |   |   |
 *                    \/     |   |                   Page Table    |   |   |   +---- KIO: Bypass
 *                    |      |   +--- Program Stack                |   |   |
 *                    |      |        Grows down from 0X3fa8,C000  |   |   +-------- KIO: Cached
 *                    |      |        pgd_table[192...255]         |   |
 *                    |      |                                     |   |
 *                    |      +--- MMAP stuff: Shared Libraries     |   +--- KSEG: Cached: 0xc0000,0000 ... 0xc7fff,ffff
 *                    |                       Heap via malloc()    |              Bypass: 0xf8000,0000 ... 0xc8fff,ffff
 *                    |           pgd_table[128...191]             |
 *                    |                                            ^
 *               USER SPACE                                      /   \
 *                PROGRAM               c0  c1  c2  c3  c4  c5  c6  c7  c8  c9  ca  cb  cc  cd  ce  cf
 *                  512                +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *                MegBytes             |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
 *            128 PGD Entries          +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *           pgd_table[0...127]        ^                           ^^^^^                               ^
 *                                     |                           |||||                               |
 *                                     |<--------- VMALLOC ------->|||||<-- EXTENDED (KERNEL) MEMORY ->|
 *                                     |                            |||            128 Mbytes
 *                                     +-VMALLOC_START VMALLOC_END->|||         32 PGD Entries
 *                                         0xC0000000   0xC6FEFFFF  |||
 *                                            (See pgtable.h)       ||+- TLBTEMP_BASE_1: 0xC7FF0000 32KB    [REMIND: Move these to FIXMAP]
 *                                              122 MBytes          ||   TLBTEMP_BASE_2: 0xC7FF8000 32KB
 *                                            28 PGD Entries        ||
 *                                                                  ||
 *                                                                  ||
 *                                                                  ||
 *                                                                 /  \
 *                                                                /    \
 *                                                               /      \
 *                                                              /        \
 *                                                             /          \
 *                                   __end_of_fixed_addresses---+ FIX_KMAP_END, ... FIX_KMAP_BEGIN, FIX_HOLE
 *                                                              |     16                  1            0
 *                                                              |
 *                                    NORMAL                    |                ATOMIC
 *                          PERSISTANT  KERNEL MAPPINGS         |      FIXED-MAPPED LINEAR ADDRESSES
 *                                   512                        |                  512
 *                             Used in this Dir                 |             Used in this Dir
 *                              ---------->                     |             <-----------
 *                                                              v
 *                 |------------------ LAST_PKMAP ------------> | <------------- FIXADDR_SIZE -------------->|
 *                                                                                                           |
 *      VMALLOC_END    PKMAP_ADDR(last_pkmap_nr)                                                             |         
 *       C6FEFFFF                                                        C730D000 C730E000 C73FF000 C7400000 v
 *       +---//---+---------+--------+---//---+---//---+--------+--\ \---+--------+---------+-------+--------+ pkmap_page_table[1024] 4k PTE's
 *       |         | page 0 | page 1 |        |        |        |        |        |  idx:2  | idx:1 |  idx:0 | 
 *       +---//----+--------+--------+---//---+---//---+--------+--\ \------------+---------+-------+--------+ 
 *                 ^                                            ^ KMAP                      ^ KMAP  ^  HOLE  ^ 
 *                 |                                            | END                       | BEGIN |        |
 *                 |                                            |                           |       |  NOT   | 
 *                 |                                       FIXADDR_START                kmap_vstart | MAPPED | 
 *                 |                                        (0xC73EF000)                            |        |
 *                 |                                        (Currently)                             |        |
 *                 |                                                                                |        |
 *                 +--------------------------------------   PMD_SIZE ----------------------------->+        +
 *               PKMAP_BASE                                  0X400000                                    FIXADDR_TOP
 *               0xC7000000)                          One  4-MByte PGD Entry                             0xC7400000
 *                 (Currently)                                        
 */

/*
 * Used by vmalloc.c.
 *
 * Leave one empty page between vmalloc'ed areas and
 * the start of the fixmap, and leave one page empty
 * at the top of mem.
 *
 * NOTE:
 *   Currenty leaving more than a page between vmalloc
 *   area and the start of fixmap.
 */
#define FIXADDR_BOTTOM	((unsigned long)(long)(int)0xC7000000)
#define FIXADDR_TOP	((unsigned long)(long)(int)0xC7400000)
#define FIXADDR_SIZE	(__end_of_fixed_addresses << PAGE_SHIFT)
#define FIXADDR_START	(FIXADDR_TOP - FIXADDR_SIZE)

/* 
 * FIXED-MAPPED equivalent to __va() and __pa() macros; passed an index.
 * Used by kmap_atomic() and kunmap_atomic().
 */
#define __fix_to_virt(x)	(FIXADDR_TOP - ((x) << PAGE_SHIFT))
#define __virt_to_fix(x)	((FIXADDR_TOP - ((x)&PAGE_MASK)) >> PAGE_SHIFT)

extern void __this_fixmap_does_not_exist(void);

/*
 * 'index to address' translation. If anyone tries to use the idx
 * directly without tranlation, we catch the bug with a NULL-deference
 * kernel oops. Illegal ranges of incoming indices are caught too.
 */
static inline unsigned long fix_to_virt(const unsigned int idx)
{
	/*
	 * this branch gets completely eliminated after inlining,
	 * except when someone tries to use fixaddr indices in an
	 * illegal way. (such as mixing up address types or using
	 * out-of-range indices).
	 *
	 * If it doesn't get removed, the linker will complain
	 * loudly with a reasonably clear error message..
	 */
	if (idx >= __end_of_fixed_addresses)
		__this_fixmap_does_not_exist();

        return __fix_to_virt(idx);
}

static inline unsigned long virt_to_fix(const unsigned long vaddr)
{
	BUG_ON(vaddr >= FIXADDR_TOP || vaddr < FIXADDR_START);
	return __virt_to_fix(vaddr);
}

/*
 * Called from pgtable_init()
 */
extern void fixrange_init(unsigned long start, unsigned long end, pgd_t *pgd_base);


#endif
