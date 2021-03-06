/*
 * arch/xtensa/kernel/head.S
 *
 * Xtensa Processor startup code.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2001 - 2009 Tensilica Inc.
 *
 * Chris Zankel <chris@zankel.net>
 * Marc Gauthier <marc@tensilica.com, marc@alumni.uwaterloo.ca>
 * Joe Taylor <joe@tensilica.com>
 * Pete Delaney <piet@tensilica.com>
 * Kevin Chea
 */

#include <asm/bootparam.h>
#include <asm/processor.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/cacheasm.h>
#include <asm/vectors.h>
#include <asm/mxregs.h>
#include <linux/linkage.h>

/*
 * This module contains the entry code for kernel images. It performs the
 * minimal setup needed to call the generic C routines.
 *
 * Prerequisites:
 *
 * - The kernel image has been loaded to the actual address where it was
 *   compiled to.
 * - a2 contains either 0 or a pointer to a list of boot parameters.
 *   (see setup.c for more details)
 * - caches have been initialized before we come here.
 */

/*
 *  _start
 *
 *  The bootloader passes a pointer to a list of boot parameters in a2.
 */

	/* The first bytes of the kernel image must be an instruction, so we
	 * manually allocate and define the literal constant we need for a jx
	 * instruction.
	 *
	 * For MMU_V3 systems this code is loaded at location 0X2000
	 * but mapped like the rest of the kernel to 0xd000.0000 region.
	 * An additional control section is provied with the
	 * debug information for this section running at the location
	 * is was loaded and starts running at.
	 */
	.section .head.text, "ax"
	.globl _start
	.begin  no-absolute-literals

_start:	
#if defined(CONFIG_EXTENDED_MEMORY) || defined(CONFIG_HIGHMEM)
	/* Hack till problem with PROM is resolved */
	movi	$a0, 0
	movi	$a1, 0
	movi	$a2, 0
	movi	$a3, 0
	movi	$a4, 0
	movi	$a5, 0
	movi	$a6, 0
	movi	$a7, 0
	movi	$a8, 0
	movi	$a9, 0
	movi	$a10, 0
	movi	$a11, 0
	movi	$a12, 0
	movi	$a13, 0
	movi	$a14, 0
	movi	$a15, 0
#endif
	
	/* 
	 * Preserve the pointer to the boot parameter list, a2, in EXCSAVE_1.
	 * EXCSAVE_1 will later be set up to point to exc_table[cpu]
	 */
	wsr	a2, EXCSAVE_1

	_j	_SetupMMU

	.align	4
startup_lit:	
	.word	_startup	# Explicit Absolute Literal used to jump to text init section.
	.align  4
	.literal_position	# Put Literals AFTER initial Jmp Instruction
	 .align  4

_SetupMMU:
	Offset = _SetupMMU - _start

#ifdef CONFIG_INITIALIZE_XTENSA_MMU_INSIDE_VMLINUX
	/* 
	 * This mmu initialization code is linked at 0xd000.2000.
	 * A 2nd copy is Linked at 0x0000.2000 for early debugging
	 * of this code. A 3ed copy,  also used for debuging inside 
	 * the early initializatin is mapped at at 0x4000.2000.
	 */
	#include <asm/initialize_mmu.h>
#endif

_MMUSetup:

	.end    no-absolute-literals

	l32r	a0, startup_lit		# $a0 = &_startup
	jx	a0			# jmp    _startup


	/**************************************************************************
	 * This is an unmapped version of the above
	 * code that sets up the MMU from identity
	 * mapping to 'Linux mappings' in the TLB.
	 */
	.section        .head.text.unmapped, "ax"
#ifdef CONFIG_INITIALIZE_XTENSA_MMU_INSIDE_VMLINUX
	.global         _Unmapped_start

	.org 0			# Need to do org before literals
_Unmapped_start:
	.begin  no-absolute-literals
	 .literal_position

	j      _UnmappedSetupMMU

	/*
	 * Position Remapped code to same location as
	 */
	. = _Unmapped_start + Offset 

_UnmappedSetupMMU:
	#include <asm/initialize_mmu.h>
_UnmappedMMUSetup:
	.end    no-absolute-literals
#endif
	/****************************************************************************/



	/* ---------------------------------------------------------------------------
	 * This is remapped version of the above
	 * code that sets up the MMU from identity
	 * mapping to Linux mappings in the TLB.
	 */
	.section        .head.text.remapped, "ax"

#ifdef CONFIG_INITIALIZE_XTENSA_MMU_INSIDE_VMLINUX
	.global         _Remmapped_start

	.org 0			# Need to do org before literals
_Remmapped_start:
	.begin  no-absolute-literals
	 .literal_position

	j      _RemappedSetupMMU

	/*
	 * Position Remapped code to same location as
	 */
	. = _Remmapped_start + Offset 

_RemappedSetupMMU:
	#include <asm/initialize_mmu.h>
_RemappedMMUSetup:
	.end    no-absolute-literals
#endif
	/* --------------------------------------------------------------------------- */



#if 0
	/* 
	 * Start of Init Text section:
	 * We come here for both primary and secondary processors.
	 * It's mapped to the stardard Xtensa linux 0Xd000.0000 region.
	 */
	.section .init.text, "ax"
#else
	/*
	 * REMiND:
	 *	Didn't link correclty having this in init.text where
	 *      it really belongs. Since it's rather small I'm just
	 *	including it with the head text.
	 *						-piet
	 */
	.section .head.text, "ax"
#endif
	.literal_position
	.global _startup
	.align 4

#if defined(CONFIG_INITIALIZE_XTENSA_MMU_INSIDE_VMLINUX)
	.global set_breakpoints

set_breakpoints:
#endif

_startup:

	/* Disable interrupts and exceptions; but allow xocd to service xt-gdb. */

	movi	a0, XCHAL_DEBUGLEVEL -1
	wsr	a0, PS


	/* Start with a fresh windowbase and windowstart.  */

	movi	a1, 1
	movi	a0, 0
	wsr	a1, WINDOWSTART
	wsr	a0, WINDOWBASE
	rsync

	/* Set a0 to 0 for the remaining initialization. */

	movi	a0, 0

	/* Clear debugging registers. */

#if XCHAL_HAVE_DEBUG
#if XCHAL_NUM_IBREAK > 0
	wsr	a0, IBREAKENABLE
#endif
	wsr	a0, ICOUNT
	movi	a1, 15
	wsr	a0, ICOUNTLEVEL

	.set	_index, 0
	.rept	XCHAL_NUM_DBREAK - 1
	wsr	a0, DBREAKC + _index
	.set	_index, _index + 1
	.endr
#endif

	/* Clear CCOUNT (not really necessary, but nice) */

	wsr	a0, CCOUNT	# not really necessary, but nice

	/* Disable zero-loops. */

#if XCHAL_HAVE_LOOPS
	wsr	a0, LCOUNT
#endif

	/* Disable all timers. */

	.set	_index, 0
	.rept	XCHAL_NUM_TIMERS - 1
	wsr	a0, CCOMPARE + _index
	.set	_index, _index + 1
	.endr

	/* Interrupt initialization. */

	movi	a2, XCHAL_INTTYPE_MASK_SOFTWARE | XCHAL_INTTYPE_MASK_EXTERN_EDGE
	wsr	a0, INTENABLE
	wsr	a2, INTCLEAR

	/* Disable coprocessors. */

#if XCHAL_CP_NUM > 0
	wsr	a0, CPENABLE
#endif

	/* Set PS.INTLEVEL=LOCKLEVEL, PS.WOE=0, kernel stack, PS.EXCM=0
	 *
	 * Note: PS.EXCM must be cleared before using any loop
	 *	 instructions; otherwise, they are silently disabled, and
	 * 	 at most one iteration of the loop is executed.
	 */

	movi	a1, LOCKLEVEL
	wsr	a1, PS
	rsync

	/* End of baisc initialization. */

#ifdef CONFIG_SMP
	/* 
	 * Notice that we assume with SMP that cores have PRID
	 * supported by the cores.
	 */
	rsr	a2, PRID		
	bnez	a2, .Lboot_secondary

#endif	/* CONFIG_SMP */

	/* 
	 * Copy Exception Vectors and their associted Literals to their live locations.
	 * This is done so we don't disturb the environment of the code that loaded us.
	 *
	 * The linker script used to build the Linux kernel image creates a table located at 
	 * __boot_reloc_table_start that contans the information what data needs to be copied.
	 *
	 *                                           EXAMPLE
         *        a2:__boot_reloc_table_start        =======
         *         DESTINATION         SOURCE
         *        a4        a5           a6                      
         *      START       END         START	   VECTOR OFFSET NAME        VALUE             VECTOR
         *    ==========  =========   ========== ======================    ========== ==============================
         *    0xd0000000  0xd000016a  0xd02f4fd4                                      _WindowOverflow4
         *    0xd0000180  0xd0000197  0xd02f5148 XCHAL_INTLEVEL2_VECOFS    0x00000180 _Level2InterruptVector
         *    0xd00001c0  0xd00001da  0xd02f5160 XCHAL_INTLEVEL3_VECOFS    0x000001C0 _Level3InterruptVector
         *    0xd0000300  0xd0000320  0xd02f517c XCHAL_KERNEL_VECOFS       0x00000300 _KernelExceptionVector
         *    0xd0000340  0xd000035c  0xd02f519c XCHAL_USER_VECOFS         0x00000340 _UserExceptionVector
         *    0xd00003b0  0xd00003bc  0xd02f51b8          -                    -      _DoubleExceptionVector_literals
         *    0xd00003c0  0xd00004d8  0xd02f51c4 XCHAL_DOUBLEEXC_VECOFS    0x000003C0 _DoubleExceptionVector
         *    0xd0000280  0xd0000286  0xd02f5140 XCHAL_INTLEVEL6_VECOFS    0x00000280 _DebugInterruptVector
         *    0xd80004fc  0xd8000500  0xd02f52dc          -                     -     _SecondaryResetVector_literals
         *    0xd8000500  0xd8000580  0xd02f52e0 XCHAL_RESET_VECTOR1_PADDR 0x00000500 _SecondaryResetVector
         *    0x00000000  0x00000000  0xd02bdedc
         *    0x00000000  0x00000000  0xd02bdedc
         *        a3:__boot_reloc_table_end
	 *
	 * Use command "objdump -wph vmlinux" to see details.
	 *
	 */
	movi	a2, __boot_reloc_table_start
	movi	a3, __boot_reloc_table_end

1:	beq	a2, a3, 3f	# no more entries?
	l32i	a4, a2, 0	# start destination (in RAM)
	l32i	a5, a2, 4	# end desination (in RAM)
	l32i	a6, a2, 8	# start source (in ROM)
	addi	a2, a2, 12	# next entry
	beq	a4, a5, 1b	# skip, empty entry
	beq	a4, a6, 1b	# skip, source and dest. are the same

2:	l32i	a7, a6, 0	# load word
	addi	a6, a6, 4
	s32i	a7, a4, 0	# store word
	addi	a4, a4, 4
	bltu	a4, a5, 2b
	j	1b

3:
	/* All code and initialized data segments have been copied.
	 * Now clear the BSS segment.
	 */

	movi	a2, _bss_start	# start of BSS
	movi	a3, _bss_end	# end of BSS

	__loopt	a2, a3, a4, 2
	s32i	a0, a2, 0
	__endla	a2, a4, 4

#if XCHAL_DCACHE_IS_WRITEBACK

	/* After unpacking, flush the writeback cache to memory so the
	 * instructions/data are available.
	 */

	___flush_dcache_all a2 a3
#endif

// FIXME: CPU should come up that way

	___invalidate_dcache_all a2 a3

#ifdef CONFIG_ARCH_HAS_SMP
	movi	a2, CCON			# MX External Register to Configure Cache
	movi	a3, 1
	wer	a3, a2
#endif



.Lboot_secondary:

	/* Setup stack and enable window exceptions (keep irqs disabled) */

	movi	a1, start_info
	l32i	a1, a1, 0

	movi	a2, 0x00040000+LOCKLEVEL	# WOE=1, INTLEVEL=LOCKLEVEL, UM=0
	wsr	a2, PS				# (enable reg-windows; progmode stack)
	rsync

	/* 
	 * Set up pointer to the Debug Exception Handler.
	 * REMIND-FIXME: We Need a reference to the ISA here.
	 */
	movi	a2, debug_exception
	wsr	a2, EXCSAVE + XCHAL_DEBUGLEVEL

#if 0	
	/*
	 * REMIND-FIXME: try to do something in the spirit of this;
	 *  much earlier than trap_init().
	 *
	 * SKIP this, the per_cpu exc_table[] is currently zero'd out.
 	 *      it will be done a bit later in traps.c in trap_init()
	 *	which is called from start_kernel().
	 * 
	 * Set up EXCSAVE[1] to point to the exc_table. 
	 */
	rsr	a4, PRID
	movi	a6, per_cpu__exc_table
	slli	a4, a4, EXC_TABLE_SIZE_LOG2
	add	a6, a6, a4
#else
#	movi    a6, 0				# DEBUG: Use NULL Pointer to detect a bogus &exc_table[]
#endif
	xsr	a6, EXCSAVE_1			# restore a6 with boot args that were...
						# ... saved above from a2.

	/* 
	 * Initialize Architecture spcecic stuff.
	 *
	 * NOTE: can't allow most excpetions yet,
	 *	 pointer in EXCSAVE to per_cpu exc_table[]
	 *	 hasn't been set up yet.
	 */
	movi	a4, init_arch
	callx4	a4				# Call init_arch( (bp_tag_t *) a6)

	movi	a4, start_info
	l32i	a4, a4, 4
	callx4	a4				# Call start_kernel(void)

should_never_return:
	j	should_never_return

/*
 * DATA section
 */

	.section ".data.init.refok"
	.align	4
ENTRY(start_info)
	.long	init_thread_union + KERNEL_STACK_SIZE
	.long	start_kernel

/*
 * BSS section
 */
	
	.section ".bss.page_aligned", "w"
#ifdef CONFIG_MMU
ENTRY(swapper_pg_dir)
	.fill	PAGE_SIZE, 1, 0
#endif
ENTRY(empty_zero_page)
	.fill	PAGE_SIZE, 1, 0
