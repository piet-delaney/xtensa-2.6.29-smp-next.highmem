/*
 * arch/xtensa/kernel/setup.c
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1995  Linus Torvalds
 * Copyright (C) 2001 - 2009  Tensilica Inc.
 *
 * Chris Zankel	<chris@zankel.net>
 * Joe Taylor	<joe@tensilica.com>
 * Marc Gauthier<marc@tensilica.com> <marc@alumni.uwaterloo.ca>
 * Pete Delaney <piet@tensilica.com>
 * Kevin Chea
 */

#include <linux/smp.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/screen_info.h>
#include <linux/bootmem.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/cpu.h>

#if defined(CONFIG_VGA_CONSOLE) || defined(CONFIG_DUMMY_CONSOLE)
# include <linux/console.h>
#endif

#ifdef CONFIG_RTC
# include <linux/timex.h>
#endif

#ifdef CONFIG_PROC_FS
# include <linux/seq_file.h>
#endif

#include <asm/system.h>
#include <asm/bootparam.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/timex.h>
#include <asm/platform.h>
#include <asm/page.h>
#include <asm/setup.h>
#include <asm/param.h>

#include <platform/hardware.h>

#if defined(CONFIG_VGA_CONSOLE) || defined(CONFIG_DUMMY_CONSOLE)
struct screen_info screen_info = { 0, 24, 0, 0, 0, 80, 0, 0, 0, 24, 1, 16};
#endif

#ifdef CONFIG_BLK_DEV_FD
extern struct fd_ops no_fd_ops;
struct fd_ops *fd_ops;
#endif

extern struct rtc_ops no_rtc_ops;
struct rtc_ops *rtc_ops;

#ifdef CONFIG_BLK_DEV_INITRD
extern void *initrd_start;
extern void *initrd_end;
extern void *__initrd_start;
extern void *__initrd_end;
int initrd_is_mapped = 0;
extern int initrd_below_start_ok;
#endif

unsigned char aux_device_present;
extern unsigned long loops_per_jiffy;

/* Command line specified as configuration option. */

static char __initdata command_line[COMMAND_LINE_SIZE];

#ifdef CONFIG_CMDLINE_BOOL
/*
 * REMIND: What non-__initdata function is refering to this?
 */
static  /* __initdata */ char default_command_line[COMMAND_LINE_SIZE] __initdata = CONFIG_CMDLINE;
#endif

/* 
 * REMIND:
 * Why does __invalidate_dcache_all() appear to reference sysmem?
 */
sysmem_info_t /* __initdata */ sysmem;

#ifdef CONFIG_BLK_DEV_INITRD
int initrd_is_mapped;
#endif

#ifdef CONFIG_MMU
extern void init_mmu(void);
#else
static inline void init_mmu(void) { }
#endif

extern void zones_init(void);

/*
 * Boot parameter parsing.
 *
 * The Xtensa port uses a list of variable-sized tags to pass data to
 * the kernel. The first tag must be a BP_TAG_FIRST tag for the list
 * to be recognised. The list is terminated with a zero-sized
 * BP_TAG_LAST tag.
 *
 * When booting via xt-ocd the bootparams are up at the reset vector
 * and don't need to be mapped to a virtual address. When comming from
 * U-Boot the addresses are physical and need to be mapped to virtual.
 */
static int map_required = 0;

#define PHYS_TO_VIRT(pa, va)	{					\
	if (map_required) {						\
		(va) = (typeof(va)) (((int) pa) | 0XD0000000);		\
		printk("%s: va:%p = pa:%p | 0XD0000000\n", __func__,	\
			    va,     pa);				\
	} else {							\
		(va) = (pa);						\
	}								\
}									\

typedef struct tagtable {
	u32 tag;
	int (*parse)(const bp_tag_t*);
} tagtable_t;

#define __tagtable(tag, fn) static tagtable_t __tagtable_##fn 		\
	__attribute__((used, __section__(".taglist"))) = { tag, fn }

/* 
 * parse current memory info tag:
 */
static int __init parse_tag_mem(const bp_tag_t *tag)
{
	meminfo_t *phys_mi = (meminfo_t *)(tag->data);
	meminfo_t *mi;

#if 0
	PHYS_TO_VIRT(phys_mi, mi);
#else
	mi = phys_mi;
#endif

	if (mi->type != MEMORY_TYPE_CONVENTIONAL)
		return -1;

	if (sysmem.nr_banks >= SYSMEM_BANKS_MAX) {
		printk(KERN_WARNING
		       "Ignoring memory bank 0x%08lx size %ldKB\n",
		       (unsigned long)mi->start,
		       (unsigned long)mi->end - (unsigned long)mi->start);
		return -EINVAL;
	}
#if 0 &&  defined(CONFIG_EXTENDED_MEMORY)
	// FIXME: Workaround for a well known board.
	printk("## Extending physical memory from %dMB to %dMB\n",
		mi->end / 1024 / 1024, (mi->end + 0x04000000) / 1024 / 1024);
	mi->end += 0x04000000;
#endif

	sysmem.bank[sysmem.nr_banks].type  = mi->type;
	sysmem.bank[sysmem.nr_banks].start = PAGE_ALIGN(mi->start);
	sysmem.bank[sysmem.nr_banks].end   = mi->end & PAGE_MASK;
	sysmem.nr_banks++;

	return 0;
}

__tagtable(BP_TAG_MEMORY, parse_tag_mem);

#ifdef CONFIG_BLK_DEV_INITRD

static int __init_refok parse_tag_initrd(const bp_tag_t *tag)
{
	meminfo_t *phys_mi;
	meminfo_t *mi;

	phys_mi = (meminfo_t *)(tag->data);

#if 0
	PHYS_TO_VIRT(phys_mi, mi);
#else
	 mi = phys_mi;
#endif
	
	initrd_start = (void*)(mi->start);
	initrd_end = (void*)(mi->end);

	return 0;
}

__tagtable(BP_TAG_INITRD, parse_tag_initrd);

#endif /* CONFIG_BLK_DEV_INITRD */

static int __init_refok parse_tag_cmdline(const bp_tag_t *tag)
{
	char *phys_command_line = (char*)(tag->data);
	char *virt_command_line;

#if 0
	PHYS_TO_VIRT(phys_command_line, virt_command_line);
#else
	virt_command_line = phys_command_line;
#endif

	strncpy(command_line, virt_command_line, COMMAND_LINE_SIZE);
	command_line[COMMAND_LINE_SIZE - 1] = '\0';
	return 0;
}

__tagtable(BP_TAG_COMMAND_LINE, parse_tag_cmdline);



/* TODO: Add __tagtable(BP_TAG_SERIAL_BAUDRATE, ) sent by u-boot */

/*
 * Currently only the primary processor has boot params.
 * You shouldn't get here from _startup() on secondary processors.
 */
static int __init parse_bootparam(const bp_tag_t *phys_tag)
{
	const bp_tag_t *tag;
	extern tagtable_t __tagtable_begin, __tagtable_end;
	tagtable_t *t;

	printk("%s(phys_tag:%p): \n",  __func__, phys_tag);

	if ( ((unsigned int) phys_tag) < ((unsigned int) 0XF0000000)) {
		map_required = 1;
		PHYS_TO_VIRT(phys_tag, tag);
	} else {
		tag = ( bp_tag_t *) phys_tag;
	}

	/* Boot parameters must start with a BP_TAG_FIRST tag. */

	if (tag->id != BP_TAG_FIRST) {
		printk(KERN_WARNING "%s: Invalid boot parameters!\n", __func__);
		return 0;
	}

	tag = (bp_tag_t *)((unsigned long)tag + sizeof(bp_tag_t) + tag->size);

	/* Parse all tags. */

	while (tag != NULL && tag->id != BP_TAG_LAST) {
	 	for (t = &__tagtable_begin; t < &__tagtable_end; t++) {
			if (tag->id == t->tag) {
				t->parse(tag);
				break;
			}
		}
		if (t == &__tagtable_end)
			printk(KERN_WARNING "%s: Ignoring tag "
			       "0x%04x\n", __func__, tag->id);

		tag = (bp_tag_t *)((unsigned long)(tag + 1) + tag->size);
	}
	return 0;
}

/*
 * Initialize architecture for each CPU. (Early stage)
 */
void __init_refok init_arch(bp_tag_t *bp_start)
{

#ifdef CONFIG_DEBUG_KERNEL
	default_message_loglevel = 7;
	default_console_loglevel = 7;
#endif	

#if 0
#ifdef CONFIG_BLK_DEV_INITRD
	initrd_start = &__initrd_start;
	initrd_end = &__initrd_end;
#endif

	sysmem.nr_banks = 0;
#endif

#ifdef CONFIG_CMDLINE_BOOL
	strcpy(command_line, default_command_line);
#endif

	/* Parse boot parameters */

        if (bp_start)
	  parse_bootparam(bp_start);

	/* 
  	 * Early hook for platforms; allow them to setup memory banks and 
  	 * board specific stuff; Ex: gpio for the Stretch a6105 board.
  	 */
	platform_init(bp_start);

	/* If platform didn't set up memory, use the default start and size */
	if (sysmem.nr_banks == 0) {
		sysmem.nr_banks = 1;
		sysmem.bank[0].start = PLATFORM_DEFAULT_MEM_START;
		sysmem.bank[0].end = PLATFORM_DEFAULT_MEM_START
				     + PLATFORM_DEFAULT_MEM_SIZE;
	}

	/* Initialize MMU. */
	init_mmu();
}

/*
 * Initialize system. Setup memory and reserve regions.
 */

extern char _end;
extern char _stext;
extern char _WindowVectors_text_start;
extern char _WindowVectors_text_end;
extern char _DebugInterruptVector_literal_start;
extern char _DebugInterruptVector_text_end;
extern char _KernelExceptionVector_literal_start;
extern char _KernelExceptionVector_text_end;
extern char _UserExceptionVector_literal_start;
extern char _UserExceptionVector_text_end;
extern char _DoubleExceptionVector_literal_start;
extern char _DoubleExceptionVector_text_end;

#ifdef CONFIG_SMP
extern __init void smp_init_cpus(void);
#endif

#if XCHAL_EXCM_LEVEL >= 2
extern char _Level2InterruptVector_text_start;
extern char _Level2InterruptVector_text_end;
#endif
#if XCHAL_EXCM_LEVEL >= 3
extern char _Level3InterruptVector_text_start;
extern char _Level3InterruptVector_text_end;
#endif
#if XCHAL_EXCM_LEVEL >= 4
extern char _Level4InterruptVector_text_start;
extern char _Level4InterruptVector_text_end;
#endif
#if XCHAL_EXCM_LEVEL >= 5
extern char _Level5InterruptVector_text_start;
extern char _Level5InterruptVector_text_end;
#endif
#if XCHAL_EXCM_LEVEL >= 6
extern char _Level6InterruptVector_text_start;
extern char _Level6InterruptVector_text_end;
#endif



#if XCHAL_HAVE_S32C1I

static volatile int __initdata rcw_word, rcw_probe_pc, rcw_exc;

/* Basic atomic compare-and-swap, that records PC of S32C1I for probing.
 *
 * If *v == cmp, set *v = set.  Return previous *v.
 */
static inline int probed_compare_swap(volatile int * v, int cmp, int set)
{
	int tmp;

	__asm__ __volatile__(
"	movi	%1, 1f			\n"
"	s32i	%1, %4, 0		\n"
"	wsr	%2, SCOMPARE1		\n"
"1:	s32c1i	%0, %3, 0		\n"
	: "=a" (set), "=&a" (tmp)
	: "a" (cmp), "a" (v), "a" (&rcw_probe_pc), "0" (set)
	: "memory"
	);
	return set;
}

/* Handle probed exception */

void __init
do_probed_exception(struct pt_regs *regs, unsigned long exccause)
{
	extern void do_unhandled(struct pt_regs *regs, unsigned long exccause);
	if (regs->pc == rcw_probe_pc) {		/* exception on s32c1i ? */
		regs->pc += 3;			/* skip the s32c1i instruction */
		rcw_exc = exccause;
	} else
		do_unhandled(regs, exccause);
}

/* Simple test of S32C1I (soc bringup assist) */

void __init
check_s32c1i (void)
{
	extern void *trap_set_early_C_handler(int cause, void *handler);
	extern void trap_initialize_early_exc_table(void);
	extern void trap_enable_early_exc_table(void);

	int n, cause1, cause2;
	void *handbus, *handdata, *handaddr;	/* temporarily saved handlers */

	/*
	 * Using Early Exception Handler Table till per_cpu code knows how many
	 * CPU's are being brought on line and we can initialized the final tables
	 */ 
	trap_initialize_early_exc_table();	/* Set default handlers, including C (Default) handler */

	rcw_probe_pc = 0;
	handbus  = trap_set_early_C_handler(EXCCAUSE_LOAD_STORE_ERROR, do_probed_exception);
	handdata = trap_set_early_C_handler(EXCCAUSE_LOAD_STORE_DATA_ERROR, do_probed_exception);
	handaddr = trap_set_early_C_handler(EXCCAUSE_LOAD_STORE_ADDR_ERROR, do_probed_exception);

	trap_enable_early_exc_table();	/* set excsave1 to point to early_exc_table */

	/* First try an S32C1I that does not store: */
	rcw_exc = 0;
	rcw_word = 1;
	n = probed_compare_swap(&rcw_word, 0, 2);
	if ((cause1 = rcw_exc) != 0) {		/* took exception? */
		if (n != 2 || rcw_word != 1)
			panic("S32C1I exception error");	/* unclean exception */
	} else if (rcw_word != 1 || n != 1)
		panic("S32C1I compare error");

	/* Then an S32C1I that stores: */
	rcw_exc = 0;
	rcw_word = 0x1234567;
	n = probed_compare_swap(&rcw_word, 0x1234567, 0xabcde);
	if ((cause2 = rcw_exc) != 0) {
		if (n != 0xabcde || rcw_word != 0x1234567)
			panic("S32C1I exception error (b)");	/* unclean exception */
	} else if (rcw_word != 0xabcde || n != 0x1234567)
		panic("S32C1I store error");

	/* Verify consistency of exceptions: */
	if (cause1 || cause2) {
		printk(KERN_WARNING "S32C1I took exception %d, %d\n", cause1, cause2);
		/* If emulation of S32C1I upon bus error gets implemented,
		   we can get rid of this panic for single core (not SMP) */
		panic("S32C1I exceptions not currently supported");
	}
	if (cause1 != cause2)
		panic("inconsistent S32C1I exceptions");

	trap_set_early_C_handler(EXCCAUSE_LOAD_STORE_ERROR, handbus);
	trap_set_early_C_handler(EXCCAUSE_LOAD_STORE_DATA_ERROR, handdata);
	trap_set_early_C_handler(EXCCAUSE_LOAD_STORE_ADDR_ERROR, handaddr);
}

#else /* XCHAL_HAVE_S32C1I */

/* This condition should not occur with a commercially deployed processor.
   Display reminder for early engr test or demo chips / FPGA bitstreams */
void
check_s32c1i (void)
{
	printk(KERN_WARNING "Processor configuration lacks atomic compare-and-swap support!\n");
}

#endif /* XCHAL_HAVE_S32C1I */


void __init setup_arch(char **cmdline_p)
{
	extern int mem_reserve(unsigned long, unsigned long, int);
	extern void bootmem_init(void);

	memcpy(boot_command_line, command_line, COMMAND_LINE_SIZE);
	boot_command_line[COMMAND_LINE_SIZE-1] = '\0';
	*cmdline_p = command_line;

	check_s32c1i();		/* NOTE: can cause an exception while probing */

	/*
 	 * Likely setup by init_arch() on the primary processor.
	 */	
	if (sysmem.nr_banks == 0) {
		sysmem.nr_banks = 1;
		sysmem.bank[0].start = PLATFORM_DEFAULT_MEM_START;
		sysmem.bank[0].end = PLATFORM_DEFAULT_MEM_START
				     + PLATFORM_DEFAULT_MEM_SIZE;
	}

	/* Reserve some memory regions */

#ifdef CONFIG_BLK_DEV_INITRD
	if (initrd_start < initrd_end) {
		initrd_is_mapped = mem_reserve(__pa(initrd_start),
					       __pa(initrd_end), 0);
		initrd_below_start_ok = 1;
 	} else {
		initrd_start = 0;
	}
#endif

	mem_reserve(__pa(&_stext),__pa(&_end), 1);

	mem_reserve(__pa(&_WindowVectors_text_start),
		    __pa(&_WindowVectors_text_end), 0);

	mem_reserve(__pa(&_DebugInterruptVector_literal_start),
		    __pa(&_DebugInterruptVector_text_end), 0);

	mem_reserve(__pa(&_KernelExceptionVector_literal_start),
		    __pa(&_KernelExceptionVector_text_end), 0);

	mem_reserve(__pa(&_UserExceptionVector_literal_start),
		    __pa(&_UserExceptionVector_text_end), 0);

	mem_reserve(__pa(&_DoubleExceptionVector_literal_start),
		    __pa(&_DoubleExceptionVector_text_end), 0);

#if XCHAL_EXCM_LEVEL >= 2
	mem_reserve(__pa(&_Level2InterruptVector_text_start),
		    __pa(&_Level2InterruptVector_text_end), 0);
#endif
#if XCHAL_EXCM_LEVEL >= 3
	mem_reserve(__pa(&_Level3InterruptVector_text_start),
		    __pa(&_Level3InterruptVector_text_end), 0);
#endif
#if XCHAL_EXCM_LEVEL >= 4
	mem_reserve(__pa(&_Level4InterruptVector_text_start),
		    __pa(&_Level4InterruptVector_text_end), 0);
#endif
#if XCHAL_EXCM_LEVEL >= 5
	mem_reserve(__pa(&_Level5InterruptVector_text_start),
		    __pa(&_Level5InterruptVector_text_end), 0);
#endif
#if XCHAL_EXCM_LEVEL >= 6
	mem_reserve(__pa(&_Level6InterruptVector_text_start),
		    __pa(&_Level6InterruptVector_text_end), 0);
#endif

	bootmem_init();

	platform_setup(cmdline_p);

#ifdef CONFIG_SMP
	smp_init_cpus();
#endif

	/* Set up zones before page_table fixed mappings */
	zones_init();

	paging_init();

#ifdef CONFIG_VT
# if defined(CONFIG_VGA_CONSOLE)
	conswitchp = &vga_con;
# elif defined(CONFIG_DUMMY_CONSOLE)
	conswitchp = &dummy_con;
# endif
#endif

#ifdef CONFIG_PCI
	platform_pcibios_init();
#endif
}

DEFINE_PER_CPU(struct cpu, cpu_devices);

static int __init topology_init(void)
{
	int cpuid, ret;

	for_each_possible_cpu(cpuid) {
		ret = register_cpu(&per_cpu(cpu_devices, cpuid), cpuid);
		if (unlikely(ret))
			printk(KERN_WARNING "%s: register_cpu %d failed (%d)\n",
			       __FUNCTION__, cpuid, ret);
	}
	return 0;
}

subsys_initcall(topology_init);



void machine_restart(char * cmd)
{
	platform_restart();
}

void machine_halt(void)
{
	platform_halt();
	while (1);
}

void machine_power_off(void)
{
	platform_power_off();
	while (1);
}

/*
 * Constants for showcache.gdb macro.
 * Perhaps should be #ifdef CONFIG_DEBUG_KERNEL
 */
int xchal_have_be = XCHAL_HAVE_BE;

int xchal_icache_line_lockable = XCHAL_ICACHE_LINE_LOCKABLE;
int xchal_dcache_line_lockable = XCHAL_DCACHE_LINE_LOCKABLE;

int xchal_icache_linesize = XCHAL_ICACHE_LINESIZE;
int xchal_dcache_linesize = XCHAL_DCACHE_LINESIZE;

int xchal_icache_size = XCHAL_ICACHE_SIZE;
int xchal_dcache_size = XCHAL_DCACHE_SIZE;

int xchal_icache_ways = XCHAL_ICACHE_WAYS;
int xchal_dcache_ways = XCHAL_DCACHE_WAYS; 

int xchal_dcache_is_writeback = XCHAL_DCACHE_IS_WRITEBACK;

int xchal_have_ptp_mmu = XCHAL_HAVE_PTP_MMU;
int xchal_have_spanning_way = XCHAL_HAVE_SPANNING_WAY;

int thread_size = CONFIG_STACK_SIZE;

#ifdef CONFIG_SMP
int arch_is_running_smp = 1;
#else
int arch_is_running_smp = 0;
#endif

long spill_location_0[128] __attribute__ ((aligned (XCHAL_TOTAL_SA_ALIGN)));
long spill_location_1[128] __attribute__ ((aligned (XCHAL_TOTAL_SA_ALIGN)));
long spill_location_2[128] __attribute__ ((aligned (XCHAL_TOTAL_SA_ALIGN)));


#ifdef CONFIG_PROC_FS

/*
 * Display some core information through /proc/cpuinfo.
 */

static int
c_show(struct seq_file *f, void *slot)
{
	/* high-level stuff */
	seq_printf(f,"\nprocessor\t: %d\n"
		     "vendor_id\t: Tensilica\n"
		     "model\t\t: Xtensa " XCHAL_HW_VERSION_NAME "\n"
		     "core ID\t\t: " XCHAL_CORE_ID "\n"
		     "build ID\t: 0x%x\n"
		     "byte order\t: %s\n"
 		     "cpu MHz\t\t: %lu.%02lu\n"
		     "bogomips\t: %lu.%02lu\n",
		     *(int*) slot,
		     XCHAL_BUILD_UNIQUE_ID,
		     XCHAL_HAVE_BE ?  "big" : "little",
		     CCOUNT_PER_JIFFY/(1000000/HZ),
		     (CCOUNT_PER_JIFFY/(10000/HZ)) % 100,
		     loops_per_jiffy/(500000/HZ),
		     (loops_per_jiffy/(5000/HZ)) % 100);

	seq_printf(f,"flags\t\t: "
#if XCHAL_HAVE_NMI
		     "nmi "
#endif
#if XCHAL_HAVE_DEBUG
		     "debug "
# if XCHAL_HAVE_OCD
		     "ocd "
# endif
#endif
#if XCHAL_HAVE_DENSITY
	    	     "density "
#endif
#if XCHAL_HAVE_BOOLEANS
		     "boolean "
#endif
#if XCHAL_HAVE_LOOPS
		     "loop "
#endif
#if XCHAL_HAVE_NSA
		     "nsa "
#endif
#if XCHAL_HAVE_MINMAX
		     "minmax "
#endif
#if XCHAL_HAVE_SEXT
		     "sext "
#endif
#if XCHAL_HAVE_CLAMPS
		     "clamps "
#endif
#if XCHAL_HAVE_MAC16
		     "mac16 "
#endif
#if XCHAL_HAVE_MUL16
		     "mul16 "
#endif
#if XCHAL_HAVE_MUL32
		     "mul32 "
#endif
#if XCHAL_HAVE_MUL32_HIGH
		     "mul32h "
#endif
#if XCHAL_HAVE_FP
		     "fpu "
#endif
		     "\n");

	/* Registers. */
	seq_printf(f,"physical aregs\t: %d\n"
		     "misc regs\t: %d\n"
		     "ibreak\t\t: %d\n"
		     "dbreak\t\t: %d\n",
		     XCHAL_NUM_AREGS,
		     XCHAL_NUM_MISC_REGS,
		     XCHAL_NUM_IBREAK,
		     XCHAL_NUM_DBREAK);


	/* Interrupt. */
	seq_printf(f,"num ints\t: %d\n"
		     "ext ints\t: %d\n"
		     "int levels\t: %d\n"
		     "timers\t\t: %d\n"
		     "debug level\t: %d\n",
		     XCHAL_NUM_INTERRUPTS,
		     XCHAL_NUM_EXTINTERRUPTS,
		     XCHAL_NUM_INTLEVELS,
		     XCHAL_NUM_TIMERS,
		     XCHAL_DEBUGLEVEL);

	/* Cache */
	seq_printf(f,"icache line size: %d\n"
		     "icache ways\t: %d\n"
		     "icache size\t: %d\n"
		     "icache flags\t: "
#if XCHAL_ICACHE_LINE_LOCKABLE
		     "lock "
#endif
		     "\n"
		     "dcache line size: %d\n"
		     "dcache ways\t: %d\n"
		     "dcache size\t: %d\n"
		     "dcache flags\t: "
#if XCHAL_DCACHE_IS_WRITEBACK
		     "writeback "
#endif
#if XCHAL_DCACHE_LINE_LOCKABLE
		     "lock "
#endif
		     "\n",
		     XCHAL_ICACHE_LINESIZE,
		     XCHAL_ICACHE_WAYS,
		     XCHAL_ICACHE_SIZE,
		     XCHAL_DCACHE_LINESIZE,
		     XCHAL_DCACHE_WAYS,
		     XCHAL_DCACHE_SIZE);

	return 0;
}

/*
 * We show only CPU #0 info.
 */
static void *
c_start(struct seq_file *f, loff_t *pos)
{
	return (*pos < NR_CPUS && cpu_online(*pos)) ? (void*) pos : NULL;
}

static void *
c_next(struct seq_file *f, void *v, loff_t *pos)
{
	*pos = next_cpu(*pos, cpu_online_map);
	return c_start(f, pos);
}

static void
c_stop(struct seq_file *f, void *v)
{
}

const struct seq_operations cpuinfo_op =
{
	start:  c_start,
	next:   c_next,
	stop:   c_stop,
	show:   c_show
};

#endif /* CONFIG_PROC_FS */

