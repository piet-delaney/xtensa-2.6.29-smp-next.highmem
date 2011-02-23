#include <linux/highmem.h>
#include <linux/module.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>

/*
 * Enable HIGHMEM Debug Here, with .xt-gdbinit file, or via CONFIG_CMDLINE. 
 * Ex:
 *     CONFIG_CMDLINE="console=ttyS0 ... coredump_filter=0xff highmem_debug=1"
 */
int highmem_debug = 0;

static int __init highmem_debug_setup(char *buf)
{
	highmem_debug = 1;
        return 0;
}

/* Set in CONFIG_CMDLINE, Ex: highmem_debug=1 */
early_param("highmem_debug", highmem_debug_setup);

#define dprintf(fmt, args...) ({                        \
        if (unlikely(highmem_debug))                    \
                printk(KERN_INFO                        \
                        "HighMem::%s " fmt,             \
                        __func__, ## args);             \
})


void *kmap(struct page *page)
{
	might_sleep();
	if (!PageHighMem(page))
		return page_address(page);
	return kmap_high(page);
}

void kunmap(struct page *page)
{
	if (in_interrupt())
		BUG();
	if (!PageHighMem(page))
		return;
	kunmap_high(page);
}

static void debug_kmap_atomic_prot(enum km_type type)
{
#ifdef CONFIG_DEBUG_HIGHMEM
	static unsigned warn_count = 10;

	if (unlikely(warn_count == 0))
		return;

	if (unlikely(in_interrupt())) {
		if (in_irq()) {
			if (type != KM_IRQ0 && type != KM_IRQ1 &&
			    type != KM_BIO_SRC_IRQ && type != KM_BIO_DST_IRQ &&
			    type != KM_BOUNCE_READ) {
				WARN_ON(1);
				warn_count--;
			}
		} else if (!irqs_disabled()) {	/* softirq */
			if (type != KM_IRQ0 && type != KM_IRQ1 &&
			    type != KM_SOFTIRQ0 && type != KM_SOFTIRQ1 &&
			    type != KM_SKB_SUNRPC_DATA &&
			    type != KM_SKB_DATA_SOFTIRQ &&
			    type != KM_BOUNCE_READ) {
				WARN_ON(1);
				warn_count--;
			}
		}
	}

	if (type == KM_IRQ0 || type == KM_IRQ1 || type == KM_BOUNCE_READ ||
			type == KM_BIO_SRC_IRQ || type == KM_BIO_DST_IRQ) {
		if (!irqs_disabled()) {
			WARN_ON(1);
			warn_count--;
		}
	} else if (type == KM_SOFTIRQ0 || type == KM_SOFTIRQ1) {
		if (irq_count() == 0 && !irqs_disabled()) {
			WARN_ON(1);
			warn_count--;
		}
	}
#endif
}

/*
 * kmap_atomic/kunmap_atomic is significantly faster than kmap/kunmap because
 * no global lock is needed and because the generic kmap code must perform a 
 * global TLB invalidation when the kmap pool wraps. 
 *
 * Our associated * kunmap_atomic() we will clear the temorary page table entry 
 * and flush the TLB entry.
 *
 * However when holding an atomic kmap is is not legal to sleep, so atomic
 * kmaps are appropriate for short, tight code paths only.
 */
void *kmap_atomic_prot(struct page *page, enum km_type type, pgprot_t prot)
{
	enum fixed_addresses idx;
	unsigned long vaddr;
	pte_t *ptep;
	pte_t pte;

	dprintf("(page:%p, type:%d, prot)\n", page, type);

	/* even !CONFIG_PREEMPT needs this, for in_atomic in do_page_fault */
	pagefault_disable();

	if (!PageHighMem(page))
		return page_address(page);

	debug_kmap_atomic_prot(type);

	idx = type + KM_TYPE_NR*smp_processor_id();
	vaddr = __fix_to_virt(FIX_KMAP_BEGIN + idx);
	ptep = kmap_pte - idx;
	BUG_ON( !pte_none(*ptep) );
	pte = mk_pte(page, prot);
	set_pte(ptep, pte);
	arch_flush_lazy_mmu_mode();

#if 0 && defined(CONFIG_DEBUG_KERNEL)
	{
		 unsigned long *test_addr;
		 unsigned long saved_data;

		/* 
	  	 * Make sure TLB gets loaded. After storing to *test_addr the
	  	 * fast_second_level_miss() code in entry.S should load the TLB
	  	 * entry into ones of the auto-refill ways, (0,1,2,or 3), and it
	  	 * should be visible with the gdb 'dtshow' command. Ex:
	  	 *
	  	 * 	Showing way 3
	  	 * 	vaddr=0xc0000000 asid=0x01  paddr=0x0f800000  ca=6  DTLB way 3 (4 kB)
	  	 * 	vaddr=0x00001000 asid=0x00  paddr=0x00000000  ca=0  DTLB way 3 (4 kB)
	  	 * --->	vaddr=0xc73fe000 asid=0x01  paddr=0x0ffdc000  ca=6  DTLB way 3 (4 kB)
	  	 * 	vaddr=0x00003000 asid=0x00  paddr=0x00000000  ca=0  DTLB way 3 (4 kB)
	  	 */
		test_addr = (unsigned long *) vaddr;		/* Save Memory */
		saved_data = *test_addr;
		*test_addr = 0X12345678;
		BUG_ON(*test_addr != 0X12345678);
		 *test_addr = saved_data;			/* Restore Memory */
		 __flush_dcache_page(vaddr);
	}
#endif

	dprintf("return(vaddr:0X%lx);\n", vaddr);
	return (void *)vaddr;
}

/* 
 * Clear a kernel PTE and flush it from the TLB.
 * Curently a bit conservative and flushing all
 * Data entries probed with the associated page 
 * and panic() if more than one entry was found.
 */
static inline void kpte_clear_flush(pte_t *pte, unsigned long vaddr)
{
	__flush_dcache_page(vaddr);

	pte_clear(&init_mm, vaddr, pte);	/* Flushes pte to memory */
	local_flush_tlb_kernel_page(vaddr);
}

void *kmap_atomic(struct page *page, enum km_type type)
{
	return kmap_atomic_prot(page, type, kmap_prot);
}

void kunmap_atomic(void *kvaddr, enum km_type type)
{
	unsigned long vaddr = (unsigned long) kvaddr & PAGE_MASK;
	enum fixed_addresses idx = type + KM_TYPE_NR*smp_processor_id();

	dprintf("(kvaddr:%p, type:%d)\n", kvaddr,    type);

	/*
	 * Force other mappings to Oops if they'll try to access this pte
	 * without first remap it.  Keeping stale mappings around is a bad idea
	 * also, in case the page changes cacheability attributes or becomes
	 * a protected page in a hypervisor.
	 */
	if (vaddr == __fix_to_virt(FIX_KMAP_BEGIN+idx))
		kpte_clear_flush(kmap_pte - idx, vaddr);
	else {
#ifdef CONFIG_DEBUG_HIGHMEM
		BUG_ON(vaddr < PAGE_OFFSET);
		BUG_ON(vaddr >= (unsigned long)high_memory);
#endif
	}

	arch_flush_lazy_mmu_mode();
	pagefault_enable();
}

/* This is the same as kmap_atomic() but can map memory that doesn't
 * have a struct page associated with it.
 */
void *kmap_atomic_pfn(unsigned long pfn, enum km_type type)
{
	enum fixed_addresses idx;
	unsigned long vaddr;
	pte_t *ptep;
	pte_t pte;

	dprintf("(pfn:0X%lx, type:%d)\n", pfn, type);

	pagefault_disable();

	idx = type + KM_TYPE_NR*smp_processor_id();
	vaddr = __fix_to_virt(FIX_KMAP_BEGIN + idx);
	ptep = kmap_pte - idx;
	pte = pfn_pte(pfn, kmap_prot);
	set_pte(ptep, pte);
	arch_flush_lazy_mmu_mode();

	dprintf("return(vaddr:0X%lx)\n", vaddr);
	return (void*) vaddr;
}
EXPORT_SYMBOL_GPL(kmap_atomic_pfn); /* temporarily in use by i915 GEM until vmap */

struct page *kmap_atomic_to_page(void *ptr)
{
	unsigned long idx, vaddr = (unsigned long)ptr;
	pte_t *pte;
	struct page *page;

	dprintf("(ptr:%p)\n", ptr);

	if (vaddr < FIXADDR_START) {
		page = virt_to_page(ptr);
		goto done;
	}
	idx = virt_to_fix(vaddr);
	pte = kmap_pte - (idx - FIX_KMAP_BEGIN);
	page = pte_page(*pte);

done:
	dprintf("return(page:%p)\n", page);
	return(page);
}

EXPORT_SYMBOL(kmap);
EXPORT_SYMBOL(kunmap);
EXPORT_SYMBOL(kmap_atomic);
EXPORT_SYMBOL(kunmap_atomic);
