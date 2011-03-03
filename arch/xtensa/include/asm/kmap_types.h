/*
 * include/asm-xtensa/kmap_types.h
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2001 - 2005 Tensilica Inc.
 */

#ifndef _XTENSA_KMAP_TYPES_H
#define _XTENSA_KMAP_TYPES_H

/* 
 * We want the number of values to be a power of two. 
 * This makes indexing the kmap_pte_table[][][] faster
 * and alignes the begining of aliases at an even boundry.
 *
 * REMIND:
 *    Verify KM_TYPE_NR > (1 << DCACHE_ALIAS_ORDER) ?
 */
enum km_type {
  KM_BOUNCE_READ,		/* 0 */
  KM_SKB_SUNRPC_DATA,		/* 1 */
  KM_SKB_DATA_SOFTIRQ,		/* 2 */
  KM_USER0,			/* 3 */
  KM_USER1,			/* 4 */
  KM_BIO_SRC_IRQ,		/* 5 */
  KM_BIO_DST_IRQ,		/* 6 */
  KM_PTE0,			/* 7 */
  KM_PTE1,			/* 8 */
  KM_IRQ0,			/* 9 */
  KM_IRQ1,			/* 10 */
  KM_SOFTIRQ0,			/* 11 */
  KM_SOFTIRQ1,			/* 12 */
  KM_L1_CACHE,			/* 13 */
  KM_L2_CACHE,			/* 14 */
  KM_KDB,			/* 15 */
  KM_TLB_CACHE_FLUSH,		/* 16 */
  KM_FLUSH_DCACHE_PAGE,		/* 17 */
  KM_FLUSH_ANON_PAGE,		/* 18 */
  LM_19,
  LM_20,
  LM_21,
  LM_22,
  LM_23,
  LM_24,
  LM_25,
  LM_26,
  LM_27,
  LM_28,
  LM_29,
  LM_30,
  LM_31,
  KM_TYPE_NR			/* 32 */
};

#define KM_TYPES		32

#ifdef CONFIG_DEBUG_HIGHMEM
#define KM_NMI          (-1)
#define KM_NMI_PTE      (-1)
#define KM_IRQ_PTE      (-1)
#endif

#endif	/* _XTENSA_KMAP_TYPES_H */
