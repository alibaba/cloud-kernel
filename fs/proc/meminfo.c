// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/mmzone.h>
#include <linux/proc_fs.h>
#include <linux/percpu.h>
#include <linux/quicklist.h>
#include <linux/seq_file.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
#include <linux/vmalloc.h>
#ifdef CONFIG_CMA
#include <linux/cma.h>
#endif
#include <asm/page.h>
#include <asm/pgtable.h>
#include "internal.h"
#include <linux/pid_namespace.h>

void __attribute__((weak)) arch_report_meminfo(struct seq_file *m)
{
}

static void show_val_kb(struct seq_file *m, const char *s, unsigned long num)
{
	seq_put_decimal_ull_width(m, s, num << (PAGE_SHIFT - 10), 8);
	seq_write(m, " kB\n", 4);
}

static int meminfo_proc_show(struct seq_file *m, void *v)
{
	struct sysinfo i;
	unsigned long committed;
	int lru;
	struct mem_cgroup *memcg = NULL;
	struct sysinfo_ext ext;

#ifdef CONFIG_MEMCG
	rcu_read_lock();
	if (in_rich_container(current))
		memcg = rich_container_get_memcg();

	rcu_read_unlock();
#endif

	if (!memcg) {
		si_meminfo(&i);
		si_swapinfo(&i);

		ext.cached = global_node_page_state(NR_FILE_PAGES) -
				total_swapcache_pages() - i.bufferram;
		if (ext.cached < 0)
			ext.cached = 0;

		for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++) {
			ext.lrupages[lru] =
				global_node_page_state(NR_LRU_BASE + lru);
		}
		ext.available = si_mem_available();
		ext.file_dirty = global_node_page_state(NR_FILE_DIRTY);
		ext.writeback = global_node_page_state(NR_WRITEBACK);
		ext.anon_mapped = global_node_page_state(NR_ANON_MAPPED);
		ext.file_mapped = global_node_page_state(NR_FILE_MAPPED);
		ext.slab_reclaimable =
			global_node_page_state(NR_SLAB_RECLAIMABLE);
		ext.slab_unreclaimable =
			global_node_page_state(NR_SLAB_UNRECLAIMABLE);
		ext.kernel_stack_kb =
			global_zone_page_state(NR_KERNEL_STACK_KB);
		ext.unstable_nfs = global_node_page_state(NR_UNSTABLE_NFS);
		ext.writeback_temp = global_node_page_state(NR_WRITEBACK_TEMP);
		ext.anon_thps = global_node_page_state(NR_ANON_THPS);
		ext.shmem_thps = global_node_page_state(NR_SHMEM_THPS);
		ext.shmem_pmd_mapped =
			global_node_page_state(NR_SHMEM_PMDMAPPED);
	} else {
		memcg_meminfo(memcg, &i, &ext);
	}

	committed = percpu_counter_read_positive(&vm_committed_as);

	show_val_kb(m, "MemTotal:       ", i.totalram);
	show_val_kb(m, "MemFree:        ", i.freeram);
	show_val_kb(m, "MemAvailable:   ", ext.available);
	show_val_kb(m, "Buffers:        ", i.bufferram);
	show_val_kb(m, "Cached:         ", ext.cached);
	show_val_kb(m, "SwapCached:     ", total_swapcache_pages());
	show_val_kb(m, "Active:         ", ext.lrupages[LRU_ACTIVE_ANON] +
					   ext.lrupages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive:       ", ext.lrupages[LRU_INACTIVE_ANON] +
					   ext.lrupages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Active(anon):   ", ext.lrupages[LRU_ACTIVE_ANON]);
	show_val_kb(m, "Inactive(anon): ", ext.lrupages[LRU_INACTIVE_ANON]);
	show_val_kb(m, "Active(file):   ", ext.lrupages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive(file): ", ext.lrupages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Unevictable:    ", ext.lrupages[LRU_UNEVICTABLE]);
	show_val_kb(m, "Mlocked:        ", global_zone_page_state(NR_MLOCK));

#ifdef CONFIG_HIGHMEM
	show_val_kb(m, "HighTotal:      ", i.totalhigh);
	show_val_kb(m, "HighFree:       ", i.freehigh);
	show_val_kb(m, "LowTotal:       ", i.totalram - i.totalhigh);
	show_val_kb(m, "LowFree:        ", i.freeram - i.freehigh);
#endif

#ifndef CONFIG_MMU
	show_val_kb(m, "MmapCopy:       ",
		    (unsigned long)atomic_long_read(&mmap_pages_allocated));
#endif

	show_val_kb(m, "SwapTotal:      ", i.totalswap);
	show_val_kb(m, "SwapFree:       ", i.freeswap);
	show_val_kb(m, "Dirty:          ", ext.file_dirty);
	show_val_kb(m, "Writeback:      ", ext.writeback);
	show_val_kb(m, "AnonPages:      ", ext.anon_mapped);
	show_val_kb(m, "Mapped:         ", ext.file_mapped);
	show_val_kb(m, "Shmem:          ", i.sharedram);
	show_val_kb(m, "Slab:           ",
			ext.slab_reclaimable + ext.slab_unreclaimable);

	show_val_kb(m, "SReclaimable:   ", ext.slab_reclaimable);
	show_val_kb(m, "SUnreclaim:     ", ext.slab_unreclaimable);
	seq_printf(m, "KernelStack:    %8lu kB\n", ext.kernel_stack_kb);
	show_val_kb(m, "PageTables:     ",
		    global_zone_page_state(NR_PAGETABLE));
#ifdef CONFIG_QUICKLIST
	show_val_kb(m, "Quicklists:     ", quicklist_total_size());
#endif

	show_val_kb(m, "NFS_Unstable:   ", ext.unstable_nfs);
	show_val_kb(m, "Bounce:         ",
		    global_zone_page_state(NR_BOUNCE));
	show_val_kb(m, "WritebackTmp:   ", ext.writeback_temp);
	show_val_kb(m, "CommitLimit:    ", vm_commit_limit());
	show_val_kb(m, "Committed_AS:   ", committed);
	seq_printf(m, "VmallocTotal:   %8lu kB\n",
		   (unsigned long)VMALLOC_TOTAL >> 10);
	show_val_kb(m, "VmallocUsed:    ", 0ul);
	show_val_kb(m, "VmallocChunk:   ", 0ul);
	show_val_kb(m, "Percpu:         ", pcpu_nr_pages());

#ifdef CONFIG_MEMORY_FAILURE
	seq_printf(m, "HardwareCorrupted: %5lu kB\n",
		   atomic_long_read(&num_poisoned_pages) << (PAGE_SHIFT - 10));
#endif

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	show_val_kb(m, "AnonHugePages:  ", ext.anon_thps * HPAGE_PMD_NR);
	show_val_kb(m, "ShmemHugePages: ", ext.shmem_thps * HPAGE_PMD_NR);
	show_val_kb(m, "ShmemPmdMapped: ", ext.shmem_pmd_mapped * HPAGE_PMD_NR);
	show_val_kb(m, "FileHugePages:  ",
		    global_node_page_state(NR_FILE_THPS) * HPAGE_PMD_NR);
	show_val_kb(m, "FilePmdMapped:  ",
		    global_node_page_state(NR_FILE_PMDMAPPED) * HPAGE_PMD_NR);
#endif

#ifdef CONFIG_CMA
	show_val_kb(m, "CmaTotal:       ", totalcma_pages);
	show_val_kb(m, "CmaFree:        ",
		    global_zone_page_state(NR_FREE_CMA_PAGES));
#endif

	hugetlb_report_meminfo(m);

	arch_report_meminfo(m);

#ifdef CONFIG_MEMCG
	if (memcg)
		css_put(&memcg->css);
#endif

	return 0;
}

static int __init proc_meminfo_init(void)
{
	proc_create_single("meminfo", 0, NULL, meminfo_proc_show);
	return 0;
}
fs_initcall(proc_meminfo_init);
