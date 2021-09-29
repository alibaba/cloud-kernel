/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KHUGEPAGED_H
#define _LINUX_KHUGEPAGED_H

#include <linux/sched/coredump.h> /* MMF_VM_HUGEPAGE */
#include <linux/shmem_fs.h>


#ifdef CONFIG_TRANSPARENT_HUGEPAGE
extern struct attribute_group khugepaged_attr_group;

extern int khugepaged_init(void);
extern void khugepaged_destroy(void);
extern int start_stop_khugepaged(void);
extern int __khugepaged_enter(struct mm_struct *mm);
extern void __khugepaged_exit(struct mm_struct *mm);
extern int khugepaged_enter_vma_merge(struct vm_area_struct *vma,
				      unsigned long vm_flags);
#ifdef CONFIG_SHMEM
extern void collapse_pte_mapped_thp(struct mm_struct *mm, unsigned long addr);
#else
static inline void collapse_pte_mapped_thp(struct mm_struct *mm,
					   unsigned long addr)
{
}
#endif
#ifdef CONFIG_HUGETEXT
extern void khugepaged_enter_exec_vma(struct vm_area_struct *vma,
				      unsigned long vm_flags);
#else
static inline void khugepaged_enter_exec_vma(struct vm_area_struct *vma,
					     unsigned long vm_flags)
{
}
#endif

#ifdef CONFIG_HUGETEXT
#define khugepaged_enabled()					\
	(transparent_hugepage_flags &				\
	 ((1<<TRANSPARENT_HUGEPAGE_FLAG) |			\
	  (1<<TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG) |		\
	  (1<<TRANSPARENT_HUGEPAGE_FILE_TEXT_ENABLED_FLAG) |	\
	  (1<<TRANSPARENT_HUGEPAGE_ANON_TEXT_ENABLED_FLAG)))
#else
#define khugepaged_enabled()					       \
	(transparent_hugepage_flags &				       \
	 ((1<<TRANSPARENT_HUGEPAGE_FLAG) |		       \
	  (1<<TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG)))
#endif
#define khugepaged_always()				\
	(transparent_hugepage_flags &			\
	 (1<<TRANSPARENT_HUGEPAGE_FLAG))
#define khugepaged_req_madv()					\
	(transparent_hugepage_flags &				\
	 (1<<TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG))
#define khugepaged_defrag()					\
	(transparent_hugepage_flags &				\
	 (1<<TRANSPARENT_HUGEPAGE_DEFRAG_KHUGEPAGED_FLAG))

static inline int khugepaged_fork(struct mm_struct *mm, struct mm_struct *oldmm)
{
	if (test_bit(MMF_VM_HUGEPAGE, &oldmm->flags))
		return __khugepaged_enter(mm);
	return 0;
}

static inline void khugepaged_exit(struct mm_struct *mm)
{
	if (test_bit(MMF_VM_HUGEPAGE, &mm->flags))
		__khugepaged_exit(mm);
}

static inline int khugepaged_enter(struct vm_area_struct *vma,
				   unsigned long vm_flags)
{
	if (!test_bit(MMF_VM_HUGEPAGE, &vma->vm_mm->flags))
		if ((khugepaged_always() ||
		     (shmem_file(vma->vm_file) && shmem_huge_enabled(vma)) ||
		     hugetext_vma_enabled(vma, vm_flags) ||
		     (khugepaged_req_madv() && (vm_flags & VM_HUGEPAGE))) &&
		    !(vm_flags & VM_NOHUGEPAGE) &&
		    !test_bit(MMF_DISABLE_THP, &vma->vm_mm->flags))
			if (__khugepaged_enter(vma->vm_mm))
				return -ENOMEM;

	if (hugetext_vma_enabled(vma, vm_flags)
			&& test_bit(MMF_VM_HUGEPAGE, &vma->vm_mm->flags))
		khugepaged_enter_exec_vma(vma, vm_flags);
	return 0;
}
#else /* CONFIG_TRANSPARENT_HUGEPAGE */
static inline int khugepaged_fork(struct mm_struct *mm, struct mm_struct *oldmm)
{
	return 0;
}
static inline void khugepaged_exit(struct mm_struct *mm)
{
}
static inline int khugepaged_enter(struct vm_area_struct *vma,
				   unsigned long vm_flags)
{
	return 0;
}
static inline int khugepaged_enter_vma_merge(struct vm_area_struct *vma,
					     unsigned long vm_flags)
{
	return 0;
}
static inline void collapse_pte_mapped_thp(struct mm_struct *mm,
					   unsigned long addr)
{
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

#endif /* _LINUX_KHUGEPAGED_H */
