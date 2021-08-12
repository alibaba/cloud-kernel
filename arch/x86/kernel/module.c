/*  Kernel module help for x86.
    Copyright (C) 2001 Rusty Russell.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/moduleloader.h>
#include <linux/elf.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/kasan.h>
#include <linux/bug.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/jump_label.h>
#include <linux/random.h>
#include <linux/sort.h>

#include <asm/text-patching.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/setup.h>
#include <asm/unwind.h>

#if 0
#define DEBUGP(fmt, ...)				\
	printk(KERN_DEBUG fmt, ##__VA_ARGS__)
#else
#define DEBUGP(fmt, ...)				\
do {							\
	if (0)						\
		printk(KERN_DEBUG fmt, ##__VA_ARGS__);	\
} while (0)
#endif

#ifdef CONFIG_RANDOMIZE_BASE
static unsigned long module_load_offset;

/* Mutex protects the module_load_offset. */
static DEFINE_MUTEX(module_kaslr_mutex);

static unsigned long int get_module_load_offset(void)
{
	if (kaslr_enabled()) {
		mutex_lock(&module_kaslr_mutex);
		/*
		 * Calculate the module_load_offset the first time this
		 * code is called. Once calculated it stays the same until
		 * reboot.
		 */
		if (module_load_offset == 0)
			module_load_offset =
				(get_random_int() % 1024 + 1) * PAGE_SIZE;
		mutex_unlock(&module_kaslr_mutex);
	}
	return module_load_offset;
}
#else
static unsigned long int get_module_load_offset(void)
{
	return 0;
}
#endif

#ifdef CONFIG_X86_PIE
static u64 find_got_kernel_entry(Elf64_Sym *sym, const Elf64_Rela *rela)
{
	u64 *pos;

	for (pos = (u64 *)__start_got; pos < (u64 *)__end_got; pos++) {
		if (*pos == sym->st_value)
			return (u64)pos + rela->r_addend;
	}

	return 0;
}

static u64 module_emit_got_entry(struct module *mod, void *loc,
				 const Elf64_Rela *rela, Elf64_Sym *sym)
{
	struct mod_got_sec *gotsec = &mod->arch.core;
	u64 *got = (u64 *)gotsec->got->sh_addr;
	int i = gotsec->got_num_entries;
	u64 ret;

	/* Check if we can use the kernel GOT */
	ret = find_got_kernel_entry(sym, rela);
	if (ret)
		return ret;

	got[i] = sym->st_value;

	/*
	 * Check if the entry we just created is a duplicate. Given that the
	 * relocations are sorted, this will be the last entry we allocated.
	 * (if one exists).
	 */
	if (i > 0 && got[i] == got[i - 2]) {
		ret = (u64)&got[i - 1];
	} else {
		gotsec->got_num_entries++;
		BUG_ON(gotsec->got_num_entries > gotsec->got_max_entries);
		ret = (u64)&got[i];
	}

	return ret + rela->r_addend;
}

#define cmp_3way(a, b)	((a) < (b) ? -1 : (a) > (b))

static int cmp_rela(const void *a, const void *b)
{
	const Elf64_Rela *x = a, *y = b;
	int i;

	/* sort by type, symbol index and addend */
	i = cmp_3way(ELF64_R_TYPE(x->r_info), ELF64_R_TYPE(y->r_info));
	if (i == 0)
		i = cmp_3way(ELF64_R_SYM(x->r_info), ELF64_R_SYM(y->r_info));
	if (i == 0)
		i = cmp_3way(x->r_addend, y->r_addend);
	return i;
}

static bool duplicate_rel(const Elf64_Rela *rela, int num)
{
	/*
	 * Entries are sorted by type, symbol index and addend. That means
	 * that, if a duplicate entry exists, it must be in the preceding
	 * slot.
	 */
	return num > 0 && cmp_rela(rela + num, rela + num - 1) == 0;
}

static unsigned int count_gots(Elf64_Sym *syms, Elf64_Rela *rela, int num)
{
	unsigned int ret = 0;
	Elf64_Sym *s;
	int i;

	for (i = 0; i < num; i++) {
		switch (ELF64_R_TYPE(rela[i].r_info)) {
		case R_X86_64_GOTPCREL:
			s = syms + ELF64_R_SYM(rela[i].r_info);

			/*
			 * Use the kernel GOT when possible, else reserve a
			 * custom one for this module.
			 */
			if (!duplicate_rel(rela, i) &&
			    !find_got_kernel_entry(s, rela + i))
				ret++;
			break;
		}
	}
	return ret;
}

/*
 * Generate GOT entries for GOTPCREL relocations that do not exists in the
 * kernel GOT. Based on arm64 module-plts implementation.
 */
int module_frob_arch_sections(Elf_Ehdr *ehdr, Elf_Shdr *sechdrs,
			      char *secstrings, struct module *mod)
{
	unsigned long gots = 0;
	Elf_Shdr *symtab = NULL;
	Elf64_Sym *syms = NULL;
	char *strings, *name;
	int i;

	/*
	 * Find the empty .got section so we can expand it to store the PLT
	 * entries. Record the symtab address as well.
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(secstrings + sechdrs[i].sh_name, ".got")) {
			mod->arch.core.got = sechdrs + i;
		} else if (sechdrs[i].sh_type == SHT_SYMTAB) {
			symtab = sechdrs + i;
			syms = (Elf64_Sym *)symtab->sh_addr;
		}
	}

	if (!mod->arch.core.got) {
		pr_err("%s: module GOT section missing\n", mod->name);
		return -ENOEXEC;
	}
	if (!syms) {
		pr_err("%s: module symtab section missing\n", mod->name);
		return -ENOEXEC;
	}

	for (i = 0; i < ehdr->e_shnum; i++) {
		Elf64_Rela *rels = (void *)ehdr + sechdrs[i].sh_offset;
		int numrels = sechdrs[i].sh_size / sizeof(Elf64_Rela);

		if (sechdrs[i].sh_type != SHT_RELA)
			continue;

		/* sort by type, symbol index and addend */
		sort(rels, numrels, sizeof(Elf64_Rela), cmp_rela, NULL);

		gots += count_gots(syms, rels, numrels);
	}

	mod->arch.core.got->sh_type = SHT_NOBITS;
	mod->arch.core.got->sh_flags = SHF_ALLOC;
	mod->arch.core.got->sh_addralign = L1_CACHE_BYTES;
	mod->arch.core.got->sh_size = (gots + 1) * sizeof(u64);
	mod->arch.core.got_num_entries = 0;
	mod->arch.core.got_max_entries = gots;

	/*
	 * If a _GLOBAL_OFFSET_TABLE_ symbol exists, make it absolute for
	 * modules to correctly reference it. Similar to s390 implementation.
	 */
	strings = (void *) ehdr + sechdrs[symtab->sh_link].sh_offset;
	for (i = 0; i < symtab->sh_size/sizeof(Elf_Sym); i++) {
		if (syms[i].st_shndx != SHN_UNDEF)
			continue;
		name = strings + syms[i].st_name;
		if (!strcmp(name, "_GLOBAL_OFFSET_TABLE_")) {
			syms[i].st_shndx = SHN_ABS;
			break;
		}
	}
	return 0;
}
#endif

void *module_alloc(unsigned long size)
{
	void *p;

	if (PAGE_ALIGN(size) > MODULES_LEN)
		return NULL;

	p = __vmalloc_node_range(size, MODULE_ALIGN,
				    MODULES_VADDR + get_module_load_offset(),
				    MODULES_END, GFP_KERNEL,
				    PAGE_KERNEL, 0, NUMA_NO_NODE,
				    __builtin_return_address(0));
	if (p && (kasan_module_alloc(p, size) < 0)) {
		vfree(p);
		return NULL;
	}

	return p;
}

#ifdef CONFIG_X86_32
int apply_relocate(Elf32_Shdr *sechdrs,
		   const char *strtab,
		   unsigned int symindex,
		   unsigned int relsec,
		   struct module *me)
{
	unsigned int i;
	Elf32_Rel *rel = (void *)sechdrs[relsec].sh_addr;
	Elf32_Sym *sym;
	uint32_t *location;

	DEBUGP("Applying relocate section %u to %u\n",
	       relsec, sechdrs[relsec].sh_info);
	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		/* This is where to make the change */
		location = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr
			+ rel[i].r_offset;
		/* This is the symbol it is referring to.  Note that all
		   undefined symbols have been resolved.  */
		sym = (Elf32_Sym *)sechdrs[symindex].sh_addr
			+ ELF32_R_SYM(rel[i].r_info);

		switch (ELF32_R_TYPE(rel[i].r_info)) {
		case R_386_32:
			/* We add the value into the location given */
			*location += sym->st_value;
			break;
		case R_386_PC32:
			/* Add the value, subtract its position */
			*location += sym->st_value - (uint32_t)location;
			break;
		default:
			pr_err("%s: Unknown relocation: %u\n",
			       me->name, ELF32_R_TYPE(rel[i].r_info));
			return -ENOEXEC;
		}
	}
	return 0;
}
#else /*X86_64*/
int apply_relocate_add(Elf64_Shdr *sechdrs,
		   const char *strtab,
		   unsigned int symindex,
		   unsigned int relsec,
		   struct module *me)
{
	unsigned int i;
	Elf64_Rela *rel = (void *)sechdrs[relsec].sh_addr;
	Elf64_Sym *sym;
	void *loc;
	u64 val;

	DEBUGP("Applying relocate section %u to %u\n",
	       relsec, sechdrs[relsec].sh_info);
	for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
		/* This is where to make the change */
		loc = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr
			+ rel[i].r_offset;

		/* This is the symbol it is referring to.  Note that all
		   undefined symbols have been resolved.  */
		sym = (Elf64_Sym *)sechdrs[symindex].sh_addr
			+ ELF64_R_SYM(rel[i].r_info);

		DEBUGP("type %d st_value %Lx r_addend %Lx loc %Lx\n",
		       (int)ELF64_R_TYPE(rel[i].r_info),
		       sym->st_value, rel[i].r_addend, (u64)loc);

		val = sym->st_value + rel[i].r_addend;

		switch (ELF64_R_TYPE(rel[i].r_info)) {
		case R_X86_64_NONE:
			break;
		case R_X86_64_64:
			if (*(u64 *)loc != 0)
				goto invalid_relocation;
			*(u64 *)loc = val;
			break;
		case R_X86_64_32:
			if (*(u32 *)loc != 0)
				goto invalid_relocation;
			*(u32 *)loc = val;
			if (val != *(u32 *)loc)
				goto overflow;
			break;
		case R_X86_64_32S:
			if (*(s32 *)loc != 0)
				goto invalid_relocation;
			*(s32 *)loc = val;
			if ((s64)val != *(s32 *)loc)
				goto overflow;
			break;
#ifdef CONFIG_X86_PIE
		case R_X86_64_GOTPCREL:
			val = module_emit_got_entry(me, loc, rel + i, sym);
			/* fallthrough */
#endif
		case R_X86_64_PC32:
		case R_X86_64_PLT32:
			if (*(u32 *)loc != 0)
				goto invalid_relocation;
			val -= (u64)loc;
			*(u32 *)loc = val;
			if (IS_ENABLED(CONFIG_X86_PIE) &&
			    (s64)val != *(s32 *)loc)
				goto overflow;
			break;
		default:
			pr_err("%s: Unknown rela relocation: %llu\n",
			       me->name, ELF64_R_TYPE(rel[i].r_info));
			return -ENOEXEC;
		}
	}
	return 0;

invalid_relocation:
	pr_err("x86/modules: Skipping invalid relocation target, existing value is nonzero for type %d, loc %p, val %Lx\n",
	       (int)ELF64_R_TYPE(rel[i].r_info), loc, val);
	return -ENOEXEC;

overflow:
	pr_err("overflow in relocation type %d val %Lx\n",
	       (int)ELF64_R_TYPE(rel[i].r_info), val);
	pr_err("`%s' likely too far from the kernel\n", me->name);
	return -ENOEXEC;
}
#endif

int module_finalize(const Elf_Ehdr *hdr,
		    const Elf_Shdr *sechdrs,
		    struct module *me)
{
	const Elf_Shdr *s, *text = NULL, *alt = NULL, *locks = NULL,
		*para = NULL, *orc = NULL, *orc_ip = NULL;
	char *secstrings = (void *)hdr + sechdrs[hdr->e_shstrndx].sh_offset;

	for (s = sechdrs; s < sechdrs + hdr->e_shnum; s++) {
		if (!strcmp(".text", secstrings + s->sh_name))
			text = s;
		if (!strcmp(".altinstructions", secstrings + s->sh_name))
			alt = s;
		if (!strcmp(".smp_locks", secstrings + s->sh_name))
			locks = s;
		if (!strcmp(".parainstructions", secstrings + s->sh_name))
			para = s;
		if (!strcmp(".orc_unwind", secstrings + s->sh_name))
			orc = s;
		if (!strcmp(".orc_unwind_ip", secstrings + s->sh_name))
			orc_ip = s;
	}

	if (alt) {
		/* patch .altinstructions */
		void *aseg = (void *)alt->sh_addr;
		apply_alternatives(aseg, aseg + alt->sh_size);
	}
	if (locks && text) {
		void *lseg = (void *)locks->sh_addr;
		void *tseg = (void *)text->sh_addr;
		alternatives_smp_module_add(me, me->name,
					    lseg, lseg + locks->sh_size,
					    tseg, tseg + text->sh_size);
	}

	if (para) {
		void *pseg = (void *)para->sh_addr;
		apply_paravirt(pseg, pseg + para->sh_size);
	}

	/* make jump label nops */
	jump_label_apply_nops(me);

	if (orc && orc_ip)
		unwind_module_init(me, (void *)orc_ip->sh_addr, orc_ip->sh_size,
				   (void *)orc->sh_addr, orc->sh_size);

	return 0;
}

void module_arch_cleanup(struct module *mod)
{
	alternatives_smp_module_del(mod);
}
