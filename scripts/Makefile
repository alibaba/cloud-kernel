# SPDX-License-Identifier: GPL-2.0
###
# scripts contains sources for various helper programs used throughout
# the kernel for the build process.
# ---------------------------------------------------------------------------
# kallsyms:      Find all symbols in vmlinux
# pnmttologo:    Convert pnm files to logo files
# conmakehash:   Create chartable
# conmakehash:	 Create arrays for initializing the kernel console tables

HOST_EXTRACFLAGS += -I$(srctree)/tools/include

hostprogs-$(CONFIG_BUILD_BIN2C)  += bin2c
hostprogs-$(CONFIG_KALLSYMS)     += kallsyms
hostprogs-$(CONFIG_LOGO)         += pnmtologo
hostprogs-$(CONFIG_VT)           += conmakehash
hostprogs-$(BUILD_C_RECORDMCOUNT) += recordmcount
hostprogs-$(CONFIG_BUILDTIME_TABLE_SORT) += sorttable
hostprogs-$(CONFIG_ASN1)	 += asn1_compiler
hostprogs-$(CONFIG_MODULE_SIG)	 += sign-file
hostprogs-$(CONFIG_SYSTEM_TRUSTED_KEYRING) += extract-cert
hostprogs-$(CONFIG_SYSTEM_EXTRA_CERTIFICATE) += insert-sys-cert

HOSTCFLAGS_sorttable.o = -I$(srctree)/tools/include
HOSTLDLIBS_sorttable = -lpthread
HOSTCFLAGS_asn1_compiler.o = -I$(srctree)/include
HOSTLDLIBS_sign-file = -lcrypto
HOSTLDLIBS_extract-cert = -lcrypto

ifdef CONFIG_UNWINDER_ORC
HOSTCFLAGS_sorttable.o += -I$(srctree)/tools/objtool/arch/$(SRCARCH)/include
ifneq ($(SKIP_STACK_VALIDATION),1)
HOSTCFLAGS_sorttable.o += -DUNWINDER_ORC_ENABLED
endif
endif

ifdef CONFIG_BUILDTIME_MCOUNT_SORT
HOSTCFLAGS_sorttable.o += -DMCOUNT_SORT_ENABLED
endif

always		:= $(hostprogs-y) $(hostprogs-m)

# The following hostprogs-y programs are only build on demand
hostprogs-y += unifdef

# These targets are used internally to avoid "is up to date" messages
PHONY += build_unifdef
build_unifdef: $(obj)/unifdef
	@:

subdir-$(CONFIG_MODVERSIONS) += genksyms
subdir-y                     += mod
subdir-$(CONFIG_SECURITY_SELINUX) += selinux
subdir-$(CONFIG_DTC)         += dtc
subdir-$(CONFIG_GDB_SCRIPTS) += gdb

# Let clean descend into subdirs
subdir-	+= basic kconfig package gcc-plugins
