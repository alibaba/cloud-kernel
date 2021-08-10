/* AES (Rijndael) implementation (FIPS PUB 197) for x86_64
 *
 * Copyright (C) 2005 Andreas Steinmetz, <ast@domdv.de>
 *
 * License:
 * This code can be distributed under the terms of the GNU General Public
 * License (GPL) Version 2 provided that the above header down to and
 * including this sentence is retained in full.
 */

.extern crypto_ft_tab
.extern crypto_it_tab
.extern crypto_fl_tab
.extern crypto_il_tab

.text

#include <linux/linkage.h>
#include <asm/asm-offsets.h>

#define R1	%rax
#define R1E	%eax
#define R1X	%ax
#define R1H	%ah
#define R1L	%al
#define R2	%rbx
#define R2E	%ebx
#define R2X	%bx
#define R2H	%bh
#define R2L	%bl
#define R3	%rcx
#define R3E	%ecx
#define R3X	%cx
#define R3H	%ch
#define R3L	%cl
#define R4	%rdx
#define R4E	%edx
#define R4X	%dx
#define R4H	%dh
#define R4L	%dl
#define R5	%rsi
#define R5E	%esi
#define R6	%rdi
#define R6E	%edi
#define R7	%r9	/* don't use %rbp; it breaks stack traces */
#define R7E	%r9d
#define R8	%r8
#define R10	%r10
#define R11	%r11

/* Hold global for PIE support */
#define RBASE	%r12

#define prologue(FUNC,KEY,B128,B192,r1,r2,r5,r6,r7,r8,r9,r10,r11) \
	ENTRY(FUNC);			\
	pushq	RBASE;			\
	movq	r1,r2;			\
	leaq	KEY+48(r8),r9;		\
	movq	r10,r11;		\
	movl	(r7),r5 ## E;		\
	movl	4(r7),r1 ## E;		\
	movl	8(r7),r6 ## E;		\
	movl	12(r7),r7 ## E;		\
	movl	480(r8),r10 ## E;	\
	xorl	-48(r9),r5 ## E;	\
	xorl	-44(r9),r1 ## E;	\
	xorl	-40(r9),r6 ## E;	\
	xorl	-36(r9),r7 ## E;	\
	cmpl	$24,r10 ## E;		\
	jb	B128;			\
	leaq	32(r9),r9;		\
	je	B192;			\
	leaq	32(r9),r9;

#define epilogue(FUNC,r1,r2,r5,r6,r7,r8,r9) \
	movq	r1,r2;			\
	movl	r5 ## E,(r9);		\
	movl	r6 ## E,4(r9);		\
	movl	r7 ## E,8(r9);		\
	movl	r8 ## E,12(r9);		\
	popq	RBASE;			\
	ret;				\
	ENDPROC(FUNC);

#define round_mov(tab_off, reg_i, reg_o) \
	leaq	tab_off(%rip), RBASE; \
	movl	(RBASE,reg_i,4), reg_o;

#define round_xor(tab_off, reg_i, reg_o) \
	leaq	tab_off(%rip), RBASE; \
	xorl	(RBASE,reg_i,4), reg_o;

#define round(TAB,OFFSET,r1,r2,r3,r4,r5,r6,r7,r8,ra,rb,rc,rd) \
	movzbl	r2 ## H,r5 ## E;	\
	movzbl	r2 ## L,r6 ## E;	\
	round_mov(TAB+1024, r5, r5 ## E)\
	movw	r4 ## X,r2 ## X;	\
	round_mov(TAB, r6, r6 ## E)	\
	roll	$16,r2 ## E;		\
	shrl	$16,r4 ## E;		\
	movzbl	r4 ## L,r7 ## E;	\
	movzbl	r4 ## H,r4 ## E;	\
	xorl	OFFSET(r8),ra ## E;	\
	xorl	OFFSET+4(r8),rb ## E;	\
	round_xor(TAB+3072, r4, r5 ## E)\
	round_xor(TAB+2048, r7, r6 ## E)\
	movzbl	r1 ## L,r7 ## E;	\
	movzbl	r1 ## H,r4 ## E;	\
	round_mov(TAB+1024, r4, r4 ## E)\
	movw	r3 ## X,r1 ## X;	\
	roll	$16,r1 ## E;		\
	shrl	$16,r3 ## E;		\
	round_xor(TAB, r7, r5 ## E)	\
	movzbl	r3 ## L,r7 ## E;	\
	movzbl	r3 ## H,r3 ## E;	\
	round_xor(TAB+3072, r3, r4 ## E)\
	round_xor(TAB+2048, r7, r5 ## E)\
	movzbl	r1 ## L,r7 ## E;	\
	movzbl	r1 ## H,r3 ## E;	\
	shrl	$16,r1 ## E;		\
	round_xor(TAB+3072, r3, r6 ## E)\
	round_mov(TAB+2048, r7, r3 ## E)\
	movzbl	r1 ## L,r7 ## E;	\
	movzbl	r1 ## H,r1 ## E;	\
	round_xor(TAB+1024, r1, r6 ## E)\
	round_xor(TAB, r7, r3 ## E)	\
	movzbl	r2 ## H,r1 ## E;	\
	movzbl	r2 ## L,r7 ## E;	\
	shrl	$16,r2 ## E;		\
	round_xor(TAB+3072, r1, r3 ## E)\
	round_xor(TAB+2048, r7, r4 ## E)\
	movzbl	r2 ## H,r1 ## E;	\
	movzbl	r2 ## L,r2 ## E;	\
	xorl	OFFSET+8(r8),rc ## E;	\
	xorl	OFFSET+12(r8),rd ## E;	\
	round_xor(TAB+1024, r1, r3 ## E)\
	round_xor(TAB, r2, r4 ## E)

#define move_regs(r1,r2,r3,r4) \
	movl	r3 ## E,r1 ## E;	\
	movl	r4 ## E,r2 ## E;

#define entry(FUNC,KEY,B128,B192) \
	prologue(FUNC,KEY,B128,B192,R2,R8,R1,R3,R4,R6,R10,R5,R11)

#define return(FUNC) epilogue(FUNC,R8,R2,R5,R6,R3,R4,R11)

#define encrypt_round(TAB,OFFSET) \
	round(TAB,OFFSET,R1,R2,R3,R4,R5,R6,R7,R10,R5,R6,R3,R4) \
	move_regs(R1,R2,R5,R6)

#define encrypt_final(TAB,OFFSET) \
	round(TAB,OFFSET,R1,R2,R3,R4,R5,R6,R7,R10,R5,R6,R3,R4)

#define decrypt_round(TAB,OFFSET) \
	round(TAB,OFFSET,R2,R1,R4,R3,R6,R5,R7,R10,R5,R6,R3,R4) \
	move_regs(R1,R2,R5,R6)

#define decrypt_final(TAB,OFFSET) \
	round(TAB,OFFSET,R2,R1,R4,R3,R6,R5,R7,R10,R5,R6,R3,R4)

/* void aes_enc_blk(stuct crypto_tfm *tfm, u8 *out, const u8 *in) */

	entry(aes_enc_blk,0,.Le128,.Le192)
	encrypt_round(crypto_ft_tab,-96)
	encrypt_round(crypto_ft_tab,-80)
.Le192:	encrypt_round(crypto_ft_tab,-64)
	encrypt_round(crypto_ft_tab,-48)
.Le128:	encrypt_round(crypto_ft_tab,-32)
	encrypt_round(crypto_ft_tab,-16)
	encrypt_round(crypto_ft_tab,  0)
	encrypt_round(crypto_ft_tab, 16)
	encrypt_round(crypto_ft_tab, 32)
	encrypt_round(crypto_ft_tab, 48)
	encrypt_round(crypto_ft_tab, 64)
	encrypt_round(crypto_ft_tab, 80)
	encrypt_round(crypto_ft_tab, 96)
	encrypt_final(crypto_fl_tab,112)
	return(aes_enc_blk)

/* void aes_dec_blk(struct crypto_tfm *tfm, u8 *out, const u8 *in) */

	entry(aes_dec_blk,240,.Ld128,.Ld192)
	decrypt_round(crypto_it_tab,-96)
	decrypt_round(crypto_it_tab,-80)
.Ld192:	decrypt_round(crypto_it_tab,-64)
	decrypt_round(crypto_it_tab,-48)
.Ld128:	decrypt_round(crypto_it_tab,-32)
	decrypt_round(crypto_it_tab,-16)
	decrypt_round(crypto_it_tab,  0)
	decrypt_round(crypto_it_tab, 16)
	decrypt_round(crypto_it_tab, 32)
	decrypt_round(crypto_it_tab, 48)
	decrypt_round(crypto_it_tab, 64)
	decrypt_round(crypto_it_tab, 80)
	decrypt_round(crypto_it_tab, 96)
	decrypt_final(crypto_il_tab,112)
	return(aes_dec_blk)
