/*************************************************
* Montgomery Reduction Source File               *
* (C) 2008 Jack Lloyd                            *
*************************************************/

#include <botan/asm_macr.h>

START_LISTING(mp_monty.S)

START_FUNCTION(bigint_monty_redc)
	pushq	%r15	#

	movq	%r8, %r15	# u, u
	pushq	%r14	#

	pushq	%r13	#

	pushq	%r12	#

	movq	%rdi, %r12	# z, z
	pushq	%rbp	#

	movl	%esi, %edi	# z_size, z_size
	pushq	%rbx	#

        ZEROIZE(%esi)
	movq	%rdx, %rbp	# x, x
	movl	%ecx, %ebx	# x_size, x_size
	testl	%ecx, %ecx	# x_size
	je	.L3	#,
	mov	%ecx, %eax	# x_size, pretmp.62
	leal	1(%rbx), %r13d	#, k
	salq	$3, %rax	#,
        ZEROIZE(%r8d)
	movq	%rax, -16(%rsp)	#, pretmp.18
.L7:
	mov	%r8d, %eax	# j, j
	movq	%r15, %rsi	# u, y
	leaq	(%r12,%rax,8), %r11	#, z_j
        ZEROIZE(%r9d)           # i
	imulq	(%r11), %rsi	#* z_j, y
	ZEROIZE(%r10d)          # carry
.L4:
	mov	%r9d, %eax	# i, i
	movq	%rsi, %rcx	# y, b
	leaq	(%r11,%rax,8), %rdx	#,
	incl	%r9d	# i
	movq	(%rbp,%rax,8), %rax	#* x, tmp113
	movq	%rdx, %r14	#,
	movq	%rdx, -8(%rsp)	#, D.2312

	mulq %rcx	# b
	addq (%r14),%rax	#, a
	adcq $0,%rdx	#
	addq %r10,%rax	# carry, a
	adcq $0,%rdx	#

	cmpl	%r9d, %ebx	# i, x_size
	movq	%rdx, %r10	#, carry
	movq	%rax, (%r14)	# a,
	jne	.L4	#,
	movq	-16(%rsp), %rdx	# pretmp.18,
	leaq	(%r11,%rdx), %rax	#, D.2319
	movq	(%rax), %rcx	#* D.2319, D.2320
	leaq	(%r10,%rcx), %rdx	#, z_sum
	movq	%rdx, (%rax)	# z_sum,* D.2319
	cmpq	%rdx, %rcx	# z_sum, D.2320
	jbe	.L5	#,
	cmpl	%edi, %r13d	# z_size, k
	je	.L5	#,
	movl	%r13d, %ecx	# k, k.52
	jmp	.L6	#
.L20:
	incl	%ecx	# k.52
	cmpl	%ecx, %edi	# k.52, z_size
	je	.L5	#,
.L6:
	mov	%ecx, %edx	# k.52, k.52
	leaq	(%r11,%rdx,8), %rdx	#, D.2330
	movq	(%rdx), %rax	#* D.2330, tmp116
	incq	%rax	# D.2332
	movq	%rax, (%rdx)	# D.2332,* D.2330
	testq	%rax, %rax	# D.2332
	je	.L20	#,
.L5:
	incl	%r8d	# j
	decl	%edi	# z_size
	cmpl	%r8d, %ebx	# j, x_size
	jne	.L7	#,
	movl	%ebx, %esi	# x_size, j.61
.L3:
	leal	(%rbx,%rbx), %eax	#, tmp117
	mov	%eax, %eax	# tmp117, tmp118
	leaq	(%r12,%rax,8), %rdi	#, D.2337
	cmpq	$0, (%rdi)	#,* D.2337
	jne	.L8	#,
	testl	%ebx, %ebx	# x_size
	je	.L14	#,
	leal	-1(%rbx), %ecx	#, j
	leal	(%rsi,%rcx), %edx	#, tmp121
	mov	%ecx, %eax	# j, j
	movq	(%rbp,%rax,8), %r8	#* x,
	cmpq	%r8, (%r12,%rdx,8)	#,* z
	ja	.L10	#,
	jb	.L14	#,
	leal	-2(%rsi,%rbx), %edx	#, ivtmp.37
	jmp	.L11	#
.L12:
	mov	%edx, %eax	# ivtmp.37, ivtmp.37
	decl	%ecx	# j
	movq	(%r12,%rax,8), %rsi	#* z, temp.55
	mov	%ecx, %eax	# j, j
	movq	(%rbp,%rax,8), %rax	#* x, D.2353
	cmpq	%rax, %rsi	# D.2353, temp.55
	ja	.L10	#,
	decl	%edx	# ivtmp.37
	cmpq	%rax, %rsi	# D.2353, temp.55
	jb	.L14	#,
.L11:
	testl	%ecx, %ecx	# j
	jne	.L12	#,
.L10:
	ZEROIZE(%esi)            # j
	ZEROIZE(%r8d)            # carry
.L13:
	leal	(%rsi,%rbx), %eax	#, tmp127
	mov	%esi, %ecx	# j, j
	leaq	(%r12,%rax,8), %rax	#, D.2361
	incl	%esi	# j
	movq	(%rax), %rdx	#* D.2361, tmp129

	rorq %r8	# carry
	sbbq (%rbp,%rcx,8),%rdx	#* x, x
	sbbq %r8,%r8	# carry
	negq %r8	# carry

	cmpl	%esi, %ebx	# j, x_size
	movq	%rdx, (%rax)	# x,* D.2361
	jne	.L13	#,
	testq	%r8, %r8	# carry
	je	.L14	#,
	decq	(%rdi)	#* D.2337
.L14:
	popq	%rbx	#
	popq	%rbp	#
	popq	%r12	#
	popq	%r13	#
	popq	%r14	#
	popq	%r15	#
	ret
.L8:
	testl	%ebx, %ebx	# x_size
	jne	.L10	#,
	jmp	.L14	#
END_FUNCTION(bigint_monty_redc)


#if 0
   #define Z_ARR    ARG_1 // rdi
#define Z_SIZE   ARG_2_32 // esi
// X_ARR is ARG_3 == rdx, moved b/c needed for multiply
#define X_SIZE   ARG_4_32 // ecx
#define U        ARG_5 // r8

/*
     We need all arguments for a while (we can reuse U eventually)
   So only temp registers are
     TEMP_1 %r10
     TEMP_2 %r11
     TEMP_3 = ARG_6 = %r9
   void return, so also
     R0 %rax (aka TEMP_9)
   is free (but needed for multiply)

   Can push:
     %rbx (base pointer, callee saved)
     %rpb (frame pointer, callee saved)
     %r12-%r15 (callee saved)

  Can push base/frame pointers since this is a leaf function
  and does not reference any data.
*/

   push %r12
   push %r13
   push %r14
   push %r15

#define LOOP_CTR_I %r12
#define LOOP_CTR_J %r13

#define CARRY    TEMP_1
#define Z_WORD   TEMP_2
#define X_ARR    TEMP_3
#define MUL_LO   %rax
#define MUL_HI   %rdx

   ASSIGN(X_ARR, ARG_3)

   /*
   ZEROIZE(CARRY)

   ASSIGN(LOOP_CTR, X_SIZE)

   JUMP_IF_ZERO(LOOP_CTR, .L_MULADD_DONE)
   JUMP_IF_LT(LOOP_CTR, 8, .LOOP_MULADD1)

#define MULADD_OP(N)                  \
   ASSIGN(MUL_LO, ARRAY8(X_ARR, N)) ; \
   ASSIGN(Z_WORD, ARRAY8(Z_ARR, N)) ; \
   MUL(Y)                           ; \
   ADD(Z_WORD, CARRY)               ; \
   ASSIGN(CARRY, MUL_HI)            ; \
   ADD_LAST_CARRY(CARRY)            ; \
   ADD(Z_WORD, MUL_LO)              ; \
   ADD_LAST_CARRY(CARRY)            ; \
   ASSIGN(ARRAY8(Z_ARR, N), Z_WORD)

ALIGN
.LOOP_MULADD8:
   MULADD_OP(0)
   MULADD_OP(1)
   MULADD_OP(2)
   MULADD_OP(3)
   MULADD_OP(4)
   MULADD_OP(5)
   MULADD_OP(6)
   MULADD_OP(7)

   SUB_IMM(LOOP_CTR, 8)
   ADD_IMM(Z_ARR, 64)
   ADD_IMM(X_ARR, 64)
   cmp IMM(8), LOOP_CTR
   jge .LOOP_MULADD8

   JUMP_IF_ZERO(LOOP_CTR, .L_MULADD_DONE)

ALIGN
.LOOP_MULADD1:
   MULADD_OP(0)

   SUB_IMM(LOOP_CTR, 1)
   ADD_IMM(Z_ARR, 8)
   ADD_IMM(X_ARR, 8)

   cmp IMM(0), LOOP_CTR
   jne .LOOP_MULADD1
*/

   pop %r15
   pop %r14
   pop %r13
   pop %r12
#endif
   