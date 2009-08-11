/*
* Montgomery Reduction Source File
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/asm_macr.h>

START_LISTING(mp_monty.S)

START_FUNCTION(bigint_monty_redc)
	pushq	%r15	#
	pushq	%r14	#
	pushq	%r13	#
	pushq	%r12	#
	pushq	%rbp	#
	pushq	%rbx	#

        movq	%rdi, %r14	# z
	movq	%rdx, %r12	# x
	movl	%esi, %ebp	# z_size

	xorl	%esi, %esi	# j.76
	movq	%r8, -16(%rsp)	# u, u
	movl	%ecx, %ebx	# x_size, x_size
	movl	%ecx, %r8d	# x_size, blocks_of_8
	andl	$-8, %r8d	#, blocks_of_8
	testl	%ecx, %ecx	# x_size
	je	.L3	#,
	mov	%ecx, %eax	# x_size, pretmp.71
	leal	1(%rbx), %r15d	#, k.73
	salq	$3, %rax	#,
	xorl	%r13d, %r13d	# j
	movq	%rax, -8(%rsp)	#, pretmp.21
	.p2align 4,,10
	.p2align 3
.L11:
	mov	%r13d, %eax	# j, j
	movq	-16(%rsp), %rdi	# u, y
	leaq	(%r14,%rax,8), %r11	#, z_j
	xorl	%r9d, %r9d	# i
	imulq	(%r11), %rdi	#* z_j, y
	xorl	%r10d, %r10d	# carry
	testl	%r8d, %r8d	# blocks_of_8
	je	.L7	#,
	.p2align 4,,10
	.p2align 3
.LOOP_MUL_ADD:
	mov	%r9d, %ecx	# i, i
	addl	$8, %r9d	#, i
	salq	$3, %rcx	#, D.2315
	leaq	(%r11,%rcx), %rsi	#, tmp130
	leaq	(%r12,%rcx), %rcx	#, tmp131

	movq 8*0(%rcx), %rax
	mulq %rdi	# y
	addq %r10, %rax	# carry
	adcq $0,%rdx
	addq 8*0(%rsi), %rax
	adcq $0,%rdx
	movq %rdx,%r10	# carry
	movq %rax, 8*0 (%rsi)

        movq 8*1(%rcx), %rax
	mulq %rdi	# y
	addq %r10, %rax	# carry
	adcq $0,%rdx
	addq 8*1(%rsi), %rax
	adcq $0,%rdx
	movq %rdx,%r10	# carry
	movq %rax, 8*1 (%rsi)

        movq 8*2(%rcx), %rax
	mulq %rdi	# y
	addq %r10, %rax	# carry
	adcq $0,%rdx
	addq 8*2(%rsi), %rax
	adcq $0,%rdx
	movq %rdx,%r10	# carry
	movq %rax, 8*2 (%rsi)

        movq 8*3(%rcx), %rax
	mulq %rdi	# y
	addq %r10, %rax	# carry
	adcq $0,%rdx
	addq 8*3(%rsi), %rax
	adcq $0,%rdx
	movq %rdx,%r10	# carry
	movq %rax, 8*3 (%rsi)

        movq 8*4(%rcx), %rax
	mulq %rdi	# y
	addq %r10, %rax	# carry
	adcq $0,%rdx
	addq 8*4(%rsi), %rax
	adcq $0,%rdx
	movq %rdx,%r10	# carry
	movq %rax, 8*4 (%rsi)

        movq 8*5(%rcx), %rax
	mulq %rdi	# y
	addq %r10, %rax	# carry
	adcq $0,%rdx
	addq 8*5(%rsi), %rax
	adcq $0,%rdx
	movq %rdx,%r10	# carry
	movq %rax, 8*5 (%rsi)

        movq 8*6(%rcx), %rax
	mulq %rdi	# y
	addq %r10, %rax	# carry
	adcq $0,%rdx
	addq 8*6(%rsi), %rax
	adcq $0,%rdx
	movq %rdx,%r10	# carry
	movq %rax, 8*6 (%rsi)

        movq 8*7(%rcx), %rax
	mulq %rdi	# y
	addq %r10, %rax	# carry
	adcq $0,%rdx
	addq 8*7(%rsi), %rax
	adcq $0,%rdx
	movq %rdx,%r10	# carry
	movq %rax, 8*7 (%rsi)

	cmpl	%r9d, %r8d	# i, blocks_of_8
	jne	.LOOP_MUL_ADD	#,
	cmpl	%r8d, %ebx	# blocks_of_8, x_size
	je	.L8	#,
.L7:
	movl	%r8d, %esi	# blocks_of_8, i
	.p2align 4,,10
	.p2align 3
.L5:
	mov	%esi, %eax	# i, i
	movq	%rdi, %rcx	# y, b
	leaq	(%r11, %rax,8), %r9	#, D.2325
	incl	%esi	# i
	movq	(%r12, %rax,8), %rax	#* x, tmp133

        mulq %rcx	# b
	addq (%r9), %rax	#* D.2325, a
	adcq $0,%rdx	#
	addq %r10, %rax	# carry, a
	adcq $0,%rdx	#

	cmpl	%esi, %ebx	# i, x_size
	movq	%rdx, %r10	#, carry
	movq	%rax, (%r9)	# a,* D.2325
	jne	.L5	#,
.L8:
	movq	-8(%rsp), %rdx	# pretmp.21,
	leaq	(%r11,%rdx), %rax	#, D.2332
	movq	(%rax), %rcx	#* D.2332, D.2333
	leaq	(%r10,%rcx), %rdx	#, z_sum
	movq	%rdx, (%rax)	# z_sum,* D.2332
	cmpq	%rdx, %rcx	# z_sum, D.2333
	jbe	.L9	#,
	cmpl	%ebp, %r15d	# z_size, k.73
	je	.L9	#,
	movl	%r15d, %ecx	# k.73, k
	jmp	.L10	#
	.p2align 4,,10
	.p2align 3
.L31:
	incl	%ecx	# k
	cmpl	%ecx, %ebp	# k, z_size
	.p2align 4,,4
	.p2align 3
	je	.L9	#,
.L10:
	mov	%ecx, %edx	# k, k
	leaq	(%r11,%rdx,8), %rdx	#, D.2342
	movq	(%rdx), %rax	#* D.2342, tmp136
	incq	%rax	# D.2344
	movq	%rax, (%rdx)	# D.2344,* D.2342
	testq	%rax, %rax	# D.2344
	je	.L31	#,
.L9:
	incl	%r13d	# j
	decl	%ebp	# z_size
	cmpl	%r13d, %ebx	# j, x_size
	jne	.L11	#,
	movl	%ebx, %esi	# x_size, j.76
.L3:
	leal	(%rbx,%rbx), %eax	#, tmp137
	mov	%eax, %eax
	leaq	(%r14, %rax,8), %rdi	#, D.2349
	cmpq	$0, (%rdi)	#,* D.2349
	jne	.L12	#,
	testl	%ebx, %ebx	# x_size
	je	.L12	#,
	leal	-1(%rbx), %ecx	#, j
	leal	(%rsi,%rcx), %edx	#, tmp141
	mov	%ecx, %eax	# j, j
	movq	(%r14,%rdx,8), %rbp	#* z,
	cmpq	%rbp, (%r12, %rax,8)	#,* x
	jb	.L12	#,
	ja	.L_EXIT	#,
	leal	-2(%rsi,%rbx), %edx	#, ivtmp.45
	jmp	.L14	#
	.p2align 4,,10
	.p2align 3
.L15:
	mov	%edx, %eax	# ivtmp.45, ivtmp.45
	decl	%ecx	# j
	movq	(%r14, %rax,8), %rsi	#* z, D.2360
	mov	%ecx, %eax	# j, j
	movq	(%r12, %rax,8), %rax	#* x, temp.68
	cmpq	%rax, %rsi
	ja	.L12	#,
	decl	%edx	# ivtmp.45
	cmpq	%rax, %rsi
	jb	.L_EXIT	#,
.L14:
	testl	%ecx, %ecx	# j
	jne	.L15	#,
.L12:
	xorl	%ecx, %ecx	# j
	xorl	%r10d, %r10d	# carry
	mov	%ebx, %esi	# x_size, pretmp.19
	testl	%r8d, %r8d	# blocks_of_8
	je	.L17	#,
	.p2align 4,,10
	.p2align 3
.L22:
	mov	%ecx, %edx	# j, D.2375
	addl	$8, %ecx	#, j
	leaq	(%rdx,%rsi), %rax	#, tmp146
	leaq	(%r12,%rdx,8), %rdx	#, tmp150
	leaq	(%r14, %rax,8), %rax	#, tmp148

	rorq %r10	# carry

        movq 8*0(%rdx), %r10
	sbbq %r10, 8*0(%rax)

        movq 8*1(%rdx), %r10
	sbbq %r10, 8*1(%rax)

        movq 8*2(%rdx), %r10
	sbbq %r10, 8*2(%rax)

        movq 8*3(%rdx), %r10
	sbbq %r10, 8*3(%rax)

        movq 8*4(%rdx), %r10
	sbbq %r10, 8*4(%rax)

        movq 8*5(%rdx), %r10
	sbbq %r10, 8*5(%rax)

        movq 8*6(%rdx), %r10
	sbbq %r10, 8*6(%rax)

        movq 8*7(%rdx), %r10
	sbbq %r10, 8*7(%rax)

        sbbq %r10,%r10	# carry
	negq %r10	# carry

	cmpl	%ecx, %r8d	# j, blocks_of_8
	jne	.L22	#,
.L17:
	cmpl	%r8d, %ebx	# blocks_of_8, x_size
	je	.L19	#,
	leal	(%r8,%rbx), %r9d	#, ivtmp.33
	movl	%r8d, %esi	# blocks_of_8, j
	.p2align 4,,10
	.p2align 3
.L20:
	mov	%r9d, %eax	# ivtmp.33, ivtmp.33
	mov	%esi, %ecx	# j, j
	leaq	(%r14, %rax,8), %rax	#, D.2387
	incl	%esi	# j
	movq	(%rax), %rdx	#* D.2387, tmp153
	incl	%r9d	# ivtmp.33

	rorq %r10	# carry
	sbbq (%r12,%rcx,8),%rdx	#* x, x
	sbbq %r10,%r10	# carry
	negq %r10	# carry

	cmpl	%esi, %ebx	# j, x_size
	movq	%rdx, (%rax)	# x,* D.2387
	jne	.L20	#,
.L19:
	testq	%r10, %r10	# carry
	je	.L_EXIT	#,
	decq	(%rdi)	#* D.2349
.L_EXIT:
	popq	%rbx	#
	popq	%rbp	#
	popq	%r12	#
	popq	%r13	#
	popq	%r14	#
	popq	%r15	#
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
