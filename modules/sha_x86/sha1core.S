   .file "sha1core.S"
   .text
   .p2align 4,,15

.global sha160_core
   .type   sha160_core, @function
sha160_core:
        pushl   %ebp
        pushl   %edi
        pushl   %esi
        pushl   %ebx

        movl    24(%esp), %ebp   # byte input[64]
        movl    28(%esp), %edi   # u32bit W[80]

        movl    $0, %esi  # loop counter

        .p2align 4,,7
.LOAD_INPUT_LOOP:
        movl    0(%ebp), %eax
        bswapl %eax

        movl    4(%ebp), %ebx
        bswapl %ebx
        movl   %eax, 0(%edi,%esi,4)

        movl    8(%ebp), %ecx
        bswapl %ecx
        movl   %ebx, 4(%edi,%esi,4)

        movl   12(%ebp), %edx
        bswapl %edx
        movl   %ecx, 8(%edi,%esi,4)

        movl   %edx, 12(%edi,%esi,4)

        addl  $4, %esi
        addl $16, %ebp
        cmpl $16, %esi
     jne        .LOAD_INPUT_LOOP

        leal    64(%edi), %ebp

        .p2align 4,,7
.EXPANSION_LOOP:
        addl $4, %esi

        xorl     %eax,  %eax
        movl  -4(%ebp), %ebx
        movl  -8(%ebp), %ecx
        movl -12(%ebp), %edx

        xorl -20(%ebp), %eax
        xorl -24(%ebp), %ebx
        xorl -28(%ebp), %ecx
        xorl -32(%ebp), %edx

        xorl -44(%ebp), %eax
        xorl -48(%ebp), %ebx
        xorl -52(%ebp), %ecx
        xorl -52(%ebp), %eax

        xorl -56(%ebp), %edx
        xorl -56(%ebp), %ebx
        xorl -60(%ebp), %ecx
        xorl -64(%ebp), %edx

        roll $1, %edx

        roll $1, %ecx
        movl %edx, (%ebp)

        roll $1, %ebx
        movl %ecx, 4(%ebp)

        xorl %edx, %eax
        movl %ebx, 8(%ebp)
        roll $1, %eax
        movl %eax, 12(%ebp)

        addl $16, %ebp
        cmpl $80, %esi
    jne .EXPANSION_LOOP

   movl 20(%esp), %ebp
   movl 0(%ebp), %eax
   movl 4(%ebp), %ebx
   movl 8(%ebp), %ecx
   movl 12(%ebp), %edx
   movl 16(%ebp), %esi

#define MAGIC1 0x5A827999
#define MAGIC2 0x6ED9EBA1
#define MAGIC3 0x8F1BBCDC
#define MAGIC4 0xCA62C1D6

#define F1(A, B, C, D, E, TEMP, MSG) \
   addl 4*MSG(%edi), E          ; \
   movl C, TEMP                 ; \
   roll $5, A                   ; \
   xorl D, TEMP                 ; \
   addl A, E                    ; \
   andl B, TEMP                 ; \
   rorl $2, B                   ; \
   xorl D, TEMP                 ; \
   leal MAGIC1(E,TEMP,1), E     ; \
   rorl $5, A                   ;

#define F2_OR_F4(A, B, C, D, E, TEMP, MSG, MAGIC) \
   addl 4*MSG(%edi), E          ; \
   movl B, TEMP                 ; \
   roll $5, A                   ; \
   xorl D, TEMP                 ; \
   addl A, E                    ; \
   xorl C, TEMP                 ; \
   rorl $2, B                   ; \
   leal MAGIC(E,TEMP,1), E      ; \
   rorl $5, A                   ;

#define F3(A, B, C, D, E, TEMP, MSG) \
   addl 4*MSG(%edi), E          ; \
   movl B, TEMP                 ; \
   roll $5, A                   ; \
   orl  C, TEMP                 ; \
   movl B, (%edi)               ; \
   andl D, TEMP                 ; \
   andl C, (%edi)               ; \
   orl  (%edi), TEMP            ; \
   addl A, E                    ; \
   leal MAGIC3(E,TEMP,1), E     ; \
   rorl $2, B                   ; \
   rorl $5, A                   ;

#define F2(A, B, C, D, E, TEMP, MSG) \
   F2_OR_F4(A, B, C, D, E, TEMP, MSG, MAGIC2)

#define F4(A, B, C, D, E, TEMP, MSG) \
   F2_OR_F4(A, B, C, D, E, TEMP, MSG, MAGIC4)

#define F_BLOCK(F, MSG) \
    F(%eax, %ebx, %ecx, %edx, %esi, %ebp, (MSG+0)) \
    F(%esi, %eax, %ebx, %ecx, %edx, %ebp, (MSG+1)) \
    F(%edx, %esi, %eax, %ebx, %ecx, %ebp, (MSG+2)) \
    F(%ecx, %edx, %esi, %eax, %ebx, %ebp, (MSG+3)) \
    F(%ebx, %ecx, %edx, %esi, %eax, %ebp, (MSG+4))

   F_BLOCK(F1, 0)
   F_BLOCK(F1, 5)
   F_BLOCK(F1, 10)
   F_BLOCK(F1, 15)

   F_BLOCK(F2, 20)
   F_BLOCK(F2, 25)
   F_BLOCK(F2, 30)
   F_BLOCK(F2, 35)

   F_BLOCK(F3, 40)
   F_BLOCK(F3, 45)
   F_BLOCK(F3, 50)
   F_BLOCK(F3, 55)

   F_BLOCK(F4, 60)
   F_BLOCK(F4, 65)
   F_BLOCK(F4, 70)
   F_BLOCK(F4, 75)

   movl 20(%esp), %ebp
   addl %eax, 0(%ebp)
   addl %ebx, 4(%ebp)
   addl %ecx, 8(%ebp)
   addl %edx, 12(%ebp)
   addl %esi, 16(%ebp)

        popl    %ebx
        popl    %esi
        popl    %edi
        popl    %ebp
        ret
