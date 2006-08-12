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

        movl    24(%esp), %ecx   # byte input[64]
        movl    28(%esp), %edi   # u32bit W[80]

        movl    $0, %esi  # loop counter

        .p2align 4,,7
.LOAD_INPUT_LOOP:  
        movl    0(%ecx), %eax
        addl    $4, %ecx
        incl    %esi

        bswapl  %eax
        movl    %eax, -4(%edi,%esi,4)
        cmpl    $16, %esi
        jne     .LOAD_INPUT_LOOP

     leal    64(%edi), %edx
    
        .p2align 4,,7
       // here esi == 16
.EXPANSION_LOOP:
        movl    -32(%edx), %eax
        xorl    -12(%edx), %eax
        xorl    -56(%edx), %eax
        xorl    -64(%edx), %eax
        incl    %esi
        roll    $1, %eax

        movl    %eax, (%edx)
        addl    $4, %edx
        cmpl    $80, %esi
        jne .EXPANSION_LOOP

   // here: edi = W
   
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
