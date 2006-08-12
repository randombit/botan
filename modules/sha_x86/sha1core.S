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

#define MAGIC1 $0x5A827999
#define MAGIC2 $0x6ED9EBA1
#define MAGIC3 $0x8F1BBCDC
#define MAGIC4 $0xCA62C1D6
   
#define FUNC1(B, C, D, TEMP)   \
   movl C, TEMP                 ; \
   xorl D, TEMP                 ; \
   andl B, TEMP                 ; \
   xorl D, TEMP

#define FUNC2(B, C, D, TEMP)   \
   movl B, TEMP                 ; \
   xorl C, TEMP                 ; \
   xorl D, TEMP  

#define FUNC3(B, C, D, TEMP)   \
   movl B, TEMP                 ; \
   orl  C, TEMP                 ; \
   andl D, TEMP                 ; \
   movl B, (%edi)               ; \
   andl C, (%edi)               ; \
   orl  (%edi), TEMP           
   
#define FUNC4(B, C, D, TEMP)   \
   movl B, TEMP                 ; \
   xorl C, TEMP                 ; \
   xorl D, TEMP  

#define F(A, B, C, D, E, TEMP, MAGIC, FUNC) \
   addl (%edi), E               ; \
   FUNC(B, C, D, TEMP)          ; \
   addl $4, %edi                ; \
   addl TEMP, E                 ; \
   addl MAGIC, E                ; \
   roll $5, A                   ; \
   addl A, E                    ; \
   rorl $5, A                   ; \
   roll $30, B                  ; 

#define F1(A, B, C, D, E, TEMP) \
   F(A, B, C, D, E, TEMP, MAGIC1, FUNC1)

#define F2(A, B, C, D, E, TEMP) \
   F(A, B, C, D, E, TEMP, MAGIC2, FUNC2)

#define F3(A, B, C, D, E, TEMP) \
   F(A, B, C, D, E, TEMP, MAGIC3, FUNC3)

#define F4(A, B, C, D, E, TEMP) \
   F(A, B, C, D, E, TEMP, MAGIC4, FUNC4)
   
#define F_BLOCK(F) \
    F(%eax, %ebx, %ecx, %edx, %esi, %ebp) \
    F(%esi, %eax, %ebx, %ecx, %edx, %ebp) \
    F(%edx, %esi, %eax, %ebx, %ecx, %ebp) \
    F(%ecx, %edx, %esi, %eax, %ebx, %ebp) \
    F(%ebx, %ecx, %edx, %esi, %eax, %ebp)
/*
    F1(%eax, %ebx, %ecx, %edx, %esi, %ebp)
    F1(%esi, %eax, %ebx, %ecx, %edx, %ebp)
    F1(%edx, %esi, %eax, %ebx, %ecx, %ebp)
    F1(%ecx, %edx, %esi, %eax, %ebx, %ebp)
    F1(%ebx, %ecx, %edx, %esi, %eax, %ebp)
*/

   F_BLOCK(F1)
   F_BLOCK(F1)
   F_BLOCK(F1)
   F_BLOCK(F1)

   F_BLOCK(F2)
   F_BLOCK(F2)
   F_BLOCK(F2)
   F_BLOCK(F2)

   F_BLOCK(F3)
   F_BLOCK(F3)
   F_BLOCK(F3)
   F_BLOCK(F3)

   F_BLOCK(F4)
   F_BLOCK(F4)
   F_BLOCK(F4)
   F_BLOCK(F4)

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
