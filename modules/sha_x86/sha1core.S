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

#define FUNC1(B, C, D, TEMP)   \
   movl C, TEMP                 ; \
   xorl D, TEMP                 ; \
   andl B, TEMP                 ; \
   xorl D, TEMP

#define FUNC2(B, C, D, TEMP)   \
   movl B, TEMP                 ; \
   xorl C, TEMP                 ; \
   xorl D, TEMP  

#define F(A, B, C, D, E, TEMP, MSG, MAGIC, FUNC) \
   FUNC(B, C, D, TEMP)          ; \
   addl MSG, E                  ; \
   addl TEMP, E                 ; \
   addl MAGIC, E                ; \
   roll $5, A                   ; \
   addl A, E                    ; \
   rorl $5, A                   ; \
   roll $30, B

    F(%eax, %ebx, %ecx, %edx, %esi, %ebp,  0(%edi), MAGIC1, FUNC1)
    F(%esi, %eax, %ebx, %ecx, %edx, %ebp,  4(%edi), MAGIC1, FUNC1)
    F(%edx, %esi, %eax, %ebx, %ecx, %ebp,  8(%edi), MAGIC1, FUNC1)
    F(%ecx, %edx, %esi, %eax, %ebx, %ebp, 12(%edi), MAGIC1, FUNC1)
    F(%ebx, %ecx, %edx, %esi, %eax, %ebp, 16(%edi), MAGIC1, FUNC1)

    F(%eax, %ebx, %ecx, %edx, %esi, %ebp, 20(%edi), MAGIC1, FUNC1)
    F(%esi, %eax, %ebx, %ecx, %edx, %ebp, 24(%edi), MAGIC1, FUNC1)
    F(%edx, %esi, %eax, %ebx, %ecx, %ebp, 28(%edi), MAGIC1, FUNC1)
    F(%ecx, %edx, %esi, %eax, %ebx, %ebp, 32(%edi), MAGIC1, FUNC1)
    F(%ebx, %ecx, %edx, %esi, %eax, %ebp, 36(%edi), MAGIC1, FUNC1)

    F(%eax, %ebx, %ecx, %edx, %esi, %ebp, 40(%edi), MAGIC1, FUNC1)
    F(%esi, %eax, %ebx, %ecx, %edx, %ebp, 44(%edi), MAGIC1, FUNC1)
    F(%edx, %esi, %eax, %ebx, %ecx, %ebp, 48(%edi), MAGIC1, FUNC1)
    F(%ecx, %edx, %esi, %eax, %ebx, %ebp, 52(%edi), MAGIC1, FUNC1)
    F(%ebx, %ecx, %edx, %esi, %eax, %ebp, 56(%edi), MAGIC1, FUNC1)

    F(%eax, %ebx, %ecx, %edx, %esi, %ebp, 60(%edi), MAGIC1, FUNC1)
    F(%esi, %eax, %ebx, %ecx, %edx, %ebp, 64(%edi), MAGIC1, FUNC1)
    F(%edx, %esi, %eax, %ebx, %ecx, %ebp, 68(%edi), MAGIC1, FUNC1)
    F(%ecx, %edx, %esi, %eax, %ebx, %ebp, 72(%edi), MAGIC1, FUNC1)
    F(%ebx, %ecx, %edx, %esi, %eax, %ebp, 76(%edi), MAGIC1, FUNC1)
 
   movl 20(%esp), %ebp
   movl %eax, 0(%ebp)
   movl %ebx, 4(%ebp)
   movl %ecx, 8(%ebp)
   movl %edx, 12(%ebp)
   movl %esi, 16(%ebp)
   
        popl    %ebx
        popl    %esi
        popl    %edi
        popl    %ebp
        ret
