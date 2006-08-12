   .file "sha1core.S"
   .text
   .p2align 4,,15

.global sha160_core
   .type   sha160_core, @function
sha160_core:
        pushl   %edi
        pushl   %esi
   
        movl    16(%esp), %ecx   # byte input[64]
        movl    20(%esp), %edi   # u32bit W[80]

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
        movl    $16, %ecx
       
       // here esi == 16
.EXPANSION_LOOP:
        movl    -32(%edx), %eax
        xorl    -12(%edx), %eax
        incl    %ecx
        xorl    -56(%edx), %eax
        xorl    -64(%edx), %eax
        rorl    $31, %eax
        movl    %eax, (%edx)
        addl    $4, %edx
        cmpl    $80, %ecx
        jne .EXPANSION_LOOP
   
        popl    %esi
        popl    %edi
        ret
