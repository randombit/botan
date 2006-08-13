/*************************************************
* SHA-160 Source File                            *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/asm_macr.h>

START_LISTING(sha1core.S)

FUNCTION(sha160_core)
   PUSH(EBP)
   PUSH(EDI)
   PUSH(ESI)
   PUSH(EBX)

#define PUSHED 4

   MOV(ARG(2), EBP)
   MOV(ARG(3), EDI)

   ZEROIZE(ESI)

   ALIGN
.LOAD_INPUT_LOOP:
   ADD(IMM(4), ESI)

        movl    0(EBP), EAX
        movl    4(EBP), EBX
        movl    8(EBP), ECX
        bswapl EAX
        movl   12(EBP), EDX
        bswapl EBX
        addl $16, EBP
        bswapl ECX
        bswapl EDX

        movl   EAX, -16(EDI,ESI,4)
        movl   EBX, -12(EDI,ESI,4)
        movl   ECX, -8(EDI,ESI,4)
        movl   EDX, -4(EDI,ESI,4)

        cmpl $16, ESI
        jne .LOAD_INPUT_LOOP

        leal    64(EDI), EBP

        ALIGN
.EXPANSION_LOOP:
        addl $4, ESI

        ZEROIZE(EAX)
        movl  -4(EBP), EBX
        movl  -8(EBP), ECX
        movl -12(EBP), EDX

        xorl -20(EBP), EAX
        xorl -24(EBP), EBX
        xorl -28(EBP), ECX
        xorl -32(EBP), EDX

        xorl -44(EBP), EAX
        xorl -48(EBP), EBX
        xorl -52(EBP), ECX
        xorl -56(EBP), EDX

        xorl -52(EBP), EAX
        xorl -56(EBP), EBX
        xorl -60(EBP), ECX
        xorl -64(EBP), EDX

        roll $1, EDX

        roll $1, ECX
        movl EDX, (EBP)

        roll $1, EBX
        movl ECX, 4(EBP)

        xorl EDX, EAX
        movl EBX, 8(EBP)
        roll $1, EAX
        movl EAX, 12(EBP)

        addl $16, EBP
        cmpl $80, ESI
    jne .EXPANSION_LOOP

   movl 20(%esp), EBP
   movl 0(EBP), EAX
   movl 4(EBP), EBX
   movl 8(EBP), ECX
   movl 12(EBP), EDX
   movl 16(EBP), ESI

#define MAGIC1 0x5A827999
#define MAGIC2 0x6ED9EBA1
#define MAGIC3 0x8F1BBCDC
#define MAGIC4 0xCA62C1D6

#define F1(A, B, C, D, E, TEMP, MSG) \
   addl 4*MSG(EDI), E          ; \
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
   addl 4*MSG(EDI), E          ; \
   movl B, TEMP                 ; \
   roll $5, A                   ; \
   xorl D, TEMP                 ; \
   addl A, E                    ; \
   xorl C, TEMP                 ; \
   rorl $2, B                   ; \
   leal MAGIC(E,TEMP,1), E      ; \
   rorl $5, A                   ;

#define F3(A, B, C, D, E, TEMP, MSG) \
   addl 4*MSG(EDI), E          ; \
   movl B, TEMP                 ; \
   roll $5, A                   ; \
   orl  C, TEMP                 ; \
   movl B, 4*MSG(EDI)          ; \
   andl D, TEMP                 ; \
   andl C, 4*MSG(EDI)          ; \
   orl  4*MSG(EDI), TEMP       ; \
   addl A, E                    ; \
   leal MAGIC3(E,TEMP,1), E     ; \
   rorl $2, B                   ; \
   rorl $5, A                   ;

#define F2(A, B, C, D, E, TEMP, MSG) \
   F2_OR_F4(A, B, C, D, E, TEMP, MSG, MAGIC2)

#define F4(A, B, C, D, E, TEMP, MSG) \
   F2_OR_F4(A, B, C, D, E, TEMP, MSG, MAGIC4)

#define F_BLOCK(F, MSG) \
    F(EAX, EBX, ECX, EDX, ESI, EBP, (MSG+0)) \
    F(ESI, EAX, EBX, ECX, EDX, EBP, (MSG+1)) \
    F(EDX, ESI, EAX, EBX, ECX, EBP, (MSG+2)) \
    F(ECX, EDX, ESI, EAX, EBX, EBP, (MSG+3)) \
    F(EBX, ECX, EDX, ESI, EAX, EBP, (MSG+4))

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

   movl 20(%esp), EBP
   addl EAX, 0(EBP)
   addl EBX, 4(EBP)
   addl ECX, 8(EBP)
   addl EDX, 12(EBP)
   addl ESI, 16(EBP)

        popl    EBX
        popl    ESI
        popl    EDI
        popl    EBP
        ret
