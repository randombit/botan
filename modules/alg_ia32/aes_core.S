/*************************************************
* AES Source File                                *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/asm_macr.h>

START_LISTING(aes_core.S)

FUNCTION(aes_encrypt)
   PUSH(EBP)
   PUSH(EDI)
   PUSH(ESI)
   PUSH(EBX)

#define PUSHED 4

   
   
   
   POP(EBX)
   POP(ESI)
   POP(EDI)
   POP(EBP)
   ret
