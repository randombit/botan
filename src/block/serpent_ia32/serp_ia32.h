/*
* Serpent (IA-32)
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SERPENT_IA32_H__
#define BOTAN_SERPENT_IA32_H__

#include <botan/serpent.h>

namespace Botan {

/**
* Serpent implementation in x86 assembly
*/
class BOTAN_DLL Serpent_IA32 : public Serpent
   {
   public:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      BlockCipher* clone() const { return new Serpent_IA32; }
   private:
      void key_schedule(const byte[], u32bit);
   };

}

#endif
