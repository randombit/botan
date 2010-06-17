/*
* MISTY1
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MISTY1_H__
#define BOTAN_MISTY1_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* MISTY1
*/
class BOTAN_DLL MISTY1 : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear() { EK.clear(); DK.clear(); }
      std::string name() const { return "MISTY1"; }
      BlockCipher* clone() const { return new MISTY1; }

      /**
      * @param rounds the number of rounds. Must be 8 with the current
      * implementation
      */
      MISTY1(u32bit rounds = 8);
   private:
      void key_schedule(const byte[], u32bit);

      SecureVector<u16bit, 100> EK, DK;
   };

}

#endif
