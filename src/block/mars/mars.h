/*
* MARS
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MARS_H__
#define BOTAN_MARS_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* MARS, IBM's candidate for AES
*/
class BOTAN_DLL MARS : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear() { zeroise(EK); }
      std::string name() const { return "MARS"; }
      BlockCipher* clone() const { return new MARS; }

      MARS() : BlockCipher(16, 16, 32, 4), EK(40) {}
   private:
      void key_schedule(const byte[], u32bit);

      SecureVector<u32bit> EK;
   };

}

#endif
