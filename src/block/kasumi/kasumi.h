/*
* KASUMI
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_KASUMI_H__
#define BOTAN_KASUMI_H__

#include <botan/block_cipher.h>

namespace Botan {

/*
* KASUMI
*/
class BOTAN_DLL KASUMI : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear() { EK.clear(); }
      std::string name() const { return "KASUMI"; }
      BlockCipher* clone() const { return new KASUMI; }

      KASUMI() : BlockCipher(8, 16) {}
   private:
      void key_schedule(const byte[], u32bit);

      SecureVector<u16bit, 64> EK;
   };

}

#endif
