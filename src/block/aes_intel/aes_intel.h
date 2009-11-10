/**
* AES using Intel's AES-NI instructions
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_AES_INTEL_H__
#define BOTAN_AES_INTEL_H__

#include <botan/block_cipher.h>

namespace Botan {

class BOTAN_DLL AES_128_Intel : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear();
      std::string name() const { return "AES-128"; }
      BlockCipher* clone() const { return new AES_128_Intel; }

      AES_128_Intel() : BlockCipher(16, 16) { }
   private:
      void key_schedule(const byte[], u32bit);

      SecureBuffer<u32bit, 44> EK, DK;
   };

}

#endif
