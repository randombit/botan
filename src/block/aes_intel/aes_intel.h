/**
* AES using Intel's AES instructions
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_AES_INTEL_H__
#define BOTAN_AES_INTEL_H__

#include <botan/block_cipher.h>

namespace Botan {

class BOTAN_DLL AES_Intel : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear();
      std::string name() const { return "AES"; }
      BlockCipher* clone() const { return new AES_Intel; }

      AES_Intel() : BlockCipher(16, 16, 32, 8) { ROUNDS = 14; }
      AES_Intel(u32bit);
   private:
      void key_schedule(const byte[], u32bit);

      u32bit ROUNDS;

      SecureBuffer<u32bit, 56> EK;
      SecureBuffer<byte, 16> ME;

      SecureBuffer<u32bit, 56> DK;
      SecureBuffer<byte, 16> MD;
   };

/**
* AES-128
*/
class BOTAN_DLL AES_Intel_128 : public AES_Intel
   {
   public:
      std::string name() const { return "AES-128"; }
      BlockCipher* clone() const { return new AES_Intel_128; }
      AES_Intel_128() : AES_Intel(16) {}
   };

/**
* AES-192
*/
class BOTAN_DLL AES_Intel_192 : public AES_Intel
   {
   public:
      std::string name() const { return "AES-192"; }
      BlockCipher* clone() const { return new AES_Intel_192; }
      AES_Intel_192() : AES_Intel(24) {}
   };

/**
* AES-256
*/
class BOTAN_DLL AES_Intel_256 : public AES_Intel
   {
   public:
      std::string name() const { return "AES-256"; }
      BlockCipher* clone() const { return new AES_Intel_256; }
      AES_Intel_256() : AES_Intel(32) {}
   };

}

#endif
