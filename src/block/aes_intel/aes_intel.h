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

/**
* AES-128 using AES-NI
*/
class BOTAN_DLL AES_128_Intel : public BlockCipher
   {
   public:
      u32bit parallelism() const { return 8; }

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

/**
* AES-192 using AES-NI
*/
class BOTAN_DLL AES_192_Intel : public BlockCipher
   {
   public:
      u32bit parallelism() const { return 8; }

      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear();
      std::string name() const { return "AES-192"; }
      BlockCipher* clone() const { return new AES_192_Intel; }

      AES_192_Intel() : BlockCipher(16, 24) { }
   private:
      void key_schedule(const byte[], u32bit);

      SecureBuffer<u32bit, 52> EK, DK;
   };

/**
* AES-256 using AES-NI
*/
class BOTAN_DLL AES_256_Intel : public BlockCipher
   {
   public:
      u32bit parallelism() const { return 8; }

      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear();
      std::string name() const { return "AES-256"; }
      BlockCipher* clone() const { return new AES_256_Intel; }

      AES_256_Intel() : BlockCipher(16, 32) { }
   private:
      void key_schedule(const byte[], u32bit);

      SecureBuffer<u32bit, 60> EK, DK;
   };

}

#endif
