/*
* AES using AES-NI instructions
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_AES_NI_H__
#define BOTAN_AES_NI_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* AES-128 using AES-NI
*/
class BOTAN_DLL AES_128_NI : public Block_Cipher_Fixed_Params<16, 16>
   {
   public:
      size_t parallelism() const { return 4; }

      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear();
      std::string name() const { return "AES-128"; }
      BlockCipher* clone() const { return new AES_128_NI; }

      AES_128_NI() : EK(44), DK(44) { }
   private:
      void key_schedule(const byte[], size_t);

      SecureVector<u32bit> EK, DK;
   };

/**
* AES-192 using AES-NI
*/
class BOTAN_DLL AES_192_NI : public Block_Cipher_Fixed_Params<16, 24>
   {
   public:
      size_t parallelism() const { return 4; }

      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear();
      std::string name() const { return "AES-192"; }
      BlockCipher* clone() const { return new AES_192_NI; }

      AES_192_NI() : EK(52), DK(52) { }
   private:
      void key_schedule(const byte[], size_t);

      SecureVector<u32bit> EK, DK;
   };

/**
* AES-256 using AES-NI
*/
class BOTAN_DLL AES_256_NI : public Block_Cipher_Fixed_Params<16, 32>
   {
   public:
      size_t parallelism() const { return 4; }

      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear();
      std::string name() const { return "AES-256"; }
      BlockCipher* clone() const { return new AES_256_NI; }

      AES_256_NI() : EK(60), DK(60) { }
   private:
      void key_schedule(const byte[], size_t);

      SecureVector<u32bit> EK, DK;
   };

}

#endif
