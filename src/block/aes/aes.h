/*
* AES
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_AES_H__
#define BOTAN_AES_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* AES-128
*/
class BOTAN_DLL AES_128 : public Block_Cipher_Fixed_Params<16, 16>
   {
   public:
      AES_128() : EK(40), DK(40), ME(16), MD(16) {}

      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear();

      std::string name() const { return "AES-128"; }
      BlockCipher* clone() const { return new AES_128; }
   private:
      void key_schedule(const byte key[], size_t length);

      SecureVector<u32bit> EK, DK;
      SecureVector<byte> ME, MD;
   };

/**
* AES-192
*/
class BOTAN_DLL AES_192 : public Block_Cipher_Fixed_Params<16, 24>
   {
   public:
      AES_192() : EK(48), DK(48), ME(16), MD(16) {}

      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear();

      std::string name() const { return "AES-192"; }
      BlockCipher* clone() const { return new AES_192; }
   private:
      void key_schedule(const byte key[], size_t length);

      SecureVector<u32bit> EK, DK;
      SecureVector<byte> ME, MD;
   };

/**
* AES-256
*/
class BOTAN_DLL AES_256 : public Block_Cipher_Fixed_Params<16, 32>
   {
   public:
      AES_256() : EK(56), DK(56), ME(16), MD(16) {}

      void encrypt_n(const byte in[], byte out[], size_t blocks) const;
      void decrypt_n(const byte in[], byte out[], size_t blocks) const;

      void clear();

      std::string name() const { return "AES-256"; }
      BlockCipher* clone() const { return new AES_256; }
   private:
      void key_schedule(const byte key[], size_t length);

      SecureVector<u32bit> EK, DK;
      SecureVector<byte> ME, MD;
   };

}

#endif
