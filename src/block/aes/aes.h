/*
* AES
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_AES_H__
#define BOTAN_AES_H__

#include <botan/block_cipher.h>

namespace Botan {

/**
* Rijndael aka AES
*/
class BOTAN_DLL AES : public BlockCipher
   {
   public:
      void encrypt_n(const byte in[], byte out[], u32bit blocks) const;
      void decrypt_n(const byte in[], byte out[], u32bit blocks) const;

      void clear();
      std::string name() const { return "AES"; }
      BlockCipher* clone() const { return new AES; }

      AES() : BlockCipher(16, 16, 32, 8) { ROUNDS = 14; }

      /**
      * AES fixed to a particular key_size (16, 24, or 32 bytes)
      * @param key_size the chosen fixed key size
      */
      AES(u32bit key_size);
   private:
      void key_schedule(const byte[], u32bit);
      static u32bit S(u32bit);

      u32bit ROUNDS;

      SecureVector<u32bit, 56> EK;
      SecureVector<byte, 16> ME;

      SecureVector<u32bit, 56> DK;
      SecureVector<byte, 16> MD;
   };

/**
* AES-128
*/
class BOTAN_DLL AES_128 : public AES
   {
   public:
      std::string name() const { return "AES-128"; }
      BlockCipher* clone() const { return new AES_128; }
      AES_128() : AES(16) {}
   };

/**
* AES-192
*/
class BOTAN_DLL AES_192 : public AES
   {
   public:
      std::string name() const { return "AES-192"; }
      BlockCipher* clone() const { return new AES_192; }
      AES_192() : AES(24) {}
   };

/**
* AES-256
*/
class BOTAN_DLL AES_256 : public AES
   {
   public:
      std::string name() const { return "AES-256"; }
      BlockCipher* clone() const { return new AES_256; }
      AES_256() : AES(32) {}
   };

}

#endif
