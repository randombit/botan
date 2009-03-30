/**
* AES
* (C) 1999-2007 Jack Lloyd
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
      void clear() throw();
      std::string name() const { return "AES"; }
      BlockCipher* clone() const { return new AES; }
      AES() : BlockCipher(16, 16, 32, 8) { ROUNDS = 14; }
      AES(u32bit);
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);
      static u32bit S(u32bit);

      static const byte SE[256];
      static const byte SD[256];
      static const u32bit TE[1024];
      static const u32bit TD[1024];

      u32bit ROUNDS;

      SecureBuffer<u32bit, 56> EK;
      SecureBuffer<byte, 16> ME;

      SecureBuffer<u32bit, 56> DK;
      SecureBuffer<byte, 16> MD;
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
