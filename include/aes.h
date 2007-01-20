/*************************************************
* AES Header File                                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_AES_H__
#define BOTAN_AES_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* AES                                            *
*************************************************/
class AES : public BlockCipher
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
      void key(const byte[], u32bit);
      static u32bit S(u32bit);
      static const byte SE[256], SD[256];
      static const u32bit TE[1024], TD[1024];
      SecureBuffer<u32bit, 52> EK, DK;
      SecureBuffer<byte, 32> ME, MD;
      u32bit ROUNDS;
   };

/*************************************************
* AES-128                                        *
*************************************************/
class AES_128 : public AES
   {
   public:
      std::string name() const { return "AES-128"; }
      BlockCipher* clone() const { return new AES_128; }
      AES_128() : AES(16) {}
   };

/*************************************************
* AES-192                                        *
*************************************************/
class AES_192 : public AES
   {
   public:
      std::string name() const { return "AES-192"; }
      BlockCipher* clone() const { return new AES_192; }
      AES_192() : AES(24) {}
   };

/*************************************************
* AES-256                                        *
*************************************************/
class AES_256 : public AES
   {
   public:
      std::string name() const { return "AES-256"; }
      BlockCipher* clone() const { return new AES_256; }
      AES_256() : AES(32) {}
   };

}

#endif
