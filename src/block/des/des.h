/*
* DES
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DES_H__
#define BOTAN_DES_H__

#include <botan/block_cipher.h>

namespace Botan {

/*
* DES
*/
class BOTAN_DLL DES : public BlockCipher
   {
   public:
      void clear() throw() { round_key.clear(); }
      std::string name() const { return "DES"; }
      BlockCipher* clone() const { return new DES; }
      DES() : BlockCipher(8, 8) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);

      SecureBuffer<u32bit, 32> round_key;
   };

/*
* Triple DES
*/
class BOTAN_DLL TripleDES : public BlockCipher
   {
   public:
      void clear() throw() { round_key.clear(); }
      std::string name() const { return "TripleDES"; }
      BlockCipher* clone() const { return new TripleDES; }
      TripleDES() : BlockCipher(8, 16, 24, 8) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);

      SecureBuffer<u32bit, 96> round_key;
   };

/*
* DES Tables
*/
extern const u32bit DES_SPBOX1[256];
extern const u32bit DES_SPBOX2[256];
extern const u32bit DES_SPBOX3[256];
extern const u32bit DES_SPBOX4[256];
extern const u32bit DES_SPBOX5[256];
extern const u32bit DES_SPBOX6[256];
extern const u32bit DES_SPBOX7[256];
extern const u32bit DES_SPBOX8[256];

extern const u64bit DES_IPTAB1[256];
extern const u64bit DES_IPTAB2[256];
extern const u64bit DES_FPTAB1[256];
extern const u64bit DES_FPTAB2[256];

}

#endif
