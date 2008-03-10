/*************************************************
* DES Header File                                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_DES_H__
#define BOTAN_DES_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* DES                                            *
*************************************************/
class DES : public BlockCipher
   {
   public:
      void clear() throw() { round_key.clear(); }
      std::string name() const { return "DES"; }
      BlockCipher* clone() const { return new DES; }
      DES() : BlockCipher(8, 8) {}
   private:
      friend class TripleDES;

      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);
      void raw_encrypt(u32bit&, u32bit&) const;
      void raw_decrypt(u32bit&, u32bit&) const;
      void round(u32bit&, u32bit, u32bit) const;
      static void IP(u32bit&, u32bit&);
      static void FP(u32bit&, u32bit&);

      static const u32bit SPBOX1[256], SPBOX2[256], SPBOX3[256], SPBOX4[256],
                          SPBOX5[256], SPBOX6[256], SPBOX7[256], SPBOX8[256];
      static const u64bit IPTAB1[256], IPTAB2[256], FPTAB1[256], FPTAB2[256];

      SecureBuffer<u32bit, 32> round_key;
   };

/*************************************************
* Triple DES                                     *
*************************************************/
class TripleDES : public BlockCipher
   {
   public:
      void clear() throw() { des1.clear(); des2.clear(); des3.clear(); }
      std::string name() const { return "TripleDES"; }
      BlockCipher* clone() const { return new TripleDES; }
      TripleDES() : BlockCipher(8, 16, 24, 8) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);
      DES des1, des2, des3;
   };

/*************************************************
* DESX                                           *
*************************************************/
class DESX : public BlockCipher
   {
   public:
      void clear() throw() { des.clear(); K1.clear(); K2.clear(); }
      std::string name() const { return "DESX"; }
      BlockCipher* clone() const { return new DESX; }
      DESX() : BlockCipher(8, 24) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);
      SecureBuffer<byte, 8> K1, K2;
      DES des;
   };

}

#endif
