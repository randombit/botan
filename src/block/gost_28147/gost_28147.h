/*
* GOST 28147-89
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_GOST_28147_89_H__
#define BOTAN_GOST_28147_89_H__

#include <botan/block_cipher.h>

namespace Botan {

class GOST_28147_89_Params;

/**
* The GOST 28147-89 block cipher uses a set of 4 bit Sboxes, however
* the standard does not actually define these Sboxes; they are
* considered a local configuration issue. Several different sets are
* used.
*/
class GOST_28147_89_Params
   {
   public:
      byte sbox_entry(u32bit row, u32bit col) const;

      std::string param_name() const { return name; }

      /**
      * Default GOST parameters are the ones given in GOST R 34.11 for
      * testing purposes; these sboxes are also used by Crypto++, and,
      * at least according to Wikipedia, the Central Bank of Russian Federation
      */
      GOST_28147_89_Params(const std::string& name = "R3411_94_TestParam");
   private:
      const byte* sboxes;
      std::string name;
   };

/**
* GOST 28147-89
*/
class BOTAN_DLL GOST_28147_89 : public BlockCipher
   {
   public:
      void clear() throw() { EK.clear(); }

      std::string name() const;
      BlockCipher* clone() const { return new GOST_28147_89(SBOX); }

      GOST_28147_89(const GOST_28147_89_Params& params);
   private:
      GOST_28147_89(const SecureBuffer<u32bit, 1024>& other_SBOX) :
         BlockCipher(8, 32), SBOX(other_SBOX) {}

      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key_schedule(const byte[], u32bit);

      SecureBuffer<u32bit, 1024> SBOX;
      SecureBuffer<u32bit, 8> EK;
   };

}

#endif
