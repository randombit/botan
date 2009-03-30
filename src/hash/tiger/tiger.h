/*
* Tiger
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TIGER_H__
#define BOTAN_TIGER_H__

#include <botan/mdx_hash.h>

namespace Botan {

/*
* Tiger
*/
class BOTAN_DLL Tiger : public MDx_HashFunction
   {
   public:
      void clear() throw();
      std::string name() const;
      HashFunction* clone() const { return new Tiger(OUTPUT_LENGTH); }
      Tiger(u32bit = 24, u32bit = 3);
   private:
      void compress_n(const byte[], u32bit block);
      void copy_out(byte[]);

      static void pass(u64bit&, u64bit&, u64bit&, u64bit[8], byte);
      static void mix(u64bit[8]);

      static const u64bit SBOX1[256];
      static const u64bit SBOX2[256];
      static const u64bit SBOX3[256];
      static const u64bit SBOX4[256];

      SecureBuffer<u64bit, 8> X;
      SecureBuffer<u64bit, 3> digest;
      const u32bit PASS;
   };

}

#endif
