/*
* RIPEMD-160
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_RIPEMD_160_H__
#define BOTAN_RIPEMD_160_H__

#include <botan/mdx_hash.h>

namespace Botan {

/*
* RIPEMD-160
*/
class BOTAN_DLL RIPEMD_160 : public MDx_HashFunction
   {
   public:
      void clear() throw();
      std::string name() const { return "RIPEMD-160"; }
      HashFunction* clone() const { return new RIPEMD_160; }
      RIPEMD_160() : MDx_HashFunction(20, 64, false, true) { clear(); }
   private:
      void compress_n(const byte[], u32bit blocks);
      void copy_out(byte[]);

      SecureBuffer<u32bit, 16> M;
      SecureBuffer<u32bit, 5> digest;
   };

}

#endif
