/*
* HAS-160
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_HAS_160_H__
#define BOTAN_HAS_160_H__

#include <botan/mdx_hash.h>

namespace Botan {

/*
* HAS-160
*/
class BOTAN_DLL HAS_160 : public MDx_HashFunction
   {
   public:
      void clear() throw();
      std::string name() const { return "HAS-160"; }
      HashFunction* clone() const { return new HAS_160; }
      HAS_160() : MDx_HashFunction(20, 64, false, true) { clear(); }
   private:
      void compress_n(const byte[], u32bit blocks);
      void copy_out(byte[]);

      SecureBuffer<u32bit, 20> X;
      SecureBuffer<u32bit, 5> digest;
   };

}

#endif
