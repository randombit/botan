/*
* SHA-160
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SHA_160_H__
#define BOTAN_SHA_160_H__

#include <botan/mdx_hash.h>

namespace Botan {

/*
* SHA-160
*/
class BOTAN_DLL SHA_160 : public MDx_HashFunction
   {
   public:
      void clear() throw();
      std::string name() const { return "SHA-160"; }
      HashFunction* clone() const { return new SHA_160; }
      SHA_160();

   protected:
      SHA_160(u32bit W_size);

      void compress_n(const byte[], u32bit blocks);
      void copy_out(byte[]);

      SecureBuffer<u32bit, 5> digest;
      SecureVector<u32bit> W;
   };

}

#endif
