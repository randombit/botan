/*************************************************
* SHA-160 Header File                            *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_SHA_160_SSE2_H__
#define BOTAN_SHA_160_SSE2_H__

#include <botan/mdx_hash.h>

namespace Botan {

/*************************************************
* SHA-160                                        *
*************************************************/
class SHA_160_SSE2 : public MDx_HashFunction
   {
   public:
      void clear() throw();
      std::string name() const { return "SHA-160"; }
      HashFunction* clone() const { return new SHA_160_SSE2; }

      SHA_160_SSE2() : MDx_HashFunction(20, 64, true, true) { clear(); }
   private:
      void hash(const byte[]);
      void copy_out(byte[]);

      SecureBuffer<u32bit, 5> digest;
   };

}

#endif
