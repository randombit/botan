/*************************************************
* SHA-256 Header File                            *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_SHA_256_H__
#define BOTAN_SHA_256_H__

#include <botan/mdx_hash.h>

namespace Botan {

/*************************************************
* SHA-256                                        *
*************************************************/
class SHA_256 : public MDx_HashFunction
   {
   public:
      void clear() throw();
      std::string name() const { return "SHA-256"; }
      HashFunction* clone() const { return new SHA_256; }
      SHA_256() : MDx_HashFunction(32, 64, true, true) { clear(); }
   private:
      void hash(const byte[]);
      void copy_out(byte[]);

      SecureBuffer<u32bit, 64> W;
      SecureBuffer<u32bit, 8> digest;
   };

}

#endif
