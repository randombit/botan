/*
* FORK-256
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_FORK_256_H__
#define BOTAN_FORK_256_H__

#include <botan/mdx_hash.h>

namespace Botan {

/*
* FORK-256
*/
class BOTAN_DLL FORK_256 : public MDx_HashFunction
   {
   public:
      void clear() throw();
      std::string name() const { return "FORK-256"; }
      HashFunction* clone() const { return new FORK_256; }
      FORK_256() : MDx_HashFunction(32, 64, true, true) { clear(); }
   private:
      void compress_n(const byte[], u32bit blocks);
      void copy_out(byte[]);

      SecureBuffer<u32bit, 8> digest;
      SecureBuffer<u32bit, 16> M;
   };

}

#endif
