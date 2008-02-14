/*************************************************
* FORK-256 Header File                           *
* (C) 1999-2008 The Botan Project                *
*************************************************/

#ifndef BOTAN_FORK_256_H__
#define BOTAN_FORK_256_H__

#include <botan/mdx_hash.h>

namespace Botan {

/*************************************************
* FORK-256                                       *
*************************************************/
class FORK_256 : public MDx_HashFunction
   {
   public:
      void clear() throw();
      std::string name() const { return "FORK-256"; }
      HashFunction* clone() const { return new FORK_256; }
      FORK_256() : MDx_HashFunction(32, 64, true, true) { clear(); }
   private:
      void hash(const byte[]);
      void copy_out(byte[]);

      SecureBuffer<u32bit, 8> digest;
      SecureBuffer<u32bit, 16> M;
   };

}

#endif
