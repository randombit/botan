/*************************************************
* RIPEMD-128 Header File                         *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_RIPEMD_128_H__
#define BOTAN_RIPEMD_128_H__

#include <botan/mdx_hash.h>

namespace Botan {

/*************************************************
* RIPEMD-128                                     *
*************************************************/
class BOTAN_DLL RIPEMD_128 : public MDx_HashFunction
   {
   public:
      void clear() throw();
      std::string name() const { return "RIPEMD-128"; }
      HashFunction* clone() const { return new RIPEMD_128; }
      RIPEMD_128() : MDx_HashFunction(16, 64, false, true) { clear(); }
  private:
      void hash(const byte[]);
      void copy_out(byte[]);

      SecureBuffer<u32bit, 16> M;
      SecureBuffer<u32bit, 4> digest;
   };

}

#endif
