/*************************************************
* MD4 (IA-32) Header File                        *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_MD4_IA32_H__
#define BOTAN_MD4_IA32_H__

#include <botan/mdx_hash.h>

namespace Botan {

/*************************************************
* MD4                                            *
*************************************************/
class BOTAN_DLL MD4_IA32 : public MDx_HashFunction
   {
   public:
      void clear() throw();
      std::string name() const { return "MD4"; }
      HashFunction* clone() const { return new MD4_IA32; }
      MD4_IA32() : MDx_HashFunction(16, 64, false, true) { clear(); }
   private:
      void hash(const byte[]);
      void copy_out(byte[]);

      SecureBuffer<u32bit, 48> M;
      SecureBuffer<u32bit, 4> digest;
   };

}

#endif
