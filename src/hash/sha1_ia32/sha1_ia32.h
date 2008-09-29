/*************************************************
* SHA-160 (IA-32) Header File                    *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_SHA_160_IA32_H__
#define BOTAN_SHA_160_IA32_H__

#include <botan/mdx_hash.h>

namespace Botan {

/*************************************************
* SHA-160                                        *
*************************************************/
class BOTAN_DLL SHA_160_IA32 : public MDx_HashFunction
   {
   public:
      void clear() throw();
      std::string name() const { return "SHA-160"; }
      HashFunction* clone() const { return new SHA_160_IA32; }

      SHA_160_IA32() : MDx_HashFunction(20, 64, true, true) { clear(); }
   private:
      void hash(const byte[]);
      void copy_out(byte[]);

      SecureBuffer<u32bit, 5> digest;

      // Note 81 instead of normal 80: IA-32 asm needs an extra temp
      SecureBuffer<u32bit, 81> W;
   };

}

#endif
