/*************************************************
* Whirlpool Header File                          *
* (C) 1999-2008 The Botan Project                *
*************************************************/

#ifndef BOTAN_WHIRLPOOL_H__
#define BOTAN_WHIRLPOOL_H__

#include <botan/mdx_hash.h>

namespace Botan {

/*************************************************
* Whirlpool                                      *
*************************************************/
class Whirlpool : public MDx_HashFunction
   {
   public:
      void clear() throw();
      std::string name() const { return "Whirlpool"; }
      HashFunction* clone() const { return new Whirlpool; }
      Whirlpool() : MDx_HashFunction(64, 64, true, true, 32) { clear(); }
   private:
      void hash(const byte[]);
      void copy_out(byte[]);

      static const u64bit C0[256], C1[256], C2[256], C3[256],
                          C4[256], C5[256], C6[256], C7[256];
      SecureBuffer<u64bit, 8> M, digest;
   };

}

#endif
