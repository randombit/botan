/*************************************************
* TEA Header File                                *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_TEA_H__
#define BOTAN_TEA_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* TEA                                            *
*************************************************/
class TEA : public BlockCipher
   {
   public:
      void clear() throw() { K.clear(); }
      std::string name() const { return "TEA"; }
      BlockCipher* clone() const { return new TEA; }
      TEA() : BlockCipher(8, 16) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);
      SecureBuffer<u32bit, 4> K;
   };

}

#endif
