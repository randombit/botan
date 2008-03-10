/*************************************************
* RC5 Header File                                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_RC5_H__
#define BOTAN_RC5_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* RC5                                            *
*************************************************/
class RC5 : public BlockCipher
   {
   public:
      void clear() throw() { S.clear(); }
      std::string name() const;
      BlockCipher* clone() const { return new RC5(ROUNDS); }
      RC5(u32bit);
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);
      SecureVector<u32bit> S;
      const u32bit ROUNDS;
   };

}

#endif
