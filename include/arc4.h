/*************************************************
* ARC4 Header File                               *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_ARC4_H__
#define BOTAN_ARC4_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* ARC4                                           *
*************************************************/
class ARC4 : public StreamCipher
   {
   public:
      void clear() throw();
      std::string name() const;
      StreamCipher* clone() const { return new ARC4(SKIP); }
      ARC4(u32bit = 0);
      ~ARC4() { clear(); }
   private:
      void cipher(const byte[], byte[], u32bit);
      void key(const byte[], u32bit);
      void generate();
      const u32bit SKIP;
      SecureBuffer<byte, 1024> buffer;
      SecureBuffer<u32bit, 256> state;
      u32bit X, Y, position;
   };

}

#endif
