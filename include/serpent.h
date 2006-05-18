/*************************************************
* Serpent Header File                            *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_SERPENT_H__
#define BOTAN_SERPENT_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* Serpent                                        *
*************************************************/
class Serpent : public BlockCipher
   {
   public:
      void clear() throw() { round_key.clear(); }
      std::string name() const { return "Serpent"; }
      BlockCipher* clone() const { return new Serpent; }
      Serpent() : BlockCipher(16, 16, 32, 8) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);

      void key_xor(u32bit, u32bit&, u32bit&, u32bit&, u32bit&) const;
      SecureBuffer<u32bit, 132> round_key;
   };

}

#endif
