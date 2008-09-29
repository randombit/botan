/*************************************************
* Serpent (IA-32) Header File                    *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_SERPENT_IA32_H__
#define BOTAN_SERPENT_IA32_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* Serpent                                        *
*************************************************/
class BOTAN_DLL Serpent_IA32 : public BlockCipher
   {
   public:
      void clear() throw() { round_key.clear(); }
      std::string name() const { return "Serpent"; }
      BlockCipher* clone() const { return new Serpent_IA32; }
      Serpent_IA32() : BlockCipher(16, 16, 32, 8) {}
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);

      SecureBuffer<u32bit, 132> round_key;
   };

}

#endif
