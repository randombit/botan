/*************************************************
* Luby-Rackoff Header File                       *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_LUBY_RACKOFF_H__
#define BOTAN_LUBY_RACKOFF_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* Luby-Rackoff                                   *
*************************************************/
class BOTAN_DLL LubyRackoff : public BlockCipher
   {
   public:
      void clear() throw();
      std::string name() const;
      BlockCipher* clone() const;

      LubyRackoff(HashFunction* hash);
      ~LubyRackoff() { delete hash; }
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);
      HashFunction* hash;
      SecureVector<byte> K1, K2;
   };

}

#endif
