/*************************************************
* Lion Header File                               *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_LION_H__
#define BOTAN_LION_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* Lion                                           *
*************************************************/
class Lion : public BlockCipher
   {
   public:
      void clear() throw();
      std::string name() const;
      BlockCipher* clone() const;
      Lion(const std::string&, const std::string&, u32bit);
      ~Lion() { delete hash; delete cipher; }
   private:
      void enc(const byte[], byte[]) const;
      void dec(const byte[], byte[]) const;
      void key(const byte[], u32bit);
      const u32bit LEFT_SIZE, RIGHT_SIZE;
      HashFunction* hash;
      StreamCipher* cipher;
      SecureVector<byte> key1, key2;
   };

}

#endif
