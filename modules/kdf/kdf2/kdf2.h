/*************************************************
* KDF2 Header File                               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_KDF2_H__
#define BOTAN_KDF2_H__

#include <botan/pk_util.h>

namespace Botan {

/*************************************************
* KDF2                                           *
*************************************************/
class BOTAN_DLL KDF2 : public KDF
   {
   public:
      SecureVector<byte> derive(u32bit, const byte[], u32bit,
                                const byte[], u32bit) const;

      KDF2(const std::string&);
   private:
      const std::string hash_name;
   };

}

#endif
