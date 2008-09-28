/*************************************************
* KDF1 Header File                                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_KDF1_H__
#define BOTAN_KDF1_H__

#include <botan/pk_util.h>

namespace Botan {

/*************************************************
* KDF1                                           *
*************************************************/
class BOTAN_DLL KDF1 : public KDF
   {
   public:
      SecureVector<byte> derive(u32bit, const byte[], u32bit,
                                const byte[], u32bit) const;

      KDF1(const std::string&);
   private:
      const std::string hash_name;
   };

}

#endif
