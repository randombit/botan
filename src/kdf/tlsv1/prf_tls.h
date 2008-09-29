/*************************************************
* TLS v1.0 PRF Header File                       *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_TLS_PRF__
#define BOTAN_TLS_PRF__

#include <botan/kdf.h>

namespace Botan {

/*************************************************
* TLS PRF                                        *
*************************************************/
class BOTAN_DLL TLS_PRF : public KDF
   {
   public:
      SecureVector<byte> derive(u32bit, const byte[], u32bit,
                                const byte[], u32bit) const;
   private:
      SecureVector<byte> P_hash(const std::string&, u32bit,
                                const byte[], u32bit,
                                const byte[], u32bit) const;
   };

}

#endif
