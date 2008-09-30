/*************************************************
* KDF1 Source File                               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/kdf1.h>

namespace Botan {

/*************************************************
* KDF1 Key Derivation Mechanism                  *
*************************************************/
SecureVector<byte> KDF1::derive(u32bit,
                                const byte secret[], u32bit secret_len,
                                const byte P[], u32bit P_len) const
   {
   hash->update(secret, secret_len);
   hash->update(P, P_len);
   return hash->final();
   }

}
