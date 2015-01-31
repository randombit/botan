/*
* KDF1
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/kdf_utils.h>
#include <botan/kdf1.h>

namespace Botan {

BOTAN_REGISTER_KDF_1HASH(KDF1, "KDF1");

/*
* KDF1 Key Derivation Mechanism
*/
secure_vector<byte> KDF1::derive(size_t,
                                const byte secret[], size_t secret_len,
                                const byte P[], size_t P_len) const
   {
   hash->update(secret, secret_len);
   hash->update(P, P_len);
   return hash->final();
   }

}
