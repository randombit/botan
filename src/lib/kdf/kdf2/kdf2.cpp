/*
* KDF2
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/kdf_utils.h>
#include <botan/kdf2.h>

namespace Botan {

BOTAN_REGISTER_KDF_1HASH(KDF2, "KDF2");

/*
* KDF2 Key Derivation Mechanism
*/
secure_vector<byte> KDF2::derive(size_t out_len,
                                const byte secret[], size_t secret_len,
                                const byte P[], size_t P_len) const
   {
   secure_vector<byte> output;
   u32bit counter = 1;

   while(out_len && counter)
      {
      hash->update(secret, secret_len);
      hash->update_be(counter);
      hash->update(P, P_len);

      secure_vector<byte> hash_result = hash->final();

      size_t added = std::min(hash_result.size(), out_len);
      output += std::make_pair(&hash_result[0], added);
      out_len -= added;

      ++counter;
      }

   return output;
   }

}
