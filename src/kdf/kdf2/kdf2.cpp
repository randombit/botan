/*
* KDF2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/kdf2.h>
#include <botan/loadstor.h>

namespace Botan {

/*
* KDF2 Key Derivation Mechanism
*/
SecureVector<byte> KDF2::derive(u32bit out_len,
                                const byte secret[], u32bit secret_len,
                                const byte P[], u32bit P_len) const
   {
   SecureVector<byte> output;
   u32bit counter = 1;

   while(out_len && counter)
      {
      hash->update(secret, secret_len);
      for(u32bit j = 0; j != 4; ++j)
         hash->update(get_byte(j, counter));
      hash->update(P, P_len);
      SecureVector<byte> hash_result = hash->final();

      u32bit added = std::min(hash_result.size(), out_len);
      output.append(hash_result, added);
      out_len -= added;

      ++counter;
      }

   return output;
   }

}
