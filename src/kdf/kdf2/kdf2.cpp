/*************************************************
* KDF2 Source File                               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/kdf2.h>
#include <botan/lookup.h>
#include <botan/loadstor.h>
#include <memory>

namespace Botan {

/*************************************************
* KDF2 Key Derivation Mechanism                  *
*************************************************/
SecureVector<byte> KDF2::derive(u32bit out_len,
                                const byte secret[], u32bit secret_len,
                                const byte P[], u32bit P_len) const
   {
   SecureVector<byte> output;
   u32bit counter = 1;

   std::auto_ptr<HashFunction> hash(get_hash(hash_name));
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

/*************************************************
* KDF2 Constructor                               *
*************************************************/
KDF2::KDF2(const std::string& h_name) : hash_name(h_name)
   {
   if(!have_hash(hash_name))
      throw Algorithm_Not_Found(hash_name);
   }

}
