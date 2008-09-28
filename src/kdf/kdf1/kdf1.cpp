/*************************************************
* KDF1 Source File                               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/kdf1.h>
#include <botan/lookup.h>
#include <memory>

namespace Botan {

/*************************************************
* KDF1 Key Derivation Mechanism                  *
*************************************************/
SecureVector<byte> KDF1::derive(u32bit,
                                const byte secret[], u32bit secret_len,
                                const byte P[], u32bit P_len) const
   {
   std::auto_ptr<HashFunction> hash(get_hash(hash_name));

   hash->update(secret, secret_len);
   hash->update(P, P_len);
   return hash->final();
   }

/*************************************************
* KDF1 Constructor                               *
*************************************************/
KDF1::KDF1(const std::string& h_name) : hash_name(h_name)
   {
   if(!have_hash(hash_name))
      throw Algorithm_Not_Found(hash_name);
   }

}
