/*************************************************
* KDF1/KDF2 Source File                          *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/kdf.h>
#include <botan/lookup.h>
#include <botan/loadstor.h>
#include <algorithm>
#include <memory>

namespace Botan {

/*************************************************
* Derive a key                                   *
*************************************************/
SecureVector<byte> KDF::derive_key(u32bit key_len,
                                   const MemoryRegion<byte>& secret,
                                   const std::string& salt) const
   {
   return derive_key(key_len, secret, secret.size(),
                     reinterpret_cast<const byte*>(salt.data()),
                     salt.length());
   }

/*************************************************
* Derive a key                                   *
*************************************************/
SecureVector<byte> KDF::derive_key(u32bit key_len,
                                   const MemoryRegion<byte>& secret,
                                   const byte salt[], u32bit salt_len) const
   {
   return derive_key(key_len, secret.begin(), secret.size(),
                     salt, salt_len);
   }

/*************************************************
* Derive a key                                   *
*************************************************/
SecureVector<byte> KDF::derive_key(u32bit key_len,
                                   const MemoryRegion<byte>& secret,
                                   const MemoryRegion<byte>& salt) const
   {
   return derive_key(key_len, secret.begin(), secret.size(),
                     salt.begin(), salt.size());
   }

/*************************************************
* Derive a key                                   *
*************************************************/
SecureVector<byte> KDF::derive_key(u32bit key_len,
                                   const byte secret[], u32bit secret_len,
                                   const std::string& salt) const
   {
   return derive_key(key_len, secret, secret_len,
                     reinterpret_cast<const byte*>(salt.data()),
                     salt.length());
   }

/*************************************************
* Derive a key                                   *
*************************************************/
SecureVector<byte> KDF::derive_key(u32bit key_len,
                                   const byte secret[], u32bit secret_len,
                                   const byte salt[], u32bit salt_len) const
   {
   return derive(key_len, secret, secret_len, salt, salt_len);
   }

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
