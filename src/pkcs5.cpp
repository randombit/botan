/*************************************************
* PKCS #5 Source File                            *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/pkcs5.h>
#include <botan/lookup.h>
#include <botan/bit_ops.h>
#include <botan/hmac.h>
#include <algorithm>
#include <memory>

namespace Botan {

/*************************************************
* Return a PKCS#5 PBKDF1 derived key             *
*************************************************/
OctetString PKCS5_PBKDF1::derive(u32bit key_len,
                                 const std::string& passphrase,
                                 const byte salt[], u32bit salt_size,
                                 u32bit iterations) const
   {
   if(iterations == 0)
      throw Invalid_Argument("PKCS#5 PBKDF1: Invalid iteration count");

   std::auto_ptr<HashFunction> hash(get_hash(hash_name));
   if(key_len > hash->OUTPUT_LENGTH)
      throw Exception("PKCS#5 PBKDF1: Requested output length too long");

   hash->update(passphrase);
   hash->update(salt, salt_size);
   SecureVector<byte> key = hash->final();

   for(u32bit j = 1; j != iterations; ++j)
      {
      hash->update(key);
      hash->final(key);
      }

   return OctetString(key, std::min(key_len, key.size()));
   }

/*************************************************
* Return the name of this type                   *
*************************************************/
std::string PKCS5_PBKDF1::name() const
   {
   return "PBKDF1(" + hash_name + ")";
   }

/*************************************************
* PKCS5_PBKDF1 Constructor                       *
*************************************************/
PKCS5_PBKDF1::PKCS5_PBKDF1(const std::string& h_name) : hash_name(h_name)
   {
   if(!have_hash(hash_name))
      throw Algorithm_Not_Found(hash_name);
   }

/*************************************************
* Return a PKCS#5 PBKDF2 derived key             *
*************************************************/
OctetString PKCS5_PBKDF2::derive(u32bit key_len,
                                 const std::string& passphrase,
                                 const byte salt[], u32bit salt_size,
                                 u32bit iterations) const
   {
   if(iterations == 0)
      throw Invalid_Argument("PKCS#5 PBKDF2: Invalid iteration count");

   if(passphrase.length() == 0)
      throw Invalid_Argument("PKCS#5 PBKDF2: Empty passphrase is invalid");

   HMAC hmac(hash_name);
   hmac.set_key((const byte*)passphrase.c_str(), passphrase.length());
   SecureVector<byte> key(key_len);

   byte* T = key.begin();

   u32bit counter = 1;
   while(key_len)
      {
      u32bit T_size = std::min(hmac.OUTPUT_LENGTH, key_len);
      SecureVector<byte> U(hmac.OUTPUT_LENGTH);

      hmac.update(salt, salt_size);
      for(u32bit j = 0; j != 4; ++j)
         hmac.update(get_byte(j, counter));
      hmac.final(U);
      xor_buf(T, U, T_size);

      for(u32bit j = 1; j != iterations; ++j)
         {
         hmac.update(U);
         hmac.final(U);
         xor_buf(T, U, T_size);
         }

      key_len -= T_size;
      T += T_size;
      ++counter;
      }

   return key;
   }

/*************************************************
* Return the name of this type                   *
*************************************************/
std::string PKCS5_PBKDF2::name() const
   {
   return "PBKDF2(" + hash_name + ")";
   }

/*************************************************
* PKCS5_PBKDF2 Constructor                       *
*************************************************/
PKCS5_PBKDF2::PKCS5_PBKDF2(const std::string& h_name) : hash_name(h_name)
   {
   if(!have_hash(hash_name))
      throw Algorithm_Not_Found(hash_name);
   }

}
