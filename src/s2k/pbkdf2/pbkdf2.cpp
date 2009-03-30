/*
* PBKDF2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pbkdf2.h>
#include <botan/loadstor.h>
#include <botan/xor_buf.h>

namespace Botan {

/*
* Return a PKCS#5 PBKDF2 derived key
*/
OctetString PKCS5_PBKDF2::derive(u32bit key_len,
                                 const std::string& passphrase,
                                 const byte salt[], u32bit salt_size,
                                 u32bit iterations) const
   {
   if(iterations == 0)
      throw Invalid_Argument("PKCS#5 PBKDF2: Invalid iteration count");

   if(passphrase.length() == 0)
      throw Invalid_Argument("PKCS#5 PBKDF2: Empty passphrase is invalid");

   mac->set_key(reinterpret_cast<const byte*>(passphrase.data()),
                passphrase.length());

   SecureVector<byte> key(key_len);

   byte* T = key.begin();

   u32bit counter = 1;
   while(key_len)
      {
      u32bit T_size = std::min(mac->OUTPUT_LENGTH, key_len);
      SecureVector<byte> U(mac->OUTPUT_LENGTH);

      mac->update(salt, salt_size);
      for(u32bit j = 0; j != 4; ++j)
         mac->update(get_byte(j, counter));
      mac->final(U);
      xor_buf(T, U, T_size);

      for(u32bit j = 1; j != iterations; ++j)
         {
         mac->update(U);
         mac->final(U);
         xor_buf(T, U, T_size);
         }

      key_len -= T_size;
      T += T_size;
      ++counter;
      }

   return key;
   }

/*
* Return the name of this type
*/
std::string PKCS5_PBKDF2::name() const
   {
   return "PBKDF2(" + mac->name() + ")";
   }

S2K* PKCS5_PBKDF2::clone() const
   {
   return new PKCS5_PBKDF2(mac->clone());
   }

/*
* PKCS5_PBKDF2 Constructor
*/
PKCS5_PBKDF2::PKCS5_PBKDF2(MessageAuthenticationCode* m) : mac(m) {}

PKCS5_PBKDF2::~PKCS5_PBKDF2() { delete mac; }

}
