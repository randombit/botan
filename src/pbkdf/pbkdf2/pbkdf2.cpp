/*
* PBKDF2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pbkdf2.h>
#include <botan/get_byte.h>
#include <botan/internal/xor_buf.h>

namespace Botan {

/*
* Return a PKCS #5 PBKDF2 derived key
*/
OctetString PKCS5_PBKDF2::derive_key(size_t key_len,
                                     const std::string& passphrase,
                                     const byte salt[], size_t salt_size,
                                     size_t iterations) const
   {
   if(iterations == 0)
      throw Invalid_Argument("PKCS#5 PBKDF2: Invalid iteration count");

   try
      {
      mac->set_key(reinterpret_cast<const byte*>(passphrase.data()),
                   passphrase.length());
      }
   catch(Invalid_Key_Length)
      {
      throw Exception(name() + " cannot accept passphrases of length " +
                      to_string(passphrase.length()));
      }

   SecureVector<byte> key(key_len);

   byte* T = &key[0];

   SecureVector<byte> U(mac->output_length());

   u32bit counter = 1;
   while(key_len)
      {
      size_t T_size = std::min<size_t>(mac->output_length(), key_len);

      mac->update(salt, salt_size);
      mac->update_be(counter);
      mac->final(&U[0]);

      xor_buf(T, U, T_size);

      for(size_t j = 1; j != iterations; ++j)
         {
         mac->update(U);
         mac->final(&U[0]);
         xor_buf(T, U, T_size);
         }

      key_len -= T_size;
      T += T_size;
      ++counter;
      }

   return key;
   }

}
