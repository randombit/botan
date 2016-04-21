/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/key_filt.h>
#include <botan/cipher_filter.h>

namespace Botan {

Keyed_Filter* get_cipher(const std::string& algo_spec,
                         Cipher_Dir direction)
   {
   std::unique_ptr<Cipher_Mode> c(get_cipher_mode(algo_spec, direction));
   if(c)
      return new Cipher_Mode_Filter(c.release());
   throw Algorithm_Not_Found(algo_spec);
   }

Keyed_Filter* get_cipher(const std::string& algo_spec,
                         const SymmetricKey& key,
                         const InitializationVector& iv,
                         Cipher_Dir direction)
   {
   Keyed_Filter* cipher = get_cipher(algo_spec, key, direction);
   if(iv.length())
      cipher->set_iv(iv);
   return cipher;
   }

Keyed_Filter* get_cipher(const std::string& algo_spec,
                         const SymmetricKey& key,
                         Cipher_Dir direction)
   {
   Keyed_Filter* cipher = get_cipher(algo_spec, direction);
   cipher->set_key(key);
   return cipher;
   }

}
