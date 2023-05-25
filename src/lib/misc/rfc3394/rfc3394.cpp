/*
* AES Key Wrap (RFC 3394)
* (C) 2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rfc3394.h>

#include <botan/block_cipher.h>
#include <botan/nist_keywrap.h>

namespace Botan {

secure_vector<uint8_t> rfc3394_keywrap(const secure_vector<uint8_t>& key, const SymmetricKey& kek) {
   BOTAN_ARG_CHECK(kek.size() == 16 || kek.size() == 24 || kek.size() == 32, "Invalid KEK length for NIST key wrap");

   const std::string cipher_name = "AES-" + std::to_string(8 * kek.size());
   auto aes = BlockCipher::create_or_throw(cipher_name);
   aes->set_key(kek);

   std::vector<uint8_t> wrapped = nist_key_wrap(key.data(), key.size(), *aes);
   return secure_vector<uint8_t>(wrapped.begin(), wrapped.end());
}

secure_vector<uint8_t> rfc3394_keyunwrap(const secure_vector<uint8_t>& key, const SymmetricKey& kek) {
   BOTAN_ARG_CHECK(kek.size() == 16 || kek.size() == 24 || kek.size() == 32, "Invalid KEK length for NIST key wrap");

   BOTAN_ARG_CHECK(key.size() >= 16 && key.size() % 8 == 0, "Bad input key size for NIST key unwrap");

   const std::string cipher_name = "AES-" + std::to_string(8 * kek.size());
   auto aes = BlockCipher::create_or_throw(cipher_name);
   aes->set_key(kek);

   return nist_key_unwrap(key.data(), key.size(), *aes);
}

}  // namespace Botan
