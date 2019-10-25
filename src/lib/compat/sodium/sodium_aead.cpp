/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sodium.h>
#include <botan/aead.h>

namespace Botan {

namespace {

int sodium_aead_chacha20poly1305_encrypt(uint8_t ctext[],
                                         unsigned long long* ctext_len,
                                         const uint8_t ptext[],
                                         size_t ptext_len,
                                         const uint8_t ad[],
                                         size_t ad_len,
                                         const uint8_t nonce[],
                                         size_t nonce_len,
                                         const uint8_t key[])
   {
   auto chacha20poly1305 = AEAD_Mode::create_or_throw("ChaCha20Poly1305", ENCRYPTION);

   chacha20poly1305->set_key(key, 32);
   chacha20poly1305->set_associated_data(ad, ad_len);
   chacha20poly1305->start(nonce, nonce_len);

   // FIXME do this in-place
   secure_vector<uint8_t> buf;
   buf.reserve(ptext_len + 16);
   buf.assign(ptext, ptext + ptext_len);

   chacha20poly1305->finish(buf);

   copy_mem(ctext, buf.data(), buf.size());
   if(ctext_len)
      *ctext_len = buf.size();
   return 0;
   }

int sodium_aead_chacha20poly1305_decrypt(uint8_t ptext[],
                                         unsigned long long* ptext_len,
                                         const uint8_t ctext[],
                                         size_t ctext_len,
                                         const uint8_t ad[],
                                         size_t ad_len,
                                         const uint8_t nonce[],
                                         size_t nonce_len,
                                         const uint8_t key[])
   {
   if(ctext_len < 16)
      return -1;

   *ptext_len = 0;

   auto chacha20poly1305 = AEAD_Mode::create_or_throw("ChaCha20Poly1305", DECRYPTION);

   chacha20poly1305->set_key(key, 32);
   chacha20poly1305->set_associated_data(ad, ad_len);
   chacha20poly1305->start(nonce, nonce_len);

   // FIXME do this in-place
   secure_vector<uint8_t> buf;
   buf.assign(ctext, ctext + ctext_len);

   try
      {
      chacha20poly1305->finish(buf);
      }
   catch(Invalid_Authentication_Tag&)
      {
      return -1;
      }

   *ptext_len = ctext_len - 16;

   copy_mem(ptext, buf.data(), buf.size());
   return 0;
   }

int sodium_aead_chacha20poly1305_encrypt_detached(uint8_t ctext[],
                                                  uint8_t mac[],
                                                  const uint8_t ptext[],
                                                  size_t ptext_len,
                                                  const uint8_t ad[],
                                                  size_t ad_len,
                                                  const uint8_t nonce[],
                                                  size_t nonce_len,
                                                  const uint8_t key[])
   {
   auto chacha20poly1305 = AEAD_Mode::create_or_throw("ChaCha20Poly1305", ENCRYPTION);

   chacha20poly1305->set_key(key, 32);
   chacha20poly1305->set_associated_data(ad, ad_len);
   chacha20poly1305->start(nonce, nonce_len);

   // FIXME do this in-place
   secure_vector<uint8_t> buf;
   buf.reserve(ptext_len + 16);
   buf.assign(ptext, ptext + ptext_len);

   chacha20poly1305->finish(buf);

   copy_mem(ctext, buf.data(), ptext_len);
   copy_mem(mac, buf.data() + ptext_len, 16);
   return 0;
   }

int sodium_aead_chacha20poly1305_decrypt_detached(uint8_t ptext[],
                                                  const uint8_t ctext[],
                                                  size_t ctext_len,
                                                  const uint8_t mac[],
                                                  const uint8_t ad[],
                                                  size_t ad_len,
                                                  const uint8_t nonce[],
                                                  size_t nonce_len,
                                                  const uint8_t key[])
   {
   auto chacha20poly1305 = AEAD_Mode::create_or_throw("ChaCha20Poly1305", DECRYPTION);

   chacha20poly1305->set_key(key, 32);
   chacha20poly1305->set_associated_data(ad, ad_len);
   chacha20poly1305->start(nonce, nonce_len);

   // FIXME do this in-place
   secure_vector<uint8_t> buf;
   buf.reserve(ctext_len + 16);
   buf.assign(ctext, ctext + ctext_len);
   buf.insert(buf.end(), mac, mac + 16);

   try
      {
      chacha20poly1305->finish(buf);
      }
   catch(Invalid_Authentication_Tag&)
      {
      return -1;
      }

   copy_mem(ptext, buf.data(), buf.size());
   return 0;
   }

}

int Sodium::crypto_aead_chacha20poly1305_ietf_encrypt(uint8_t ctext[],
                                                      unsigned long long* ctext_len,
                                                      const uint8_t ptext[],
                                                      size_t ptext_len,
                                                      const uint8_t ad[],
                                                      size_t ad_len,
                                                      const uint8_t unused_secret_nonce[],
                                                      const uint8_t nonce[],
                                                      const uint8_t key[])
   {
   BOTAN_UNUSED(unused_secret_nonce);

   return sodium_aead_chacha20poly1305_encrypt(
      ctext, ctext_len, ptext, ptext_len,
      ad, ad_len, nonce, crypto_aead_chacha20poly1305_ietf_npubbytes(), key);
   }

int Sodium::crypto_aead_chacha20poly1305_ietf_decrypt(uint8_t ptext[],
                                                      unsigned long long* ptext_len,
                                                      uint8_t unused_secret_nonce[],
                                                      const uint8_t ctext[],
                                                      size_t ctext_len,
                                                      const uint8_t ad[],
                                                      size_t ad_len,
                                                      const uint8_t nonce[],
                                                      const uint8_t key[])
   {
   BOTAN_UNUSED(unused_secret_nonce);

   return sodium_aead_chacha20poly1305_decrypt(
      ptext, ptext_len, ctext, ctext_len,
      ad, ad_len, nonce, crypto_aead_chacha20poly1305_ietf_npubbytes(), key);
   }

int Sodium::crypto_aead_chacha20poly1305_ietf_encrypt_detached(uint8_t ctext[],
                                                               uint8_t mac[],
                                                               unsigned long long* mac_len,
                                                               const uint8_t ptext[],
                                                               size_t ptext_len,
                                                               const uint8_t ad[],
                                                               size_t ad_len,
                                                               const uint8_t unused_secret_nonce[],
                                                               const uint8_t nonce[],
                                                               const uint8_t key[])
   {
   BOTAN_UNUSED(unused_secret_nonce);

   if(mac_len)
      *mac_len = 16;

   return sodium_aead_chacha20poly1305_encrypt_detached(
      ctext, mac, ptext, ptext_len,
      ad, ad_len, nonce, crypto_aead_chacha20poly1305_ietf_npubbytes(), key);
   }

int Sodium::crypto_aead_chacha20poly1305_ietf_decrypt_detached(uint8_t ptext[],
                                                               uint8_t unused_secret_nonce[],
                                                               const uint8_t ctext[],
                                                               size_t ctext_len,
                                                               const uint8_t mac[],
                                                               const uint8_t ad[],
                                                               size_t ad_len,
                                                               const uint8_t nonce[],
                                                               const uint8_t key[])
   {
   BOTAN_UNUSED(unused_secret_nonce);

   return sodium_aead_chacha20poly1305_decrypt_detached(
      ptext, ctext, ctext_len, mac,
      ad, ad_len, nonce, crypto_aead_chacha20poly1305_ietf_npubbytes(), key);
   }

int Sodium::crypto_aead_chacha20poly1305_encrypt(uint8_t ctext[],
                                                 unsigned long long* ctext_len,
                                                 const uint8_t ptext[],
                                                 size_t ptext_len,
                                                 const uint8_t ad[],
                                                 size_t ad_len,
                                                 const uint8_t unused_secret_nonce[],
                                                 const uint8_t nonce[],
                                                 const uint8_t key[])
   {
   BOTAN_UNUSED(unused_secret_nonce);
   return sodium_aead_chacha20poly1305_encrypt(
      ctext, ctext_len, ptext, ptext_len,
      ad, ad_len, nonce, crypto_aead_chacha20poly1305_npubbytes(), key);
   }

int Sodium::crypto_aead_chacha20poly1305_decrypt(uint8_t ptext[],
                                                 unsigned long long* ptext_len,
                                                 uint8_t unused_secret_nonce[],
                                                 const uint8_t ctext[],
                                                 size_t ctext_len,
                                                 const uint8_t ad[],
                                                 size_t ad_len,
                                                 const uint8_t nonce[],
                                                 const uint8_t key[])
   {
   BOTAN_UNUSED(unused_secret_nonce);
   return sodium_aead_chacha20poly1305_decrypt(
      ptext, ptext_len, ctext, ctext_len,
      ad, ad_len, nonce, crypto_aead_chacha20poly1305_npubbytes(), key);
   }

int Sodium::crypto_aead_chacha20poly1305_encrypt_detached(uint8_t ctext[],
                                                          uint8_t mac[],
                                                          unsigned long long* mac_len,
                                                          const uint8_t ptext[],
                                                          size_t ptext_len,
                                                          const uint8_t ad[],
                                                          size_t ad_len,
                                                          const uint8_t unused_secret_nonce[],
                                                          const uint8_t nonce[],
                                                          const uint8_t key[])
   {
   BOTAN_UNUSED(unused_secret_nonce);
   if(mac_len)
      *mac_len = 16;

   return sodium_aead_chacha20poly1305_encrypt_detached(
      ctext, mac, ptext, ptext_len,
      ad, ad_len, nonce, crypto_aead_chacha20poly1305_npubbytes(), key);
   }

int Sodium::crypto_aead_chacha20poly1305_decrypt_detached(uint8_t ptext[],
                                                          uint8_t unused_secret_nonce[],
                                                          const uint8_t ctext[],
                                                          size_t ctext_len,
                                                          const uint8_t mac[],
                                                          const uint8_t ad[],
                                                          size_t ad_len,
                                                          const uint8_t nonce[],
                                                          const uint8_t key[])
   {
   BOTAN_UNUSED(unused_secret_nonce);

   return sodium_aead_chacha20poly1305_decrypt_detached(
      ptext, ctext, ctext_len, mac,
      ad, ad_len, nonce, crypto_aead_chacha20poly1305_npubbytes(), key);
   }

int Sodium::crypto_aead_xchacha20poly1305_ietf_encrypt(uint8_t ctext[],
                                                       unsigned long long* ctext_len,
                                                       const uint8_t ptext[],
                                                       size_t ptext_len,
                                                       const uint8_t ad[],
                                                       size_t ad_len,
                                                       const uint8_t unused_secret_nonce[],
                                                       const uint8_t nonce[],
                                                       const uint8_t key[])
   {
   BOTAN_UNUSED(unused_secret_nonce);

   return sodium_aead_chacha20poly1305_encrypt(
      ctext, ctext_len, ptext, ptext_len,
      ad, ad_len, nonce, crypto_aead_xchacha20poly1305_ietf_npubbytes(), key);
   }

int Sodium::crypto_aead_xchacha20poly1305_ietf_decrypt(uint8_t ptext[],
                                                       unsigned long long* ptext_len,
                                                       uint8_t unused_secret_nonce[],
                                                       const uint8_t ctext[],
                                                       size_t ctext_len,
                                                       const uint8_t ad[],
                                                       size_t ad_len,
                                                       const uint8_t nonce[],
                                                       const uint8_t key[])
   {
   BOTAN_UNUSED(unused_secret_nonce);

   return sodium_aead_chacha20poly1305_decrypt(
      ptext, ptext_len, ctext, ctext_len,
      ad, ad_len, nonce, crypto_aead_xchacha20poly1305_ietf_npubbytes(), key);
   }

int Sodium::crypto_aead_xchacha20poly1305_ietf_encrypt_detached(uint8_t ctext[],
                                                                uint8_t mac[],
                                                                unsigned long long* mac_len,
                                                                const uint8_t ptext[],
                                                                size_t ptext_len,
                                                                const uint8_t ad[],
                                                                size_t ad_len,
                                                                const uint8_t unused_secret_nonce[],
                                                                const uint8_t nonce[],
                                                                const uint8_t key[])
   {
   BOTAN_UNUSED(unused_secret_nonce);
   if(mac_len)
      *mac_len = 16;

   return sodium_aead_chacha20poly1305_encrypt_detached(
      ctext, mac, ptext, ptext_len,
      ad, ad_len, nonce, crypto_aead_xchacha20poly1305_ietf_npubbytes(), key);
   }

int Sodium::crypto_aead_xchacha20poly1305_ietf_decrypt_detached(uint8_t ptext[],
                                                                uint8_t unused_secret_nonce[],
                                                                const uint8_t ctext[],
                                                                size_t ctext_len,
                                                                const uint8_t mac[],
                                                                const uint8_t ad[],
                                                                size_t ad_len,
                                                                const uint8_t nonce[],
                                                                const uint8_t key[])
   {
   BOTAN_UNUSED(unused_secret_nonce);
   return sodium_aead_chacha20poly1305_decrypt_detached(
      ptext, ctext, ctext_len, mac,
      ad, ad_len, nonce, crypto_aead_xchacha20poly1305_ietf_npubbytes(), key);
   }

}
