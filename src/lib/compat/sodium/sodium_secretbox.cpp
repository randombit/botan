/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sodium.h>
#include <botan/secmem.h>
#include <botan/stream_cipher.h>
#include <botan/mac.h>

namespace Botan {

int Sodium::crypto_secretbox_xsalsa20poly1305(uint8_t ctext[],
                                              const uint8_t ptext[],
                                              size_t ptext_len,
                                              const uint8_t nonce[],
                                              const uint8_t key[])
   {
   if(ptext_len < 32)
      return -1;

   auto salsa = StreamCipher::create_or_throw("Salsa20");
   salsa->set_key(key, crypto_secretbox_KEYBYTES);
   salsa->set_iv(nonce, crypto_secretbox_NONCEBYTES);

   secure_vector<uint8_t> auth_key(32);
   salsa->write_keystream(auth_key.data(), auth_key.size());

   salsa->cipher(ptext + 32, ctext + 32, ptext_len - 32);

   auto poly1305 = MessageAuthenticationCode::create_or_throw("Poly1305");
   poly1305->set_key(auth_key);
   poly1305->update(ctext + 32, ptext_len - 32);
   poly1305->final(ctext + 16);

   clear_mem(ctext, 16);
   return 0;
   }

int Sodium::crypto_secretbox_xsalsa20poly1305_open(uint8_t ptext[],
                                                   const uint8_t ctext[],
                                                   size_t ctext_len,
                                                   const uint8_t nonce[],
                                                   const uint8_t key[])
   {
   if(ctext_len < crypto_box_curve25519xsalsa20poly1305_ZEROBYTES)
      {
      return -1;
      }

   auto salsa = StreamCipher::create_or_throw("Salsa20");
   salsa->set_key(key, crypto_secretbox_KEYBYTES);
   salsa->set_iv(nonce, crypto_secretbox_NONCEBYTES);

   secure_vector<uint8_t> auth_key(32);
   salsa->write_keystream(auth_key.data(), auth_key.size());

   auto poly1305 = MessageAuthenticationCode::create_or_throw("Poly1305");
   poly1305->set_key(auth_key);
   poly1305->update(ctext + 32, ctext_len - 32);
   secure_vector<uint8_t> computed = poly1305->final();

   if(!constant_time_compare(computed.data(), ctext + 16, 16))
      return -1;

   salsa->cipher(ctext + 32, ptext + 32, ctext_len - 32);

   clear_mem(ptext, 32);
   return 0;
   }

int Sodium::crypto_secretbox_detached(uint8_t ctext[], uint8_t mac[],
                                      const uint8_t ptext[],
                                      size_t ptext_len,
                                      const uint8_t nonce[],
                                      const uint8_t key[])
   {
   auto salsa = StreamCipher::create_or_throw("Salsa20");
   salsa->set_key(key, crypto_secretbox_KEYBYTES);
   salsa->set_iv(nonce, crypto_secretbox_NONCEBYTES);

   secure_vector<uint8_t> auth_key(32);
   salsa->write_keystream(auth_key.data(), auth_key.size());

   salsa->cipher(ptext, ctext, ptext_len);

   auto poly1305 = MessageAuthenticationCode::create_or_throw("Poly1305");
   poly1305->set_key(auth_key);
   poly1305->update(ctext, ptext_len);
   poly1305->final(mac);

   return 0;
   }

int Sodium::crypto_secretbox_open_detached(uint8_t ptext[],
                                           const uint8_t ctext[],
                                           const uint8_t mac[],
                                           size_t ctext_len,
                                           const uint8_t nonce[],
                                           const uint8_t key[])
   {
   auto salsa = StreamCipher::create_or_throw("Salsa20");
   salsa->set_key(key, crypto_secretbox_KEYBYTES);
   salsa->set_iv(nonce, crypto_secretbox_NONCEBYTES);

   secure_vector<uint8_t> auth_key(32);
   salsa->write_keystream(auth_key.data(), auth_key.size());

   auto poly1305 = MessageAuthenticationCode::create_or_throw("Poly1305");
   poly1305->set_key(auth_key);
   poly1305->update(ctext, ctext_len);
   secure_vector<uint8_t> computed_mac = poly1305->final();

   if(!constant_time_compare(mac, computed_mac.data(), computed_mac.size()))
      return -1;

   salsa->cipher(ctext, ptext, ctext_len);

   return 0;
   }

}
