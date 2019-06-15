/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sodium.h>
#include <botan/mac.h>
#include <botan/hash.h>

namespace Botan {

int Sodium::crypto_hash_sha512(uint8_t out[64], const uint8_t in[], size_t in_len)
   {
   auto sha512 = HashFunction::create_or_throw("SHA-512");
   sha512->update(in, in_len);
   sha512->final(out);
   return 0;
   }

int Sodium::crypto_hash_sha256(uint8_t out[], const uint8_t in[], size_t in_len)
   {
   auto sha256 = HashFunction::create_or_throw("SHA-256");
   sha256->update(in, in_len);
   sha256->final(out);
   return 0;
   }

int Sodium::crypto_shorthash_siphash24(uint8_t out[8], const uint8_t in[],
                                       size_t in_len, const uint8_t key[16])
   {
   auto mac = MessageAuthenticationCode::create_or_throw("SipHash(2,4)");
   mac->set_key(key, crypto_shorthash_siphash24_KEYBYTES);
   mac->update(in, in_len);
   mac->final(out);
   return 0;
   }

int Sodium::crypto_onetimeauth_poly1305(uint8_t out[],
                                        const uint8_t in[],
                                        size_t in_len,
                                        const uint8_t key[])
   {
   auto mac = MessageAuthenticationCode::create_or_throw("Poly1305");
   mac->set_key(key, crypto_onetimeauth_poly1305_KEYBYTES);
   mac->update(in, in_len);
   mac->final(out);
   return 0;
   }

int Sodium::crypto_onetimeauth_poly1305_verify(const uint8_t mac[],
                                               const uint8_t in[],
                                               size_t in_len,
                                               const uint8_t key[])
   {
   secure_vector<uint8_t> computed(crypto_onetimeauth_poly1305_BYTES);
   crypto_onetimeauth_poly1305(computed.data(), in, in_len, key);
   return crypto_verify_16(computed.data(), mac) ? 0 : -1;
   }

int Sodium::crypto_auth_hmacsha512(uint8_t out[],
                                   const uint8_t in[],
                                   size_t in_len,
                                   const uint8_t key[])
   {
   auto mac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-512)");
   mac->set_key(key, crypto_auth_hmacsha512_KEYBYTES);
   mac->update(in, in_len);
   mac->final(out);
   return 0;
   }

int Sodium::crypto_auth_hmacsha512_verify(const uint8_t mac[],
                                          const uint8_t in[],
                                          size_t in_len,
                                          const uint8_t key[])
   {
   secure_vector<uint8_t> computed(crypto_auth_hmacsha512_BYTES);
   crypto_auth_hmacsha512(computed.data(), in, in_len, key);
   return crypto_verify_64(computed.data(), mac) ? 0 : -1;
   }

int Sodium::crypto_auth_hmacsha512256(uint8_t out[],
                                      const uint8_t in[],
                                      size_t in_len,
                                      const uint8_t key[])
   {
   auto mac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-512)");
   mac->set_key(key, crypto_auth_hmacsha512256_KEYBYTES);
   mac->update(in, in_len);

   secure_vector<uint8_t> buf(64);
   mac->final(buf);

   copy_mem(out, buf.data(), crypto_auth_hmacsha512256_BYTES);
   return 0;
   }

int Sodium::crypto_auth_hmacsha512256_verify(const uint8_t mac[],
                                             const uint8_t in[],
                                             size_t in_len,
                                             const uint8_t key[])
   {
   secure_vector<uint8_t> computed(crypto_auth_hmacsha512256_BYTES);
   crypto_auth_hmacsha512256(computed.data(), in, in_len, key);
   return crypto_verify_32(computed.data(), mac) ? 0 : -1;
   }

int Sodium::crypto_auth_hmacsha256(uint8_t out[],
                                   const uint8_t in[],
                                   size_t in_len,
                                   const uint8_t key[])
   {
   auto mac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
   mac->set_key(key, crypto_auth_hmacsha256_KEYBYTES);
   mac->update(in, in_len);
   mac->final(out);
   return 0;
   }

int Sodium::crypto_auth_hmacsha256_verify(const uint8_t mac[],
                                          const uint8_t in[],
                                          size_t in_len,
                                          const uint8_t key[])
   {
   secure_vector<uint8_t> computed(crypto_auth_hmacsha256_BYTES);
   crypto_auth_hmacsha256(computed.data(), in, in_len, key);
   return crypto_verify_32(computed.data(), mac) ? 0 : -1;
   }

}
