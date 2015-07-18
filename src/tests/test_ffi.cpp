/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "catchy/catchy_tests.h"
#include <botan/version.h>

#if defined(BOTAN_HAS_FFI)

#include <botan/hex.h>
#include <botan/ffi.h>

using Botan::hex_encode;
using Botan::hex_decode;

TEST_CASE("FFI versioning", "[ffi]")
   {
   CHECK(botan_ffi_api_version() == BOTAN_HAS_FFI);
   CHECK(botan_version_major() == Botan::version_major());
   CHECK(botan_version_minor() == Botan::version_minor());
   CHECK(botan_version_patch() == Botan::version_patch());
   }

TEST_CASE("FFI hex", "[ffi]")
   {
   const std::vector<uint8_t> bin = { 0xAA, 0xDE, 0x01 };
   std::string out;
   out.resize(2*bin.size());

   CHECK(0 == botan_hex_encode(bin.data(), bin.size(), &out[0], 0));
   CHECK(out == "AADE01");

   CHECK(0 == botan_hex_encode(bin.data(), bin.size(), &out[0], BOTAN_FFI_HEX_LOWER_CASE));
   CHECK(out == "aade01");
   }

TEST_CASE("FFI RNG", "[ffi]")
   {
   botan_rng_t rng;
   unsigned char buf[512];

   CHECK(botan_rng_init(&rng, "bad_type") < 0);

   const char* types[] = { "system", "user", nullptr };

   for(size_t i = 0; types[i]; ++i)
      {
      REQUIRE(botan_rng_init(&rng, types[i]) == 0);
      CHECK(0 == botan_rng_get(rng, buf, sizeof(buf)));
      CHECK(0 == botan_rng_reseed(rng, 256));
      CHECK(0 == botan_rng_destroy(rng));
      }
   }

TEST_CASE("FFI hash", "[ffi]")
   {
   botan_hash_t hash;
   CHECK(botan_hash_init(&hash, "SHA-256", 1) < 0);
   REQUIRE(botan_hash_init(&hash, "SHA-256", 0) == 0);

   /*
   char namebuf[32];
   CHECK(botan_hash_name(hash, namebuf, 5) < 0);
   CHECK(0 == botan_hash_name(hash, namebuf, 31));
   CHECK(std::string(namebuf) == "SHA-256");
   */

   size_t ol;
   CHECK(0 == botan_hash_output_length(hash, &ol));
   CHECK(ol == 32);

   const char* s = "ABC";

   std::vector<uint8_t> outbuf(ol);
   CHECK(0 == botan_hash_update(hash, reinterpret_cast<const uint8_t*>(s), 3));
   CHECK(0 == botan_hash_final(hash, outbuf.data()));

   //CHECK_ARRAY(outbuf, "B5D4045C3F466FA91FE2CC6ABE79232A1A57CDF104F7A26E716E0A1E2789DF78");
   CHECK(hex_encode(outbuf) == "B5D4045C3F466FA91FE2CC6ABE79232A1A57CDF104F7A26E716E0A1E2789DF78");

   CHECK(0 == botan_hash_clear(hash));

   CHECK(0 == botan_hash_destroy(hash));
   }

TEST_CASE("FFI mac", "[ffi]")
   {
   botan_mac_t mac;
   CHECK(-1 == botan_mac_init(&mac, "HMAC(SHA-256)", 1)); // bad flag
   CHECK(-2 == botan_mac_init(&mac, "HMAC(SHA-259)", 0)); // bad name
   CHECK(0 == botan_mac_init(&mac, "HMAC(SHA-256)", 0));

   //char namebuf[32];
   //CHECK(botan_mac_name(mac, namebuf, 10) < 0);
   //CHECK(0 == botan_mac_name(mac, namebuf, 31));
   //CHECK(std::string(namebuf) == "HMAC(SHA-256)");

   size_t ol;
   CHECK(0 == botan_mac_output_length(mac, &ol));
   CHECK(ol == 32);

   const uint8_t key[] = { 0xAA, 0xBB, 0xCC, 0xDD };

   CHECK(0 == botan_mac_set_key(mac, key, 4));
   const char* s = "ABC";

   std::vector<uint8_t> outbuf(ol);
   CHECK(0 == botan_mac_update(mac, reinterpret_cast<const uint8_t*>(s), 3));
   CHECK(0 == botan_mac_final(mac, outbuf.data()));

   CHECK(hex_encode(outbuf) == "1A82EEA984BC4A7285617CC0D05F1FE1D6C96675924A81BC965EE8FF7B0697A7");

   CHECK(0 == botan_mac_clear(mac));
   CHECK(0 == botan_mac_destroy(mac));
   }

TEST_CASE("FFI PBKDF", "[ffi]")
   {
   const std::vector<uint8_t> salt = hex_decode("ED1F39A0A7F3889AAF7E60743B3BC1CC2C738E60");
   const std::string passphrase = "ltexmfeyylmlbrsyikaw";
   const size_t out_len = 10;
   const size_t iterations = 1000;

   std::vector<uint8_t> outbuf(out_len);

   CHECK(0 == botan_pbkdf("PBKDF2(SHA-1)", outbuf.data(), outbuf.size(),
                          passphrase.c_str(), salt.data(), salt.size(), iterations));

   CHECK(hex_encode(outbuf) == "027AFADD48F4BE8DCC4F");

   size_t iters_10ms, iters_100ms;
   CHECK(0 == botan_pbkdf_timed("PBKDF2(SHA-1)", outbuf.data(), outbuf.size(),
                                passphrase.c_str(), salt.data(), salt.size(), 10, &iters_10ms));
   CHECK(0 == botan_pbkdf_timed("PBKDF2(SHA-1)", outbuf.data(), outbuf.size(),
                                passphrase.c_str(), salt.data(), salt.size(), 100, &iters_100ms));

   CHECK(iters_10ms >= 10000);

   INFO("Iterations " << iters_10ms << " " << iters_100ms);
   const double ratio = static_cast<double>(iters_100ms) / iters_10ms;
   // Loose timing to avoid false positives on CI
   CHECK(ratio >= 3);
   CHECK(ratio <= 15);
   }

TEST_CASE("FFI KDF", "[ffi]")
   {
   const std::vector<uint8_t> secret = hex_decode("92167440112E");
   const std::vector<uint8_t> salt = hex_decode("45A9BEDED69163123D0348F5185F61ABFB1BF18D6AEA454F");
   const size_t out_len = 18;
   std::vector<uint8_t> out_buf(out_len);

   REQUIRE(botan_kdf("KDF2(SHA-1)", out_buf.data(), out_len,
                     secret.data(), secret.size(), salt.data(), salt.size()) == 0);

   CHECK(hex_encode(out_buf) == "3A5DC9AA1C872B4744515AC2702D6396FC2A");
   }

TEST_CASE("FFI bcrypt", "[ffi]")
   {
   botan_rng_t rng;
   botan_rng_init(&rng, "system");

   std::vector<uint8_t> outbuf(62);
   size_t ol = outbuf.size();

   CHECK(0 == botan_bcrypt_generate(outbuf.data(), &ol, "password", rng, 10, 0));
   botan_rng_destroy(rng);

   CHECK(1 == botan_bcrypt_is_valid("wrong", reinterpret_cast<const char*>(outbuf.data())));
   CHECK(0 == botan_bcrypt_is_valid("password", reinterpret_cast<const char*>(outbuf.data())));

   }

TEST_CASE("FFI RSA", "[ffi]")
   {
   botan_rng_t rng;
   botan_rng_init(&rng, "system");

   botan_privkey_t priv;
   REQUIRE(0 == botan_privkey_create_rsa(&priv, rng, 2048));

   botan_pubkey_t pub;
   CHECK(0 == botan_privkey_export_pubkey(&pub, priv));

   std::string name(64, '\x00');
   size_t name_len = name.size();
   CHECK(0 == botan_pubkey_algo_name(pub, &name[0], &name_len));
   name.resize(name_len - 1);

   CHECK(name == "RSA");

   botan_pk_op_encrypt_t encrypt;
   CHECK(0 == botan_pk_op_encrypt_create(&encrypt, pub, "OAEP(SHA-256)", 0));

   std::vector<uint8_t> plaintext(32);
   CHECK(0 == botan_rng_get(rng, plaintext.data(), plaintext.size()));

   std::vector<uint8_t> ciphertext(256); // TODO: no way to know this size from API
   size_t ctext_len = ciphertext.size();
   CHECK(botan_pk_op_encrypt(encrypt, rng, ciphertext.data(), &ctext_len,
                             plaintext.data(), plaintext.size()) == 0);
   ciphertext.resize(ctext_len);

   CHECK(0 == botan_pk_op_encrypt_destroy(encrypt));
   //CHECK(botan_pk_op_encrypt_destroy(encrypt) < 0);

   botan_pk_op_decrypt_t decrypt;
   CHECK(0 == botan_pk_op_decrypt_create(&decrypt, priv, "OAEP(SHA-256)", 0));

   std::vector<uint8_t> decrypted(256); // TODO as with above
   size_t decrypted_len = decrypted.size();
   CHECK(botan_pk_op_decrypt(decrypt, decrypted.data(), &decrypted_len,
                             ciphertext.data(), ciphertext.size()) == 0);
   decrypted.resize(decrypted_len);

   CHECK(hex_encode(plaintext) == hex_encode(decrypted));

   CHECK(0 == botan_pk_op_decrypt_destroy(decrypt));
   //CHECK(botan_pk_op_decrypt_destroy(decrypt) < 0);

   botan_rng_destroy(rng);
   }

TEST_CASE("FFI ECDSA", "[ffi]")
   {
   botan_rng_t rng;
   botan_rng_init(&rng, "system");

   botan_privkey_t priv;
   int rc = botan_privkey_create_ecdsa(&priv, rng, "secp384r1");

   botan_pubkey_t pub;
   CHECK(0 == botan_privkey_export_pubkey(&pub, priv));

   std::string name(64, '\x00');
   size_t name_len = name.size();
   CHECK(0 == botan_pubkey_algo_name(pub, &name[0], &name_len));
   name.resize(name_len - 1);

   CHECK(name == "ECDSA");

   botan_pk_op_sign_t signer;
   CHECK(0 == botan_pk_op_sign_create(&signer, priv, "EMSA1(SHA-384)", 0));

   std::vector<uint8_t> message(1280);
   CHECK(0 == botan_rng_get(rng, message.data(), message.size()));

   // TODO: break input into multiple calls to update
   CHECK(0 == botan_pk_op_sign_update(signer, message.data(), message.size()));

   std::vector<uint8_t> signature(96); // TODO: no way to derive this from API
   size_t sig_len = signature.size();
   CHECK(0 == botan_pk_op_sign_finish(signer, rng, signature.data(), &sig_len));
   signature.resize(sig_len);
   CHECK(0 == botan_pk_op_sign_destroy(signer));

   botan_pk_op_verify_t verifier;
   CHECK(0 == botan_pk_op_verify_create(&verifier, pub, "EMSA1(SHA-384)", 0));

   CHECK(0 == botan_pk_op_verify_update(verifier, message.data(), message.size()));
   CHECK(0 == botan_pk_op_verify_finish(verifier, signature.data(), signature.size()));

   // TODO: randomize this
   signature[0] ^= 1;

   CHECK(0 == botan_pk_op_verify_update(verifier, message.data(), message.size()));
   CHECK(1 == botan_pk_op_verify_finish(verifier, signature.data(), signature.size()));

   message[0] ^= 1;

   CHECK(0 == botan_pk_op_verify_update(verifier, message.data(), message.size()));
   CHECK(1 == botan_pk_op_verify_finish(verifier, signature.data(), signature.size()));

   signature[0] ^= 1;

   CHECK(0 == botan_pk_op_verify_update(verifier, message.data(), message.size()));
   CHECK(1 == botan_pk_op_verify_finish(verifier, signature.data(), signature.size()));

   message[0] ^= 1;

   CHECK(0 == botan_pk_op_verify_update(verifier, message.data(), message.size()));
   CHECK(0 == botan_pk_op_verify_finish(verifier, signature.data(), signature.size()));

   CHECK(0 == botan_pk_op_verify_destroy(verifier));

   botan_rng_destroy(rng);
   }

TEST_CASE("FFI ECDH", "[ffi]")
   {
   botan_rng_t rng;
   botan_rng_init(&rng, "system");

   botan_privkey_t priv1;
   CHECK(0 == botan_privkey_create_ecdh(&priv1, rng, "secp256r1"));
   botan_privkey_t priv2;
   CHECK(0 == botan_privkey_create_ecdh(&priv2, rng, "secp256r1"));

   botan_pubkey_t pub1;
   CHECK(0 == botan_privkey_export_pubkey(&pub1, priv1));
   botan_pubkey_t pub2;
   CHECK(0 == botan_privkey_export_pubkey(&pub2, priv2));

   botan_pk_op_ka_t ka1;
   CHECK(0 == botan_pk_op_key_agreement_create(&ka1, priv1, "KDF2(SHA-256)", 0));
   botan_pk_op_ka_t ka2;
   CHECK(0 == botan_pk_op_key_agreement_create(&ka2, priv2, "KDF2(SHA-256)", 0));

   std::vector<uint8_t> pubkey1(256); // length problem again
   size_t pubkey1_len = pubkey1.size();
   CHECK(0 == botan_pk_op_key_agreement_export_public(priv1, pubkey1.data(), &pubkey1_len));
   pubkey1.resize(pubkey1_len);

   std::vector<uint8_t> pubkey2(256); // length problem again
   size_t pubkey2_len = pubkey2.size();
   CHECK(0 == botan_pk_op_key_agreement_export_public(priv2, pubkey2.data(), &pubkey2_len));
   pubkey2.resize(pubkey2_len);

   std::vector<uint8_t> salt(32);
   CHECK(0 == botan_rng_get(rng, salt.data(), salt.size()));

   const size_t shared_key_len = 64;

   std::vector<uint8_t> key1(shared_key_len);
   size_t key1_len = key1.size();
   CHECK(0 == botan_pk_op_key_agreement(ka1, key1.data(), &key1_len,
                                        pubkey2.data(), pubkey2.size(),
                                        salt.data(), salt.size()));

   std::vector<uint8_t> key2(shared_key_len);
   size_t key2_len = key2.size();
   CHECK(0 == botan_pk_op_key_agreement(ka2, key2.data(), &key2_len,
                                        pubkey1.data(), pubkey1.size(),
                                        salt.data(), salt.size()));

   CHECK(hex_encode(key1) == hex_encode(key2));

   botan_rng_destroy(rng);
   }

#endif
