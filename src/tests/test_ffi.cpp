/*
* (C) 2015 Jack Lloyd
* (C) 2016 René Korthaus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <botan/version.h>

#if defined(BOTAN_HAS_FFI)
#include <botan/hex.h>
#include <botan/ffi.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_FFI)

#define TEST_FFI_OK(func, args) result.test_rc_ok(#func, func args)
#define TEST_FFI_FAIL(msg, func, args) result.test_rc_fail(#func, msg, func args)
#define TEST_FFI_RC(rc, func, args) result.test_rc(#func, rc, func args)

#define REQUIRE_FFI_OK(func, args)                           \
   if(!TEST_FFI_OK(func, args)) {                            \
      result.test_note("Exiting test early due to failure"); \
      return result;                                         \
   }

class FFI_Unit_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("FFI");

         result.test_is_eq("FFI API version", botan_ffi_api_version(), uint32_t(BOTAN_HAS_FFI));
         result.test_is_eq("Major version", botan_version_major(), Botan::version_major());
         result.test_is_eq("Minor version", botan_version_minor(), Botan::version_minor());
         result.test_is_eq("Patch version", botan_version_patch(), Botan::version_patch());
         result.test_is_eq("Botan version", botan_version_string(), Botan::version_cstr());
         result.test_is_eq("Botan version datestamp", botan_version_datestamp(), Botan::version_datestamp());

         const std::vector<uint8_t> mem1 = { 0xFF, 0xAA, 0xFF };
         const std::vector<uint8_t> mem2 = mem1;
         const std::vector<uint8_t> mem3 = { 0xFF, 0xA9, 0xFF };

         TEST_FFI_RC(0, botan_same_mem, (mem1.data(), mem2.data(), mem1.size()));
         TEST_FFI_RC(-1, botan_same_mem, (mem1.data(), mem3.data(), mem1.size()));

         const std::vector<uint8_t> bin = { 0xAA, 0xDE, 0x01 };
         const char* input_str = "ABC";

         std::string outstr;
         std::vector<uint8_t> outbuf;
         //char namebuf[32];

         outstr.resize(2*bin.size());
         TEST_FFI_OK(botan_hex_encode, (bin.data(), bin.size(), &outstr[0], 0));
         result.test_eq("uppercase hex", outstr, "AADE01");

         TEST_FFI_OK(botan_hex_encode, (bin.data(), bin.size(), &outstr[0], BOTAN_FFI_HEX_LOWER_CASE));
         result.test_eq("lowercase hex", outstr, "aade01");

         // RNG test and initialization
         botan_rng_t rng;

         TEST_FFI_FAIL("invalid rng type", botan_rng_init, (&rng, "invalid_type"));

         outbuf.resize(512);

         if(TEST_FFI_OK(botan_rng_init, (&rng, "system")))
            {
            TEST_FFI_OK(botan_rng_get, (rng, outbuf.data(), outbuf.size()));
            TEST_FFI_OK(botan_rng_reseed, (rng, 256));
            TEST_FFI_OK(botan_rng_destroy, (rng));
            }

         TEST_FFI_OK(botan_rng_init, (&rng, "user"));
         TEST_FFI_OK(botan_rng_get, (rng, outbuf.data(), outbuf.size()));
         TEST_FFI_OK(botan_rng_reseed, (rng, 256));
         // used for the rest of this function and destroyed at the end

         // hashing test
         botan_hash_t hash;
         TEST_FFI_FAIL("invalid hash name", botan_hash_init, (&hash, "SHA-255", 0));
         TEST_FFI_FAIL("invalid flags", botan_hash_init, (&hash, "SHA-256", 1));

         if(TEST_FFI_OK(botan_hash_init, (&hash, "SHA-256", 0)))
            {
            /*
            TEST_FFI_FAIL("output buffer too short", botan_hash_name, (hash, namebuf, 5));

            if(TEST_FFI_OK(botan_hash_name, (hash, namebuf, sizeof(namebuf))))
            {
            result.test_eq("hash name", std::string(namebuf), "SHA-256");
            }
            */

            size_t output_len;
            if(TEST_FFI_OK(botan_hash_output_length, (hash, &output_len)))
               {
               result.test_eq("hash output length", output_len, 32);

               outbuf.resize(output_len);

               // Test that after clear or final the object can be reused
               for(size_t r = 0; r != 2; ++r)
                  {
                  TEST_FFI_OK(botan_hash_update, (hash, reinterpret_cast<const uint8_t*>(input_str), 1));
                  TEST_FFI_OK(botan_hash_clear, (hash));

                  TEST_FFI_OK(botan_hash_update, (hash, reinterpret_cast<const uint8_t*>(input_str), std::strlen(input_str)));
                  TEST_FFI_OK(botan_hash_final, (hash, outbuf.data()));

                  result.test_eq("SHA-256 output", outbuf, "B5D4045C3F466FA91FE2CC6ABE79232A1A57CDF104F7A26E716E0A1E2789DF78");
                  }

               }

            TEST_FFI_OK(botan_hash_destroy, (hash));
            }

         // MAC test
         botan_mac_t mac;
         TEST_FFI_FAIL("bad flag", botan_mac_init, (&mac, "HMAC(SHA-256)", 1));
         TEST_FFI_FAIL("bad name", botan_mac_init, (&mac, "HMAC(SHA-259)", 0));

         if(TEST_FFI_OK(botan_mac_init, (&mac, "HMAC(SHA-256)", 0)))
            {
            /*
            TEST_FFI_FAIL("output buffer too short", botan_mac_name, (mac, namebuf, 5));

            if(TEST_FFI_OK(botan_mac_name, (mac, namebuf, 20)))
            {
            result.test_eq("mac name", std::string(namebuf), "HMAC(SHA-256)");
            }
            */

            size_t output_len;
            if(TEST_FFI_OK(botan_mac_output_length, (mac, &output_len)))
               {
               result.test_eq("MAC output length", output_len, 32);

               const byte mac_key[] = { 0xAA, 0xBB, 0xCC, 0xDD };
               outbuf.resize(output_len);

               // Test that after clear or final the object can be reused
               for(size_t r = 0; r != 2; ++r)
                  {
                  TEST_FFI_OK(botan_mac_set_key, (mac, mac_key, sizeof(mac_key)));
                  TEST_FFI_OK(botan_mac_update, (mac, reinterpret_cast<const uint8_t*>(input_str), std::strlen(input_str)));
                  TEST_FFI_OK(botan_mac_clear, (mac));

                  TEST_FFI_OK(botan_mac_set_key, (mac, mac_key, sizeof(mac_key)));
                  TEST_FFI_OK(botan_mac_update, (mac, reinterpret_cast<const uint8_t*>(input_str), std::strlen(input_str)));
                  TEST_FFI_OK(botan_mac_final, (mac, outbuf.data()));

                  result.test_eq("HMAC output", outbuf, "1A82EEA984BC4A7285617CC0D05F1FE1D6C96675924A81BC965EE8FF7B0697A7");
                  }
               }

            TEST_FFI_OK(botan_mac_destroy, (mac));
            }

         // KDF test
         const std::vector<uint8_t> pbkdf_salt = Botan::hex_decode("ED1F39A0A7F3889AAF7E60743B3BC1CC2C738E60");
         const std::string passphrase = "ltexmfeyylmlbrsyikaw";
         const size_t pbkdf_out_len = 10;
         const size_t pbkdf_iterations = 1000;

         outbuf.resize(pbkdf_out_len);

         if(TEST_FFI_OK(botan_pbkdf, ("PBKDF2(SHA-1)",
                                      outbuf.data(), outbuf.size(),
                                      passphrase.c_str(),
                                      pbkdf_salt.data(), pbkdf_salt.size(),
                                      pbkdf_iterations)))
            {
            result.test_eq("PBKDF output", outbuf, "027AFADD48F4BE8DCC4F");
            }

         size_t iters_10ms, iters_100ms;

         TEST_FFI_OK(botan_pbkdf_timed, ("PBKDF2(SHA-1)", outbuf.data(), outbuf.size(),
                                         passphrase.c_str(),
                                         pbkdf_salt.data(), pbkdf_salt.size(),
                                         10, &iters_10ms));
         TEST_FFI_OK(botan_pbkdf_timed, ("PBKDF2(SHA-1)", outbuf.data(), outbuf.size(),
                                         passphrase.c_str(),
                                         pbkdf_salt.data(), pbkdf_salt.size(),
                                         100, &iters_100ms));

         result.test_note("PBKDF timed 10 ms " + std::to_string(iters_10ms) + " iterations " +
                          "100 ms " + std::to_string(iters_100ms) + " iterations");

         const std::vector<uint8_t> kdf_secret = Botan::hex_decode("92167440112E");
         const std::vector<uint8_t> kdf_salt = Botan::hex_decode("45A9BEDED69163123D0348F5185F61ABFB1BF18D6AEA454F");
         const size_t kdf_out_len = 18;
         outbuf.resize(kdf_out_len);

         if(TEST_FFI_OK(botan_kdf, ("KDF2(SHA-1)", outbuf.data(), outbuf.size(),
                                    kdf_secret.data(),
                                    kdf_secret.size(),
                                    kdf_salt.data(),
                                    kdf_salt.size(),
                                    nullptr,
                                    0)))
            {
            result.test_eq("KDF output", outbuf, "3A5DC9AA1C872B4744515AC2702D6396FC2A");
            }

         size_t out_len = 64;
         outstr.resize(out_len);

         int rc = botan_bcrypt_generate(reinterpret_cast<uint8_t*>(&outstr[0]),
                                        &out_len, passphrase.c_str(), rng, 3, 0);

         if(rc == 0)
            {
            result.test_eq("bcrypt output size", out_len, 61);

            TEST_FFI_OK(botan_bcrypt_is_valid, (passphrase.c_str(), outstr.data()));
            TEST_FFI_FAIL("bad password", botan_bcrypt_is_valid, ("nope", outstr.data()));
            }

         // TODO: Cipher test
         /*
         botan_cipher_t cipher_encrypt, cipher_decrypt;

         if(TEST_FFI_OK(botan_cipher_init, (&cipher_encrypt, "AES-128/CBC", BOTAN_CIPHER_INIT_FLAG_ENCRYPT)))
            {
            size_t min_keylen = 0;
            size_t max_keylen = 0;
            TEST_FFI_OK(botan_cipher_query_keylen, (cipher_encrypt, &min_keylen, &max_keylen));
            result.test_int_eq(min_keylen, 16, "Min key length");
            result.test_int_eq(max_keylen, 16, "Max key length");

            std::vector<uint8_t> plaintext(256);
            std::vector<uint8_t> nonce(16);
            TEST_FFI_OK(botan_rng_get, (rng, plaintext.data(), plaintext.size()));
            TEST_FFI_OK(botan_rng_get, (rng, nonce.data(), nonce.size()));

            std::vector<uint8_t> ciphertext(plaintext.size()); // TODO: no way to know this size from API

            const std::vector<uint8_t> symkey = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01,
                                                  0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

            size_t output_written = 0;
            size_t input_consumed = 0;

            // Test that after clear or final the object can be reused
            for(size_t r = 0; r != 2; ++r)
               {
               TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, nonce.data(), nonce.size()));
               TEST_FFI_OK(botan_cipher_set_key, (cipher_encrypt, symkey.data(), symkey.size()));
               TEST_FFI_OK(botan_cipher_update, (cipher_encrypt, 0, ciphertext.data(), ciphertext.size(), &output_written,
                           plaintext.data(), plaintext.size(), &input_consumed));
               TEST_FFI_OK(botan_cipher_clear, (cipher_encrypt));

               TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, nonce.data(), nonce.size()));
               TEST_FFI_OK(botan_cipher_set_key, (cipher_encrypt, symkey.data(), symkey.size()));
               TEST_FFI_OK(botan_cipher_update, (cipher_encrypt, BOTAN_CIPHER_UPDATE_FLAG_FINAL, ciphertext.data(), ciphertext.size(), &output_written,
                           plaintext.data(), plaintext.size(), &input_consumed));

               if(TEST_FFI_OK(botan_cipher_init, (&cipher_decrypt, "AES-128/CBC", BOTAN_CIPHER_INIT_FLAG_DECRYPT)))
                  {
                  std::vector<uint8_t> decrypted(plaintext.size());

                  TEST_FFI_OK(botan_cipher_start, (cipher_decrypt, nonce.data(), nonce.size()));
                  TEST_FFI_OK(botan_cipher_set_key, (cipher_decrypt, symkey.data(), symkey.size()));
                  TEST_FFI_OK(botan_cipher_update, (cipher_decrypt, BOTAN_CIPHER_UPDATE_FLAG_FINAL, decrypted.data(), decrypted.size(), &output_written,
                        ciphertext.data(), ciphertext.size(), &input_consumed));

                  result.test_eq("AES plaintext", decrypted, plaintext);

                  TEST_FFI_OK(botan_cipher_destroy, (cipher_decrypt));
                  }
               }

            TEST_FFI_OK(botan_cipher_destroy, (cipher_encrypt));
            }
         */

         // TODO: AEAD test
         // TODO ONCE MORE WITH AES-GCM
         // botan_cipher_set_associated_data
         // botan_cipher_valid_nonce_length
         // botan_cipher_get_default_nonce_length
         // botan_cipher_get_tag_length

         // x509 cert test
         botan_x509_cert_t cert;
         if(TEST_FFI_OK(botan_x509_cert_load_file, (&cert, "src/tests/data/ecc/CSCA.CSCA.csca-germany.1.crt")))
            {
            size_t date_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_time_starts, (cert, nullptr, &date_len));

            std::string date(date_len-1, '0');
            TEST_FFI_OK(botan_x509_cert_get_time_starts, (cert, &date[0], &date_len));
            result.test_eq("cert valid from", date, "070719152718Z");

            date_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_time_expires, (cert, nullptr, &date_len));

            date.resize(date_len-1);
            TEST_FFI_OK(botan_x509_cert_get_time_expires, (cert, &date[0], &date_len));
            result.test_eq("cert valid until", date, "280119151800Z");

            size_t serial_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_serial_number, (cert, nullptr, &serial_len));

            std::vector<uint8_t> serial(serial_len);
            TEST_FFI_OK(botan_x509_cert_get_serial_number, (cert, serial.data(), &serial_len));
            result.test_eq("cert serial length", serial.size(), 1);
            result.test_int_eq(serial[0], 1, "cert serial");

            size_t fingerprint_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_fingerprint, (cert, "SHA-256", nullptr, &fingerprint_len));

            std::vector<uint8_t> fingerprint(fingerprint_len);
            TEST_FFI_OK(botan_x509_cert_get_fingerprint, (cert, "SHA-256", fingerprint.data(), &fingerprint_len));
            result.test_eq("cert fingerprint", reinterpret_cast<const char*>(fingerprint.data()), "3B:6C:99:1C:D6:5A:51:FC:EB:17:E3:AA:F6:3C:1A:DA:14:1F:82:41:30:6F:64:EE:FF:63:F3:1F:D6:07:14:9F");

            size_t key_id_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_authority_key_id, (cert, nullptr, &key_id_len));

            std::vector<uint8_t> key_id(key_id_len);
            TEST_FFI_OK(botan_x509_cert_get_authority_key_id, (cert, key_id.data(), &key_id_len));
            result.test_eq("cert authority key id", Botan::hex_encode(key_id.data(), key_id.size(), true), "0096452DE588F966C4CCDF161DD1F3F5341B71E7");

            key_id_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_subject_key_id, (cert, nullptr, &key_id_len));

            key_id.resize(key_id_len);
            TEST_FFI_OK(botan_x509_cert_get_subject_key_id, (cert, key_id.data(), &key_id_len));
            result.test_eq("cert subject key id", Botan::hex_encode(key_id.data(), key_id.size(), true), "0096452DE588F966C4CCDF161DD1F3F5341B71E7");

            size_t pubkey_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_public_key_bits, (cert, nullptr, &pubkey_len));

            std::vector<uint8_t> pubkey(pubkey_len);
            TEST_FFI_OK(botan_x509_cert_get_public_key_bits, (cert, pubkey.data(), &pubkey_len));

            botan_pubkey_t pub;
            if(TEST_FFI_OK(botan_x509_cert_get_public_key, (cert, &pub)))
               {
               TEST_FFI_OK(botan_pubkey_destroy, (pub));
               }

            size_t dn_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_issuer_dn, (cert, "Name", 0, nullptr, &dn_len));

            std::vector<uint8_t> dn(dn_len);
            TEST_FFI_OK(botan_x509_cert_get_issuer_dn, (cert, "Name", 0, dn.data(), &dn_len));
            result.test_eq("issuer dn", reinterpret_cast<const char*>(dn.data()), "csca-germany");

            dn_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_subject_dn, (cert, "Name", 0, nullptr, &dn_len));

            dn.resize(dn_len);
            TEST_FFI_OK(botan_x509_cert_get_subject_dn, (cert, "Name", 0, dn.data(), &dn_len));
            result.test_eq("subject dn", reinterpret_cast<const char*>(dn.data()), "csca-germany");

            size_t printable_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_to_string, (cert, nullptr, &printable_len));

            std::string printable(printable_len-1, '0');
            TEST_FFI_OK(botan_x509_cert_to_string, (cert, &printable[0], &printable_len));

            TEST_FFI_RC(0, botan_x509_cert_allowed_usage, (cert, KEY_CERT_SIGN));
            TEST_FFI_RC(0, botan_x509_cert_allowed_usage, (cert, CRL_SIGN));
            TEST_FFI_RC(1, botan_x509_cert_allowed_usage, (cert, DIGITAL_SIGNATURE));

            TEST_FFI_OK(botan_x509_cert_destroy, (cert));
            }

         std::vector<Test::Result> results;
         results.push_back(ffi_test_rsa(rng));
         results.push_back(ffi_test_ecdsa(rng));
         results.push_back(ffi_test_ecdh(rng));
         results.push_back(ffi_test_mceliece(rng));

         TEST_FFI_OK(botan_rng_destroy, (rng));

         results.push_back(result);
         return results;
         }

   private:
      void ffi_test_pubkey_export(Test::Result& result, botan_pubkey_t pub, botan_privkey_t priv, botan_rng_t rng)
         {
         // export public key
         size_t pubkey_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_pubkey_export, (pub, nullptr, &pubkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_DER));

         std::vector<uint8_t> pubkey(pubkey_len);
         TEST_FFI_OK(botan_pubkey_export, (pub, pubkey.data(), &pubkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_DER));

         pubkey_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_pubkey_export, (pub, nullptr, &pubkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

         pubkey.resize(pubkey_len);
         TEST_FFI_OK(botan_pubkey_export, (pub, pubkey.data(), &pubkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

         // export private key
         size_t privkey_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_privkey_export, (priv, nullptr, &privkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_DER));

         std::vector<uint8_t> privkey(privkey_len);
         TEST_FFI_OK(botan_privkey_export, (priv, privkey.data(), &privkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_DER));

         privkey_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_privkey_export, (priv, nullptr, &privkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

         privkey.resize(privkey_len);
         TEST_FFI_OK(botan_privkey_export, (priv, privkey.data(), &privkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

         // export private key encrypted
         privkey_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_privkey_export_encrypted, (priv, nullptr, &privkey_len, rng, "password", "", BOTAN_PRIVKEY_EXPORT_FLAG_DER));

         privkey.resize(privkey_len);
         TEST_FFI_OK(botan_privkey_export_encrypted, (priv, privkey.data(), &privkey_len, rng, "password", "", BOTAN_PRIVKEY_EXPORT_FLAG_DER));

         privkey_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_privkey_export_encrypted, (priv, nullptr, &privkey_len, rng, "password", "", BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

         privkey.resize(privkey_len);
         TEST_FFI_OK(botan_privkey_export_encrypted, (priv, privkey.data(), &privkey_len, rng, "password", "", BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

         // calculate fingerprint
         size_t strength = 0;
         TEST_FFI_OK(botan_pubkey_estimated_strength, (pub, &strength));
         result.test_gte("estimated strength", strength, 1);

         size_t fingerprint_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_pubkey_fingerprint, (pub, "SHA-512", nullptr, &fingerprint_len));

         std::vector<uint8_t> fingerprint(fingerprint_len);
         TEST_FFI_OK(botan_pubkey_fingerprint, (pub, "SHA-512", fingerprint.data(), &fingerprint_len));
         }

      Test::Result ffi_test_rsa(botan_rng_t rng)
         {
         Test::Result result("FFI");

         botan_privkey_t priv;
         if(TEST_FFI_OK(botan_privkey_create_rsa, (&priv, rng, 1024)))
            {
            botan_pubkey_t pub;
            TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));

            ffi_test_pubkey_export(result, pub, priv, rng);

            char namebuf[32] = { 0 };
            size_t name_len = sizeof(namebuf);
            if(TEST_FFI_OK(botan_pubkey_algo_name, (pub, namebuf, &name_len)))
               {
               result.test_eq("algo name", std::string(namebuf), "RSA");
               }

            botan_pk_op_encrypt_t encrypt;

            if(TEST_FFI_OK(botan_pk_op_encrypt_create, (&encrypt, pub, "OAEP(SHA-256)", 0)))
               {
               std::vector<uint8_t> plaintext(32);
               TEST_FFI_OK(botan_rng_get, (rng, plaintext.data(), plaintext.size()));

               std::vector<uint8_t> ciphertext(256); // TODO: no way to know this size from API
               size_t ctext_len = ciphertext.size();

               if(TEST_FFI_OK(botan_pk_op_encrypt, (encrypt, rng,
                                                    ciphertext.data(), &ctext_len,
                                                    plaintext.data(), plaintext.size())))
                  {
                  ciphertext.resize(ctext_len);

                  botan_pk_op_decrypt_t decrypt;
                  if(TEST_FFI_OK(botan_pk_op_decrypt_create, (&decrypt, priv, "OAEP(SHA-256)", 0)))
                     {
                     std::vector<uint8_t> decrypted(256); // TODO as with above
                     size_t decrypted_len = decrypted.size();
                     TEST_FFI_OK(botan_pk_op_decrypt, (decrypt, decrypted.data(), &decrypted_len,
                                                       ciphertext.data(), ciphertext.size()));
                     decrypted.resize(decrypted_len);

                     result.test_eq("RSA plaintext", decrypted, plaintext);
                     }

                  TEST_FFI_OK(botan_pk_op_decrypt_destroy, (decrypt));
                  }

               TEST_FFI_OK(botan_pk_op_encrypt_destroy, (encrypt));
               }

            TEST_FFI_OK(botan_pubkey_destroy, (pub));
            TEST_FFI_OK(botan_privkey_destroy, (priv));
            }

         return result;
         }

      Test::Result ffi_test_ecdsa(botan_rng_t rng)
         {
         Test::Result result("FFI");

         botan_privkey_t priv;

         if(TEST_FFI_OK(botan_privkey_create_ecdsa, (&priv, rng, "secp384r1")))
            {
            botan_pubkey_t pub;
            TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));

            ffi_test_pubkey_export(result, pub, priv, rng);

            char namebuf[32] = { 0 };
            size_t name_len = sizeof(namebuf);
            TEST_FFI_OK(botan_pubkey_algo_name, (pub, &namebuf[0], &name_len));

            result.test_eq(namebuf, namebuf, "ECDSA");

            std::vector<uint8_t> message(1280), signature;
            TEST_FFI_OK(botan_rng_get, (rng, message.data(), message.size()));

            botan_pk_op_sign_t signer;

            if(TEST_FFI_OK(botan_pk_op_sign_create, (&signer, priv, "EMSA1(SHA-384)", 0)))
               {
               // TODO: break input into multiple calls to update
               TEST_FFI_OK(botan_pk_op_sign_update, (signer, message.data(), message.size()));

               signature.resize(96); // TODO: no way to derive this from API
               size_t sig_len = signature.size();
               TEST_FFI_OK(botan_pk_op_sign_finish, (signer, rng, signature.data(), &sig_len));
               signature.resize(sig_len);

               TEST_FFI_OK(botan_pk_op_sign_destroy, (signer));
               }

            botan_pk_op_verify_t verifier;

            if(TEST_FFI_OK(botan_pk_op_verify_create, (&verifier, pub, "EMSA1(SHA-384)", 0)))
               {
               TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
               TEST_FFI_OK(botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

               // TODO: randomize this
               signature[0] ^= 1;
               TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
               TEST_FFI_FAIL("bad signature", botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

               message[0] ^= 1;
               TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
               TEST_FFI_FAIL("bad signature", botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

               signature[0] ^= 1;
               TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
               TEST_FFI_FAIL("bad signature", botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

               message[0] ^= 1;
               TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
               TEST_FFI_OK(botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

               TEST_FFI_OK(botan_pk_op_verify_destroy, (verifier));
               }

            TEST_FFI_OK(botan_pubkey_destroy, (pub));
            TEST_FFI_OK(botan_privkey_destroy, (priv));
            }

         return result;
         }

      Test::Result ffi_test_ecdh(botan_rng_t rng)
         {
         Test::Result result("FFI");

         botan_privkey_t priv1;
         REQUIRE_FFI_OK(botan_privkey_create_ecdh, (&priv1, rng, "secp256r1"));

         botan_privkey_t priv2;
         REQUIRE_FFI_OK(botan_privkey_create_ecdh, (&priv2, rng, "secp256r1"));

         botan_pubkey_t pub1;
         REQUIRE_FFI_OK(botan_privkey_export_pubkey, (&pub1, priv1));

         botan_pubkey_t pub2;
         REQUIRE_FFI_OK(botan_privkey_export_pubkey, (&pub2, priv2));

         ffi_test_pubkey_export(result, pub1, priv1, rng);
         ffi_test_pubkey_export(result, pub2, priv2, rng);

         botan_pk_op_ka_t ka1;
         REQUIRE_FFI_OK(botan_pk_op_key_agreement_create, (&ka1, priv1, "KDF2(SHA-256)", 0));
         botan_pk_op_ka_t ka2;
         REQUIRE_FFI_OK(botan_pk_op_key_agreement_create, (&ka2, priv2, "KDF2(SHA-256)", 0));

         std::vector<uint8_t> pubkey1(256); // length problem again
         size_t pubkey1_len = pubkey1.size();
         REQUIRE_FFI_OK(botan_pk_op_key_agreement_export_public, (priv1, pubkey1.data(), &pubkey1_len));
         pubkey1.resize(pubkey1_len);

         std::vector<uint8_t> pubkey2(256); // length problem again
         size_t pubkey2_len = pubkey2.size();
         REQUIRE_FFI_OK(botan_pk_op_key_agreement_export_public, (priv2, pubkey2.data(), &pubkey2_len));
         pubkey2.resize(pubkey2_len);

         std::vector<uint8_t> salt(32);
         TEST_FFI_OK(botan_rng_get, (rng, salt.data(), salt.size()));

         const size_t shared_key_len = 64;

         std::vector<uint8_t> key1(shared_key_len);
         size_t key1_len = key1.size();
         TEST_FFI_OK(botan_pk_op_key_agreement, (ka1, key1.data(), &key1_len,
                                                 pubkey2.data(), pubkey2.size(),
                                                 salt.data(), salt.size()));

         std::vector<uint8_t> key2(shared_key_len);
         size_t key2_len = key2.size();
         TEST_FFI_OK(botan_pk_op_key_agreement, (ka2, key2.data(), &key2_len,
                                                 pubkey1.data(), pubkey1.size(),
                                                 salt.data(), salt.size()));

         result.test_eq("shared ECDH key", key1, key2);

         TEST_FFI_OK(botan_pk_op_key_agreement_destroy, (ka1));
         TEST_FFI_OK(botan_pk_op_key_agreement_destroy, (ka2));
         TEST_FFI_OK(botan_privkey_destroy, (priv1));
         TEST_FFI_OK(botan_privkey_destroy, (priv2));
         TEST_FFI_OK(botan_pubkey_destroy, (pub1));
         TEST_FFI_OK(botan_pubkey_destroy, (pub2));

         return result;
         }

      Test::Result ffi_test_mceliece(botan_rng_t rng)
         {
         Test::Result result("FFI");

         botan_privkey_t priv;
         if (TEST_FFI_OK(botan_privkey_create_mceliece, (&priv, rng, 2048, 50)))
            {
            botan_pubkey_t pub;
            TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));

            ffi_test_pubkey_export(result, pub, priv, rng);

            char namebuf[32] = { 0 };
            size_t name_len = sizeof(namebuf);
            if (TEST_FFI_OK(botan_pubkey_algo_name, (pub, namebuf, &name_len)))
               {
               result.test_eq("algo name", std::string(namebuf), "McEliece");
               }

            size_t i = 0;
            uint8_t ad[8];
            Botan::store_be(static_cast<Botan::u64bit>(i), ad);
            const size_t ad_len = sizeof(ad);

            const Botan::secure_vector<byte> plaintext = Test::rng().random_vec(Test::rng().next_byte());
            size_t plaintext_len = plaintext.size();
            size_t ciphertext_len = 0;

            // first calculate ciphertext length
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_mceies_encrypt, (pub, rng, "AES-256/OCB", plaintext.data(), plaintext.size(), ad, ad_len, nullptr, &ciphertext_len));
            std::vector<uint8_t> ciphertext(ciphertext_len);

            // now encrypt
            if (TEST_FFI_OK(botan_mceies_encrypt, (pub, rng, "AES-256/OCB", plaintext.data(), plaintext.size(), ad, ad_len, ciphertext.data(), &ciphertext_len)))
               {
               std::vector<uint8_t> decrypted(plaintext.size());
               size_t decrypted_len = plaintext_len;

               TEST_FFI_OK(botan_mceies_decrypt, (priv, "AES-256/OCB", ciphertext.data(), ciphertext.size(), ad, ad_len, decrypted.data(), &decrypted_len));

               result.test_eq("MCIES plaintext", decrypted, plaintext);
               }

            TEST_FFI_OK(botan_pubkey_destroy, (pub));
            TEST_FFI_OK(botan_privkey_destroy, (priv));
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("ffi", FFI_Unit_Tests);

#endif

}

}

