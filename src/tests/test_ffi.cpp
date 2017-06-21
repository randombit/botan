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
         result.test_is_eq("FFI supports its own version", botan_ffi_supports_api(botan_ffi_api_version()), 0);

         const std::vector<uint8_t> mem1 = { 0xFF, 0xAA, 0xFF };
         const std::vector<uint8_t> mem2 = mem1;
         const std::vector<uint8_t> mem3 = { 0xFF, 0xA9, 0xFF };

         TEST_FFI_RC(0, botan_same_mem, (mem1.data(), mem2.data(), mem1.size()));
         TEST_FFI_RC(-1, botan_same_mem, (mem1.data(), mem3.data(), mem1.size()));

         std::vector<uint8_t> to_zero = { 0xFF, 0xA0 };
         TEST_FFI_OK(botan_scrub_mem, (to_zero.data(), to_zero.size()));
         result.confirm("scrub_memory zeros", to_zero[0] == 0 && to_zero[1] == 0);

         const std::vector<uint8_t> bin = { 0xAA, 0xDE, 0x01 };
         const char* input_str = "ABC";

         std::string outstr;
         std::vector<uint8_t> outbuf;
         //char namebuf[32];

         outstr.resize(2 * bin.size());
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

         if(TEST_FFI_OK(botan_rng_init, (&rng, "user")))
            {
            TEST_FFI_OK(botan_rng_get, (rng, outbuf.data(), outbuf.size()));
            TEST_FFI_OK(botan_rng_reseed, (rng, 256));
            // used for the rest of this function and destroyed at the end
            }
         else
            {
            result.test_note("Existing early due to missing FFI RNG");
            return {result};
            }

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
            size_t block_size;
            if (TEST_FFI_OK(botan_hash_block_size, (hash, &block_size)))
               {
                  result.test_eq("hash block size", block_size, 64);
               }

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

               // Test botan_hash_copy_state
               const char *msg = "message digest";
               const char *expected = "F7846F55CF23E14EEBEAB5B4E1550CAD5B509E3348FBC4EFA3A1413D393CB650";
               TEST_FFI_OK(botan_hash_clear, (hash));
               TEST_FFI_OK(botan_hash_update, (hash, reinterpret_cast<const uint8_t*>(&msg[0]), 1));
               botan_hash_t fork;
               if (TEST_FFI_OK(botan_hash_copy_state, (&fork, hash)))
                  {
                  TEST_FFI_OK(botan_hash_update, (fork, reinterpret_cast<const uint8_t*>(&msg[1]), std::strlen(msg) - 2));

                  TEST_FFI_OK(botan_hash_update, (hash, reinterpret_cast<const uint8_t*>(&msg[1]), std::strlen(msg) - 1));
                  TEST_FFI_OK(botan_hash_final, (hash, outbuf.data()));
                  result.test_eq("hashing split", outbuf, expected);

                  TEST_FFI_OK(botan_hash_update, (fork, reinterpret_cast<const uint8_t*>(&msg[std::strlen(msg)-1]), 1));
                  TEST_FFI_OK(botan_hash_final, (fork, outbuf.data()));
                  result.test_eq("hashing split", outbuf, expected);

                  TEST_FFI_OK(botan_hash_destroy, (fork));
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

               const uint8_t mac_key[] = { 0xAA, 0xBB, 0xCC, 0xDD };
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
                                        &out_len, passphrase.c_str(), rng, 4, 0);

         if(rc == 0)
            {
            result.test_eq("bcrypt output size", out_len, 61);

            TEST_FFI_OK(botan_bcrypt_is_valid, (passphrase.c_str(), outstr.data()));
            TEST_FFI_FAIL("bad password", botan_bcrypt_is_valid, ("nope", outstr.data()));
            }

         // x509 cert test
         botan_x509_cert_t cert;
         if(TEST_FFI_OK(botan_x509_cert_load_file, (&cert, "src/tests/data/ecc/CSCA.CSCA.csca-germany.1.crt")))
            {
            size_t date_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_time_starts, (cert, nullptr, &date_len));

            std::string date(date_len - 1, '0');
            TEST_FFI_OK(botan_x509_cert_get_time_starts, (cert, &date[0], &date_len));
            result.test_eq("cert valid from", date, "070719152718Z");

            date_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_time_expires, (cert, nullptr, &date_len));

            date.resize(date_len - 1);
            TEST_FFI_OK(botan_x509_cert_get_time_expires, (cert, &date[0], &date_len));
            result.test_eq("cert valid until", date, "280119151800Z");

            size_t serial_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_serial_number, (cert, nullptr, &serial_len));

            std::vector<uint8_t> serial(serial_len);
            TEST_FFI_OK(botan_x509_cert_get_serial_number, (cert, serial.data(), &serial_len));
            result.test_eq("cert serial length", serial.size(), 1);
            result.test_int_eq(serial[0], 1, "cert serial");

            size_t fingerprint_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_fingerprint,
                        (cert, "SHA-256", nullptr, &fingerprint_len));

            std::vector<uint8_t> fingerprint(fingerprint_len);
            TEST_FFI_OK(botan_x509_cert_get_fingerprint, (cert, "SHA-256", fingerprint.data(), &fingerprint_len));
            result.test_eq("cert fingerprint", reinterpret_cast<const char*>(fingerprint.data()),
                           "3B:6C:99:1C:D6:5A:51:FC:EB:17:E3:AA:F6:3C:1A:DA:14:1F:82:41:30:6F:64:EE:FF:63:F3:1F:D6:07:14:9F");

            size_t key_id_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_authority_key_id,
                        (cert, nullptr, &key_id_len));

            std::vector<uint8_t> key_id(key_id_len);
            TEST_FFI_OK(botan_x509_cert_get_authority_key_id, (cert, key_id.data(), &key_id_len));
            result.test_eq("cert authority key id", Botan::hex_encode(key_id.data(), key_id.size(), true),
                           "0096452DE588F966C4CCDF161DD1F3F5341B71E7");

            key_id_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_subject_key_id,
                        (cert, nullptr, &key_id_len));

            key_id.resize(key_id_len);
            TEST_FFI_OK(botan_x509_cert_get_subject_key_id, (cert, key_id.data(), &key_id_len));
            result.test_eq("cert subject key id", Botan::hex_encode(key_id.data(), key_id.size(), true),
                           "0096452DE588F966C4CCDF161DD1F3F5341B71E7");

            size_t pubkey_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_public_key_bits,
                        (cert, nullptr, &pubkey_len));

            std::vector<uint8_t> pubkey(pubkey_len);
            TEST_FFI_OK(botan_x509_cert_get_public_key_bits, (cert, pubkey.data(), &pubkey_len));

            botan_pubkey_t pub;
            if(TEST_FFI_OK(botan_x509_cert_get_public_key, (cert, &pub)))
               {
               TEST_FFI_OK(botan_pubkey_destroy, (pub));
               }

            size_t dn_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_issuer_dn,
                        (cert, "Name", 0, nullptr, &dn_len));

            std::vector<uint8_t> dn(dn_len);
            TEST_FFI_OK(botan_x509_cert_get_issuer_dn, (cert, "Name", 0, dn.data(), &dn_len));
            result.test_eq("issuer dn", reinterpret_cast<const char*>(dn.data()), "csca-germany");

            dn_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_subject_dn,
                        (cert, "Name", 0, nullptr, &dn_len));

            dn.resize(dn_len);
            TEST_FFI_OK(botan_x509_cert_get_subject_dn, (cert, "Name", 0, dn.data(), &dn_len));
            result.test_eq("subject dn", reinterpret_cast<const char*>(dn.data()), "csca-germany");

            size_t printable_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_to_string,
                        (cert, nullptr, &printable_len));

            std::string printable(printable_len - 1, '0');
            TEST_FFI_OK(botan_x509_cert_to_string, (cert, &printable[0], &printable_len));

            TEST_FFI_RC(0, botan_x509_cert_allowed_usage, (cert, KEY_CERT_SIGN));
            TEST_FFI_RC(0, botan_x509_cert_allowed_usage, (cert, CRL_SIGN));
            TEST_FFI_RC(1, botan_x509_cert_allowed_usage, (cert, DIGITAL_SIGNATURE));

            TEST_FFI_OK(botan_x509_cert_destroy, (cert));
            }

         std::vector<Test::Result> results;
         results.push_back(ffi_test_mp(rng));
         results.push_back(ffi_test_block_ciphers());
         results.push_back(ffi_test_ciphers_cbc());
         results.push_back(ffi_test_ciphers_aead());
         results.push_back(ffi_test_stream_ciphers());
         results.push_back(ffi_test_pkcs_hash_id());

#if defined(BOTAN_HAS_RSA)
         results.push_back(ffi_test_rsa(rng));
#endif

#if defined(BOTAN_HAS_DSA)
         results.push_back(ffi_test_dsa(rng));
#endif

#if defined(BOTAN_HAS_ECDSA)
         results.push_back(ffi_test_ecdsa(rng));
#endif

#if defined(BOTAN_HAS_ECDH)
         results.push_back(ffi_test_ecdh(rng));
#endif

#if defined(BOTAN_HAS_SM2)
         results.push_back(ffi_test_sm2(rng));
#endif

#if defined(BOTAN_HAS_MCELIECE)
         results.push_back(ffi_test_mceliece(rng));
#endif

#if defined(BOTAN_HAS_ELGAMAL)
         results.push_back(ffi_test_elgamal(rng));
#endif

#if defined(BOTAN_HAS_ED25519)
         results.push_back(ffi_test_ed25519(rng));
#endif

         TEST_FFI_OK(botan_rng_destroy, (rng));

         results.push_back(result);
         return results;
         }

   private:
      Test::Result ffi_test_pkcs_hash_id()
         {
         Test::Result result("FFI PKCS hash id");

#if defined(BOTAN_HAS_HASH_ID)
         std::vector<uint8_t> hash_id(64);
         size_t hash_id_len;

         hash_id_len = 3; // too short
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                     botan_pkcs_hash_id, ("SHA-256", hash_id.data(), &hash_id_len));

         result.test_eq("Expected SHA-256 PKCS hash id len", hash_id_len, 19);

         TEST_FFI_OK(botan_pkcs_hash_id, ("SHA-256", hash_id.data(), &hash_id_len));

         result.test_eq("Expected SHA-256 PKCS hash id len", hash_id_len, 19);

         hash_id.resize(hash_id_len);
         result.test_eq("Expected SHA_256 PKCS hash id",
                        hash_id, "3031300D060960864801650304020105000420");
#endif

         return result;
         }

      Test::Result ffi_test_ciphers_cbc()
         {
         Test::Result result("FFI CBC cipher");

         botan_cipher_t cipher_encrypt, cipher_decrypt;

         if(TEST_FFI_OK(botan_cipher_init, (&cipher_encrypt, "AES-128/CBC/PKCS7", BOTAN_CIPHER_INIT_FLAG_ENCRYPT)))
            {
            size_t min_keylen = 0;
            size_t max_keylen = 0;
            TEST_FFI_OK(botan_cipher_query_keylen, (cipher_encrypt, &min_keylen, &max_keylen));
            result.test_int_eq(min_keylen, 16, "Min key length");
            result.test_int_eq(max_keylen, 16, "Max key length");

            // from https://github.com/geertj/bluepass/blob/master/tests/vectors/aes-cbc-pkcs7.txt
            const std::vector<uint8_t> plaintext =
               Botan::hex_decode("0397f4f6820b1f9386f14403be5ac16e50213bd473b4874b9bcbf5f318ee686b1d");
            const std::vector<uint8_t> symkey = Botan::hex_decode("898be9cc5004ed0fa6e117c9a3099d31");
            const std::vector<uint8_t> nonce = Botan::hex_decode("9dea7621945988f96491083849b068df");
            const std::vector<uint8_t> exp_ciphertext =
               Botan::hex_decode("e232cd6ef50047801ee681ec30f61d53cfd6b0bca02fd03c1b234baa10ea82ac9dab8b960926433a19ce6dea08677e34");

            std::vector<uint8_t> ciphertext(16 + plaintext.size()); // TODO: no way to know this size from API

            size_t output_written = 0;
            size_t input_consumed = 0;

            // Test that after clear or final the object can be reused
            for(size_t r = 0; r != 2; ++r)
               {
               TEST_FFI_OK(botan_cipher_set_key, (cipher_encrypt, symkey.data(), symkey.size()));
               TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, nonce.data(), nonce.size()));
               TEST_FFI_OK(botan_cipher_update, (cipher_encrypt, 0, ciphertext.data(), ciphertext.size(), &output_written,
                                                 plaintext.data(), plaintext.size(), &input_consumed));
               TEST_FFI_OK(botan_cipher_clear, (cipher_encrypt));

               TEST_FFI_OK(botan_cipher_set_key, (cipher_encrypt, symkey.data(), symkey.size()));
               TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, nonce.data(), nonce.size()));
               TEST_FFI_OK(botan_cipher_update, (cipher_encrypt, BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                                                 ciphertext.data(), ciphertext.size(), &output_written,
                                                 plaintext.data(), plaintext.size(), &input_consumed));

               ciphertext.resize(output_written);
               result.test_eq("AES/CBC ciphertext", ciphertext, exp_ciphertext);

               if(TEST_FFI_OK(botan_cipher_init, (&cipher_decrypt, "AES-128/CBC", BOTAN_CIPHER_INIT_FLAG_DECRYPT)))
                  {
                  std::vector<uint8_t> decrypted(plaintext.size());

                  TEST_FFI_OK(botan_cipher_set_key, (cipher_decrypt, symkey.data(), symkey.size()));
                  TEST_FFI_OK(botan_cipher_start, (cipher_decrypt, nonce.data(), nonce.size()));
                  TEST_FFI_OK(botan_cipher_update, (cipher_decrypt, BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                                                    decrypted.data(), decrypted.size(),   &output_written,
                                                    ciphertext.data(), ciphertext.size(), &input_consumed));

                  result.test_eq("AES/CBC plaintext", decrypted, plaintext);

                  TEST_FFI_OK(botan_cipher_destroy, (cipher_decrypt));
                  }
               }

            TEST_FFI_OK(botan_cipher_destroy, (cipher_encrypt));
            }

         return result;
         }

      Test::Result ffi_test_ciphers_aead()
         {
         Test::Result result("FFI AEAD");

#if defined(BOTAN_HAS_AEAD_GCM)

         botan_cipher_t cipher_encrypt, cipher_decrypt;

         if(TEST_FFI_OK(botan_cipher_init, (&cipher_encrypt, "AES-128/GCM", BOTAN_CIPHER_INIT_FLAG_ENCRYPT)))
            {
            size_t min_keylen = 0;
            size_t max_keylen = 0;
            size_t nonce_len = 0;
            size_t tag_len = 0;

            TEST_FFI_OK(botan_cipher_query_keylen, (cipher_encrypt, &min_keylen, &max_keylen));
            result.test_int_eq(min_keylen, 16, "Min key length");
            result.test_int_eq(max_keylen, 16, "Max key length");

            TEST_FFI_OK(botan_cipher_get_default_nonce_length, (cipher_encrypt, &nonce_len));
            result.test_int_eq(nonce_len, 12, "Expected default GCM nonce length");

            TEST_FFI_OK(botan_cipher_get_tag_length, (cipher_encrypt, &tag_len));
            result.test_int_eq(tag_len, 16, "Expected GCM tag length");

            TEST_FFI_RC(1, botan_cipher_valid_nonce_length, (cipher_encrypt, 12));
            // GCM accepts any nonce size...
            TEST_FFI_RC(1, botan_cipher_valid_nonce_length, (cipher_encrypt, 0));

            // NIST test vector
            const std::vector<uint8_t> plaintext =
               Botan::hex_decode("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39");

            const std::vector<uint8_t> symkey = Botan::hex_decode("FEFFE9928665731C6D6A8F9467308308");
            const std::vector<uint8_t> nonce = Botan::hex_decode("CAFEBABEFACEDBADDECAF888");
            const std::vector<uint8_t> exp_ciphertext = Botan::hex_decode(
                     "42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E0915BC94FBC3221A5DB94FAE95AE7121A47");
            const std::vector<uint8_t> aad = Botan::hex_decode("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2");

            std::vector<uint8_t> ciphertext(tag_len + plaintext.size());

            size_t output_written = 0;
            size_t input_consumed = 0;

            // Test that after clear or final the object can be reused
            for(size_t r = 0; r != 2; ++r)
               {
               TEST_FFI_OK(botan_cipher_set_key, (cipher_encrypt, symkey.data(), symkey.size()));
               TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, nonce.data(), nonce.size()));
               TEST_FFI_OK(botan_cipher_update, (cipher_encrypt, 0,
                                                 ciphertext.data(), ciphertext.size(), &output_written,
                                                 plaintext.data(), plaintext.size(), &input_consumed));
               TEST_FFI_OK(botan_cipher_clear, (cipher_encrypt));

               TEST_FFI_OK(botan_cipher_set_key, (cipher_encrypt, symkey.data(), symkey.size()));
               TEST_FFI_OK(botan_cipher_set_associated_data, (cipher_encrypt, aad.data(), aad.size()));
               TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, nonce.data(), nonce.size()));
               TEST_FFI_OK(botan_cipher_update, (cipher_encrypt, BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                                                 ciphertext.data(), ciphertext.size(), &output_written,
                                                 plaintext.data(), plaintext.size(), &input_consumed));

               ciphertext.resize(output_written);
               result.test_eq("AES/GCM ciphertext", ciphertext, exp_ciphertext);

               if(TEST_FFI_OK(botan_cipher_init, (&cipher_decrypt, "AES-128/GCM", BOTAN_CIPHER_INIT_FLAG_DECRYPT)))
                  {
                  std::vector<uint8_t> decrypted(plaintext.size());

                  TEST_FFI_OK(botan_cipher_set_key, (cipher_decrypt, symkey.data(), symkey.size()));
                  TEST_FFI_OK(botan_cipher_set_associated_data, (cipher_decrypt, aad.data(), aad.size()));
                  TEST_FFI_OK(botan_cipher_start, (cipher_decrypt, nonce.data(), nonce.size()));
                  TEST_FFI_OK(botan_cipher_update, (cipher_decrypt, BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                                                    decrypted.data(), decrypted.size(), &output_written,
                                                    ciphertext.data(), ciphertext.size(), &input_consumed));

                  result.test_int_eq(input_consumed, ciphertext.size(), "All input consumed");
                  result.test_int_eq(output_written, decrypted.size(), "Expected output size produced");
                  result.test_eq("AES/GCM plaintext", decrypted, plaintext);

                  TEST_FFI_OK(botan_cipher_destroy, (cipher_decrypt));
                  }
               }

            TEST_FFI_OK(botan_cipher_destroy, (cipher_encrypt));
            }
#endif

         return result;
         }

      Test::Result ffi_test_stream_ciphers()
         {
         Test::Result result("FFI stream ciphers");

#if defined(BOTAN_HAS_CTR_BE)

         const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");
         const std::vector<uint8_t> nonce = Botan::hex_decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF");
         const std::vector<uint8_t> pt = Botan::hex_decode(
                                            "AE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710");
         const std::vector<uint8_t> exp_ct = Botan::hex_decode(
                                                "9806F66B7970FDFF8617187BB9FFFDFF5AE4DF3EDBD5D35E5B4F09020DB03EAB1E031DDA2FBE03D1792170A0F3009CEE");

         botan_cipher_t ctr;

         std::vector<uint8_t> ct(pt.size());

         if(TEST_FFI_OK(botan_cipher_init, (&ctr, "AES-128/CTR-BE", BOTAN_CIPHER_INIT_FLAG_ENCRYPT)))
            {
            size_t input_consumed = 0;
            size_t output_written = 0;

            TEST_FFI_OK(botan_cipher_set_key, (ctr, key.data(), key.size()));
            TEST_FFI_OK(botan_cipher_start, (ctr, nonce.data(), nonce.size()));

            // Test partial updates...
            TEST_FFI_OK(botan_cipher_update, (ctr, 0,
                                              ct.data(), ct.size(), &output_written,
                                              pt.data(), 5, &input_consumed));

            result.test_int_eq(output_written, 5, "Expected output written");
            result.test_int_eq(input_consumed, 5, "Expected input consumed");

            TEST_FFI_OK(botan_cipher_update, (ctr, 0,
                                              &ct[5], ct.size() - 5, &output_written,
                                              &pt[5], pt.size() - 5, &input_consumed));

            result.test_int_eq(output_written, ct.size() - 5, "Expected output written");
            result.test_int_eq(input_consumed, pt.size() - 5, "Expected input consumed");
            result.test_eq("AES-128/CTR ciphertext", ct, exp_ct);

            TEST_FFI_OK(botan_cipher_destroy, (ctr));
            }

#endif

         return result;
         }

      Test::Result ffi_test_block_ciphers()
         {
         Test::Result result("FFI block ciphers");

         botan_block_cipher_t cipher;

         if(TEST_FFI_OK(botan_block_cipher_init, (&cipher, "AES-128")))
            {
            const std::vector<uint8_t> zero16(16, 0);
            std::vector<uint8_t> block(16, 0);

            TEST_FFI_OK(botan_block_cipher_clear, (cipher));

            TEST_FFI_RC(16, botan_block_cipher_block_size, (cipher));

            TEST_FFI_OK(botan_block_cipher_set_key, (cipher, zero16.data(), zero16.size()));

            TEST_FFI_OK(botan_block_cipher_encrypt_blocks, (cipher, block.data(), block.data(), 1));
            result.test_eq("AES-128 encryption works", block, "66E94BD4EF8A2C3B884CFA59CA342B2E");

            TEST_FFI_OK(botan_block_cipher_encrypt_blocks, (cipher, block.data(), block.data(), 1));
            result.test_eq("AES-128 encryption works", block, "F795BD4A52E29ED713D313FA20E98DBC");

            TEST_FFI_OK(botan_block_cipher_decrypt_blocks, (cipher, block.data(), block.data(), 1));
            result.test_eq("AES-128 decryption works", block, "66E94BD4EF8A2C3B884CFA59CA342B2E");

            TEST_FFI_OK(botan_block_cipher_decrypt_blocks, (cipher, block.data(), block.data(), 1));
            result.test_eq("AES-128 decryption works", block, "00000000000000000000000000000000");

            TEST_FFI_OK(botan_block_cipher_clear, (cipher));
            botan_block_cipher_destroy(cipher);
            }

         return result;
         }

      Test::Result ffi_test_mp(botan_rng_t rng)
         {
         Test::Result result("FFI MP");

         botan_mp_t x;
         botan_mp_init(&x);
         TEST_FFI_RC(0, botan_mp_is_odd, (x));
         TEST_FFI_RC(1, botan_mp_is_even, (x));
         TEST_FFI_RC(0, botan_mp_is_negative, (x));
         TEST_FFI_RC(1, botan_mp_is_positive, (x));
         TEST_FFI_RC(1, botan_mp_is_zero, (x));
         botan_mp_destroy(x);

         botan_mp_init(&x);
         size_t bn_bytes = 0;
         TEST_FFI_OK(botan_mp_num_bytes, (x, &bn_bytes));
         result.test_eq("Expected size for MP 0", bn_bytes, 0);

         botan_mp_set_from_int(x, 5);
         TEST_FFI_OK(botan_mp_num_bytes, (x, &bn_bytes));
         result.test_eq("Expected size for MP 5", bn_bytes, 1);

         botan_mp_set_from_int(x, 259);
         TEST_FFI_OK(botan_mp_num_bytes, (x, &bn_bytes));
         result.test_eq("Expected size for MP 259", bn_bytes, 2);

         TEST_FFI_RC(1, botan_mp_is_odd, (x));
         TEST_FFI_RC(0, botan_mp_is_even, (x));
         TEST_FFI_RC(0, botan_mp_is_negative, (x));
         TEST_FFI_RC(1, botan_mp_is_positive, (x));
         TEST_FFI_RC(0, botan_mp_is_zero, (x));


            {
            botan_mp_t zero;
            botan_mp_init(&zero);
            int cmp;
            TEST_FFI_OK(botan_mp_cmp, (&cmp, x, zero));
            result.confirm("bigint_mp_cmp(+, 0)", cmp == 1);

            TEST_FFI_OK(botan_mp_cmp, (&cmp, zero, x));
            result.confirm("bigint_mp_cmp(0, +)", cmp == -1);

            TEST_FFI_RC(0, botan_mp_is_negative, (x));
            TEST_FFI_RC(1, botan_mp_is_positive, (x));
            TEST_FFI_OK(botan_mp_flip_sign, (x));
            TEST_FFI_RC(1, botan_mp_is_negative, (x));
            TEST_FFI_RC(0, botan_mp_is_positive, (x));

            // test no negative zero
            TEST_FFI_RC(0, botan_mp_is_negative, (zero));
            TEST_FFI_RC(1, botan_mp_is_positive, (zero));
            TEST_FFI_OK(botan_mp_flip_sign, (zero));
            TEST_FFI_RC(0, botan_mp_is_negative, (zero));
            TEST_FFI_RC(1, botan_mp_is_positive, (zero));

            TEST_FFI_OK(botan_mp_cmp, (&cmp, x, zero));
            result.confirm("bigint_mp_cmp(-, 0)", cmp == -1);

            TEST_FFI_OK(botan_mp_cmp, (&cmp, zero, x));
            result.confirm("bigint_mp_cmp(0, -)", cmp == 1);

            TEST_FFI_OK(botan_mp_cmp, (&cmp, zero, zero));
            result.confirm("bigint_mp_cmp(0, 0)", cmp == 0);

            TEST_FFI_OK(botan_mp_cmp, (&cmp, x, x));
            result.confirm("bigint_mp_cmp(x, x)", cmp == 0);

            TEST_FFI_OK(botan_mp_flip_sign, (x));

            botan_mp_destroy(zero);
            }

         size_t x_bits = 0;
         TEST_FFI_OK(botan_mp_num_bits, (x, &x_bits));
         result.test_eq("botan_mp_num_bits", x_bits, 9);

         char str_buf[1024] = { 0 };
         size_t str_len = 0;

         TEST_FFI_OK(botan_mp_to_hex, (x, str_buf));
         result.test_eq("botan_mp_to_hex", std::string(str_buf), "0103");

         uint32_t x_32;
         TEST_FFI_OK(botan_mp_to_uint32, (x, &x_32));
         result.test_eq("botan_mp_to_uint32", x, 0x103);

         TEST_FFI_RC(1, botan_mp_get_bit, (x, 1));
         TEST_FFI_RC(0, botan_mp_get_bit, (x, 87));
         TEST_FFI_OK(botan_mp_set_bit, (x, 87));
         TEST_FFI_RC(1, botan_mp_get_bit, (x, 87));
         TEST_FFI_OK(botan_mp_to_hex, (x, str_buf));
         result.test_eq("botan_mp_set_bit", std::string(str_buf), "8000000000000000000103");

         TEST_FFI_OK(botan_mp_clear_bit, (x, 87));
         TEST_FFI_OK(botan_mp_to_hex, (x, str_buf));
         result.test_eq("botan_mp_set_bit", std::string(str_buf), "0103");

         botan_mp_t y;
         TEST_FFI_OK(botan_mp_init, (&y));
         TEST_FFI_OK(botan_mp_set_from_int, (y, 0x1234567));

         botan_mp_t r;
         botan_mp_init(&r);

         TEST_FFI_OK(botan_mp_add, (r, x, y));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_add", std::string(str_buf), "19089002");

         TEST_FFI_OK(botan_mp_mul, (r, x, y));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_mul", std::string(str_buf), "4943984437");
         TEST_FFI_RC(0, botan_mp_is_negative, (r));

         botan_mp_t q;
         botan_mp_init(&q);
         TEST_FFI_OK(botan_mp_div, (q, r, y, x));

         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (q, 10, str_buf, &str_len));
         result.test_eq("botan_mp_div_q", std::string(str_buf), "073701");

         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_div_r", std::string(str_buf), "184");

         TEST_FFI_OK(botan_mp_set_from_str, (y, "4943984437"));
         TEST_FFI_OK(botan_mp_sub, (r, x, y));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_sub", std::string(str_buf), "4943984178");
         TEST_FFI_RC(1, botan_mp_is_negative, (r));

         TEST_FFI_OK(botan_mp_lshift, (r, x, 39));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_lshift", std::string(str_buf), "142386755796992");

         TEST_FFI_OK(botan_mp_rshift, (r, r, 3));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_rshift", std::string(str_buf), "17798344474624");

         TEST_FFI_OK(botan_mp_gcd, (r, x, y));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_gcd", std::string(str_buf), "259");

         botan_mp_t p;
         botan_mp_init(&p);
         const uint8_t M127[] = { 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
         TEST_FFI_OK(botan_mp_from_bin, (p, M127, sizeof(M127)));
         TEST_FFI_RC(1, botan_mp_is_prime, (p, rng, 64));

         size_t p_bits = 0;
         TEST_FFI_OK(botan_mp_num_bits, (p, &p_bits));
         result.test_eq("botan_mp_num_bits", p_bits, 127);

         TEST_FFI_OK(botan_mp_mod_inverse, (r, x, p));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_mod_inverse", std::string(str_buf), "40728777507911553541948312086427855425");

         TEST_FFI_OK(botan_mp_powmod, (r, x, r, p));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_powmod", std::string(str_buf), "40550417419160441638948180641668117560");

         TEST_FFI_OK(botan_mp_num_bytes, (r, &bn_bytes));
         result.test_eq("botan_mp_num_bytes", bn_bytes, 16);

         std::vector<uint8_t> bn_buf;
         bn_buf.resize(bn_bytes);
         botan_mp_to_bin(r, bn_buf.data());
         result.test_eq("botan_mp_to_bin", bn_buf, "1E81B9EFE0BE1902F6D03F9F5E5FB438");

         TEST_FFI_OK(botan_mp_set_from_mp, (y, r));
         TEST_FFI_OK(botan_mp_mod_mul, (r, x, y, p));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_mod_mul", std::string(str_buf), "123945920473931248854653259523111998693");

         str_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_mp_to_str, (r, 10, str_buf, &str_len));

         size_t x_bytes;
         botan_mp_rand_bits(x, rng, 512);
         TEST_FFI_OK(botan_mp_num_bytes, (x, &x_bytes));
         result.test_lte("botan_mp_num_bytes", x_bytes, 512 / 8);

         TEST_FFI_OK(botan_mp_set_from_radix_str, (x, "909A", 16));
         TEST_FFI_OK(botan_mp_to_uint32, (x, &x_32));
         result.test_eq("botan_mp_set_from_radix_str(16)", x_32, static_cast<size_t>(0x909A));

         TEST_FFI_OK(botan_mp_set_from_radix_str, (x, "9098135", 10));
         TEST_FFI_OK(botan_mp_to_uint32, (x, &x_32));
         result.test_eq("botan_mp_set_from_radix_str(10)", x_32, static_cast<size_t>(9098135));

         botan_mp_destroy(p);
         botan_mp_destroy(x);
         botan_mp_destroy(y);
         botan_mp_destroy(r);
         botan_mp_destroy(q);

         return result;
         }

      void ffi_test_pubkey_export(Test::Result& result, botan_pubkey_t pub, botan_privkey_t priv, botan_rng_t rng)
         {
         const size_t pbkdf_iter = 1000;

         // export public key
         size_t pubkey_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_pubkey_export, (pub, nullptr, &pubkey_len,
                     BOTAN_PRIVKEY_EXPORT_FLAG_DER));

         std::vector<uint8_t> pubkey(pubkey_len);
         TEST_FFI_OK(botan_pubkey_export, (pub, pubkey.data(), &pubkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_DER));

         pubkey_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_pubkey_export,
                     (pub, nullptr, &pubkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

         pubkey.resize(pubkey_len);
         TEST_FFI_OK(botan_pubkey_export, (pub, pubkey.data(), &pubkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

         // reimport exported public key
         botan_pubkey_t pub_copy;
         TEST_FFI_OK(botan_pubkey_load, (&pub_copy, pubkey.data(), pubkey_len));
         TEST_FFI_OK(botan_pubkey_check_key, (pub_copy, rng, 0));

         // export private key
         std::vector<uint8_t> privkey;
         size_t privkey_len = 0;

         // call with nullptr to query the length
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_privkey_export,
                     (priv, nullptr, &privkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_DER));

         privkey.resize(privkey_len);
         privkey_len = privkey.size(); // set buffer size

         TEST_FFI_OK(botan_privkey_export, (priv, privkey.data(), &privkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_DER));

         privkey.resize(privkey_len);

         result.test_lt("Reasonable size", 64, privkey.size());

         // Now again for PEM
         privkey_len = 0;

         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_privkey_export,
                     (priv, nullptr, &privkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

         privkey.resize(privkey_len);
         TEST_FFI_OK(botan_privkey_export, (priv, privkey.data(), &privkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

         // export private key encrypted
         privkey_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_privkey_export_encrypted_pbkdf_iter, (priv, nullptr,
                     &privkey_len, rng, "password", pbkdf_iter, "", "", BOTAN_PRIVKEY_EXPORT_FLAG_DER));

         privkey.resize(privkey_len);
         privkey_len = privkey.size();

         TEST_FFI_OK(botan_privkey_export_encrypted_pbkdf_iter, (priv, privkey.data(), &privkey_len, rng, "password", pbkdf_iter,
                     "", "", BOTAN_PRIVKEY_EXPORT_FLAG_DER));

         privkey_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_privkey_export_encrypted_pbkdf_iter, (priv, nullptr,
                     &privkey_len, rng, "password", pbkdf_iter, "", "", BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

         privkey.resize(privkey_len);
         TEST_FFI_OK(botan_privkey_export_encrypted_pbkdf_iter, (priv, privkey.data(), &privkey_len, rng, "password", pbkdf_iter,
                     "", "", BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

         // calculate fingerprint
         size_t strength = 0;
         TEST_FFI_OK(botan_pubkey_estimated_strength, (pub, &strength));
         result.test_gte("estimated strength", strength, 1);

         size_t fingerprint_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_pubkey_fingerprint,
                     (pub, "SHA-512", nullptr, &fingerprint_len));

         std::vector<uint8_t> fingerprint(fingerprint_len);
         TEST_FFI_OK(botan_pubkey_fingerprint, (pub, "SHA-512", fingerprint.data(), &fingerprint_len));
         }

      Test::Result ffi_test_rsa(botan_rng_t rng)
         {
         Test::Result result("FFI RSA");

         botan_privkey_t priv;

         if(TEST_FFI_OK(botan_privkey_create_rsa, (&priv, rng, 1024)))
            {
            TEST_FFI_OK(botan_privkey_check_key, (priv, rng, 0));

            botan_pubkey_t pub;
            TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));
            TEST_FFI_OK(botan_pubkey_check_key, (pub, rng, 0));

            ffi_test_pubkey_export(result, pub, priv, rng);

            botan_mp_t p, q, d, n, e;
            botan_mp_init(&p);
            botan_mp_init(&q);
            botan_mp_init(&d);
            botan_mp_init(&n);
            botan_mp_init(&e);

            TEST_FFI_OK(botan_privkey_rsa_get_p, (p, priv));
            TEST_FFI_OK(botan_privkey_rsa_get_q, (q, priv));
            TEST_FFI_OK(botan_privkey_rsa_get_d, (d, priv));
            TEST_FFI_OK(botan_privkey_rsa_get_e, (e, priv));
            TEST_FFI_OK(botan_privkey_rsa_get_n, (n, priv));

            // Confirm same (e,n) values in public key
               {
               botan_mp_t pub_e, pub_n;
               botan_mp_init(&pub_e);
               botan_mp_init(&pub_n);
               TEST_FFI_OK(botan_pubkey_rsa_get_e, (pub_e, pub));
               TEST_FFI_OK(botan_pubkey_rsa_get_n, (pub_n, pub));

               TEST_FFI_RC(1, botan_mp_equal, (pub_e, e));
               TEST_FFI_RC(1, botan_mp_equal, (pub_n, n));
               botan_mp_destroy(pub_e);
               botan_mp_destroy(pub_n);
               }

            TEST_FFI_RC(1, botan_mp_is_prime, (p, rng, 64));
            TEST_FFI_RC(1, botan_mp_is_prime, (q, rng, 64));

            // Test p != q
            TEST_FFI_RC(0, botan_mp_equal, (p, q));

            // Test p * q == n
            botan_mp_t x;
            botan_mp_init(&x);
            TEST_FFI_OK(botan_mp_mul, (x, p, q));

            TEST_FFI_RC(1, botan_mp_equal, (x, n));
            botan_mp_destroy(x);

            botan_privkey_t loaded_privkey;
            // First try loading a bogus key and verify check_key fails
            TEST_FFI_OK(botan_privkey_load_rsa, (&loaded_privkey, n, d, q));
            TEST_FFI_RC(-1, botan_privkey_check_key, (loaded_privkey, rng, 0));
            botan_privkey_destroy(loaded_privkey);

            TEST_FFI_OK(botan_privkey_load_rsa, (&loaded_privkey, p, q, e));
            TEST_FFI_OK(botan_privkey_check_key, (loaded_privkey, rng, 0));

            botan_pubkey_t loaded_pubkey;
            TEST_FFI_OK(botan_pubkey_load_rsa, (&loaded_pubkey, n, e));
            TEST_FFI_OK(botan_pubkey_check_key, (loaded_pubkey, rng, 0));

            botan_mp_destroy(p);
            botan_mp_destroy(q);
            botan_mp_destroy(d);
            botan_mp_destroy(e);
            botan_mp_destroy(n);

            char namebuf[32] = { 0 };
            size_t name_len = sizeof(namebuf);
            if(TEST_FFI_OK(botan_pubkey_algo_name, (loaded_pubkey, namebuf, &name_len)))
               {
               result.test_eq("algo name", std::string(namebuf), "RSA");
               }

            botan_pk_op_encrypt_t encrypt;

            if(TEST_FFI_OK(botan_pk_op_encrypt_create, (&encrypt, loaded_pubkey, "OAEP(SHA-256)", 0)))
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

            TEST_FFI_OK(botan_pubkey_destroy, (loaded_pubkey));
            TEST_FFI_OK(botan_pubkey_destroy, (pub));
            TEST_FFI_OK(botan_privkey_destroy, (loaded_privkey));
            TEST_FFI_OK(botan_privkey_destroy, (priv));
            }

         return result;
         }

      Test::Result ffi_test_dsa(botan_rng_t rng)
         {
         Test::Result result("FFI DSA");

         botan_privkey_t priv;

         if(TEST_FFI_OK(botan_privkey_create, (&priv, "DSA", "dsa/jce/1024", rng)))
            {
            TEST_FFI_OK(botan_privkey_check_key, (priv, rng, 0));

            botan_pubkey_t pub;
            TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));
            TEST_FFI_OK(botan_pubkey_check_key, (pub, rng, 0));

            ffi_test_pubkey_export(result, pub, priv, rng);

            botan_mp_t p, q, g, x, y;
            botan_mp_init(&p);
            botan_mp_init(&q);
            botan_mp_init(&g);
            botan_mp_init(&x);
            botan_mp_init(&y);

            TEST_FFI_OK(botan_privkey_dsa_get_x, (x, priv));
            TEST_FFI_OK(botan_pubkey_dsa_get_g, (g, pub));
            TEST_FFI_OK(botan_pubkey_dsa_get_p, (p, pub));
            TEST_FFI_OK(botan_pubkey_dsa_get_q, (q, pub));
            TEST_FFI_OK(botan_pubkey_dsa_get_y, (y, pub));

            botan_mp_t cmp;
            botan_mp_init(&cmp);
            TEST_FFI_OK(botan_privkey_get_field, (cmp, priv, "x"));
            TEST_FFI_RC(1, botan_mp_equal, (cmp, x));
            TEST_FFI_OK(botan_privkey_get_field, (cmp, priv, "y"));
            TEST_FFI_RC(1, botan_mp_equal, (cmp, y));
            TEST_FFI_OK(botan_privkey_get_field, (cmp, priv, "p"));
            TEST_FFI_RC(1, botan_mp_equal, (cmp, p));
            botan_mp_destroy(cmp);

            botan_privkey_t loaded_privkey;
            TEST_FFI_OK(botan_privkey_load_dsa, (&loaded_privkey, p, q, g, x));
            TEST_FFI_OK(botan_privkey_check_key, (loaded_privkey, rng, 0));

            botan_pubkey_t loaded_pubkey;
            TEST_FFI_OK(botan_pubkey_load_dsa, (&loaded_pubkey, p, q, g, y));
            TEST_FFI_OK(botan_pubkey_check_key, (loaded_pubkey, rng, 0));

            botan_mp_destroy(p);
            botan_mp_destroy(q);
            botan_mp_destroy(g);
            botan_mp_destroy(y);
            botan_mp_destroy(x);

            botan_pk_op_sign_t signer;

            std::vector<uint8_t> message(6, 6);
            std::vector<uint8_t> signature(20 * 2);

            if(TEST_FFI_OK(botan_pk_op_sign_create, (&signer, loaded_privkey, "EMSA1(SHA-256)", 0)))
               {
               // TODO: break input into multiple calls to update
               TEST_FFI_OK(botan_pk_op_sign_update, (signer, message.data(), message.size()));

               signature.resize(20 * 2); // TODO: no way to derive this from API
               size_t sig_len = signature.size();
               TEST_FFI_OK(botan_pk_op_sign_finish, (signer, rng, signature.data(), &sig_len));
               signature.resize(sig_len);

               TEST_FFI_OK(botan_pk_op_sign_destroy, (signer));
               }

            botan_pk_op_verify_t verifier;

            if(TEST_FFI_OK(botan_pk_op_verify_create, (&verifier, pub, "EMSA1(SHA-256)", 0)))
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

            TEST_FFI_OK(botan_pubkey_destroy, (loaded_pubkey));
            TEST_FFI_OK(botan_pubkey_destroy, (pub));
            TEST_FFI_OK(botan_privkey_destroy, (loaded_privkey));
            TEST_FFI_OK(botan_privkey_destroy, (priv));
            }

         return result;
         }
      Test::Result ffi_test_ecdsa(botan_rng_t rng)
         {
         Test::Result result("FFI ECDSA");
         static const char* kCurve = "secp384r1";
         botan_privkey_t priv;
         botan_pubkey_t pub;
         botan_privkey_t loaded_privkey;
         botan_pubkey_t loaded_pubkey;

         REQUIRE_FFI_OK(botan_privkey_create_ecdsa, (&priv, rng, kCurve));
         TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));
         ffi_test_pubkey_export(result, pub, priv, rng);

         // Check key load functions
         botan_mp_t private_scalar, public_x, public_y;
         botan_mp_init(&private_scalar);
         botan_mp_init(&public_x);
         botan_mp_init(&public_y);

         TEST_FFI_OK(botan_privkey_get_field, (private_scalar, priv, "x"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_x, pub, "public_x"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_y, pub, "public_y"));
         TEST_FFI_OK(botan_privkey_load_ecdsa, (&loaded_privkey, private_scalar, kCurve));
         TEST_FFI_OK(botan_pubkey_load_ecdsa, (&loaded_pubkey, public_x, public_y, kCurve));
         TEST_FFI_OK(botan_privkey_check_key, (loaded_privkey, rng, 0));
         TEST_FFI_OK(botan_pubkey_check_key, (loaded_pubkey, rng, 0));

         char namebuf[32] = { 0 };
         size_t name_len = sizeof(namebuf);

         TEST_FFI_OK(botan_pubkey_algo_name, (pub, &namebuf[0], &name_len));
         result.test_eq(namebuf, namebuf, "ECDSA");

         std::vector<uint8_t> message(1280), signature;
         TEST_FFI_OK(botan_rng_get, (rng, message.data(), message.size()));
         botan_pk_op_sign_t signer;
         if(TEST_FFI_OK(botan_pk_op_sign_create, (&signer, loaded_privkey, "EMSA1(SHA-384)", 0)))
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

         TEST_FFI_OK(botan_mp_destroy, (private_scalar));
         TEST_FFI_OK(botan_mp_destroy, (public_x));
         TEST_FFI_OK(botan_mp_destroy, (public_y));
         TEST_FFI_OK(botan_pubkey_destroy, (pub));
         TEST_FFI_OK(botan_privkey_destroy, (priv));
         TEST_FFI_OK(botan_privkey_destroy, (loaded_privkey));
         TEST_FFI_OK(botan_pubkey_destroy, (loaded_pubkey));

         return result;
         }

      Test::Result ffi_test_sm2(botan_rng_t rng)
         {
         Test::Result result("FFI SM2");
         static const char* kCurve = "sm2p256v1";
         const std::string sm2_ident = "SM2 Ident Field";
         botan_privkey_t priv;
         botan_pubkey_t pub;
         botan_privkey_t loaded_privkey;
         botan_pubkey_t loaded_pubkey;

         REQUIRE_FFI_OK(botan_privkey_create, (&priv, "SM2_Sig", kCurve, rng));
         TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));
         ffi_test_pubkey_export(result, pub, priv, rng);

         // Check key load functions
         botan_mp_t private_scalar, public_x, public_y;
         botan_mp_init(&private_scalar);
         botan_mp_init(&public_x);
         botan_mp_init(&public_y);

         TEST_FFI_OK(botan_privkey_get_field, (private_scalar, priv, "x"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_x, pub, "public_x"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_y, pub, "public_y"));
         TEST_FFI_OK(botan_privkey_load_sm2, (&loaded_privkey, private_scalar, kCurve));
         TEST_FFI_OK(botan_pubkey_load_sm2, (&loaded_pubkey, public_x, public_y, kCurve));
         TEST_FFI_OK(botan_privkey_check_key, (loaded_privkey, rng, 0));
         TEST_FFI_OK(botan_pubkey_check_key, (loaded_pubkey, rng, 0));

         char namebuf[32] = { 0 };
         size_t name_len = sizeof(namebuf);

         TEST_FFI_OK(botan_pubkey_algo_name, (pub, &namebuf[0], &name_len));
         result.test_eq(namebuf, namebuf, "SM2_Sig");

         std::vector<uint8_t> message(1280), signature;
         TEST_FFI_OK(botan_rng_get, (rng, message.data(), message.size()));
         botan_pk_op_sign_t signer;
         if(TEST_FFI_OK(botan_pk_op_sign_create, (&signer, loaded_privkey, sm2_ident.c_str(), 0)))
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

         if(signature.size() > 0 && TEST_FFI_OK(botan_pk_op_verify_create, (&verifier, pub, sm2_ident.c_str(), 0)))
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

         TEST_FFI_OK(botan_mp_destroy, (private_scalar));
         TEST_FFI_OK(botan_mp_destroy, (public_x));
         TEST_FFI_OK(botan_mp_destroy, (public_y));
         TEST_FFI_OK(botan_pubkey_destroy, (pub));
         TEST_FFI_OK(botan_privkey_destroy, (priv));
         TEST_FFI_OK(botan_privkey_destroy, (loaded_privkey));
         TEST_FFI_OK(botan_pubkey_destroy, (loaded_pubkey));

         return result;
         }

      Test::Result ffi_test_ecdh(botan_rng_t rng)
         {
         Test::Result result("FFI ECDH");

         botan_mp_t private_scalar, public_x, public_y;
         botan_privkey_t loaded_privkey1;
         botan_pubkey_t loaded_pubkey1;
         botan_mp_init(&private_scalar);
         botan_mp_init(&public_x);
         botan_mp_init(&public_y);

         botan_privkey_t priv1;
         REQUIRE_FFI_OK(botan_privkey_create_ecdh, (&priv1, rng, "secp256r1"));

         botan_privkey_t priv2;
         REQUIRE_FFI_OK(botan_privkey_create_ecdh, (&priv2, rng, "secp256r1"));

         botan_pubkey_t pub1;
         REQUIRE_FFI_OK(botan_privkey_export_pubkey, (&pub1, priv1));

         botan_pubkey_t pub2;
         REQUIRE_FFI_OK(botan_privkey_export_pubkey, (&pub2, priv2));

         /* Reload key-pair1 in order to test functions for key loading */
         TEST_FFI_OK(botan_privkey_get_field, (private_scalar, priv1, "x"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_x, pub1, "public_x"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_y, pub1, "public_y"));
         TEST_FFI_OK(botan_privkey_load_ecdh, (&loaded_privkey1, private_scalar, "secp256r1"));
         TEST_FFI_OK(botan_pubkey_load_ecdh, (&loaded_pubkey1, public_x, public_y, "secp256r1"));
         TEST_FFI_OK(botan_privkey_check_key, (loaded_privkey1, rng, 0));
         TEST_FFI_OK(botan_pubkey_check_key, (loaded_pubkey1, rng, 0));

         ffi_test_pubkey_export(result, loaded_pubkey1, priv1, rng);
         ffi_test_pubkey_export(result, pub2, priv2, rng);

         botan_pk_op_ka_t ka1;
         REQUIRE_FFI_OK(botan_pk_op_key_agreement_create, (&ka1, loaded_privkey1, "KDF2(SHA-256)", 0));
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

         TEST_FFI_OK(botan_mp_destroy, (private_scalar));
         TEST_FFI_OK(botan_mp_destroy, (public_x));
         TEST_FFI_OK(botan_mp_destroy, (public_y));
         TEST_FFI_OK(botan_pk_op_key_agreement_destroy, (ka1));
         TEST_FFI_OK(botan_pk_op_key_agreement_destroy, (ka2));
         TEST_FFI_OK(botan_privkey_destroy, (priv1));
         TEST_FFI_OK(botan_privkey_destroy, (priv2));
         TEST_FFI_OK(botan_pubkey_destroy, (pub1));
         TEST_FFI_OK(botan_pubkey_destroy, (pub2));
         TEST_FFI_OK(botan_privkey_destroy, (loaded_privkey1));
         TEST_FFI_OK(botan_pubkey_destroy, (loaded_pubkey1));
         return result;
         }

      Test::Result ffi_test_mceliece(botan_rng_t rng)
         {
         Test::Result result("FFI McEliece");

         botan_privkey_t priv;
#if defined(BOTAN_HAS_MCELIECE)
         if(TEST_FFI_OK(botan_privkey_create_mceliece, (&priv, rng, 2048, 50)))
            {
            botan_pubkey_t pub;
            TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));

            ffi_test_pubkey_export(result, pub, priv, rng);

            char namebuf[32] = { 0 };
            size_t name_len = sizeof(namebuf);
            if(TEST_FFI_OK(botan_pubkey_algo_name, (pub, namebuf, &name_len)))
               {
               result.test_eq("algo name", std::string(namebuf), "McEliece");
               }

            const uint64_t zero_seq = 0;
            uint8_t ad[8];
            Botan::store_be(zero_seq, ad);
            const size_t ad_len = sizeof(ad);

            const Botan::secure_vector<uint8_t> plaintext = Test::rng().random_vec(Test::rng().next_byte());
            size_t plaintext_len = plaintext.size();
            size_t ciphertext_len = 0;

            // first calculate ciphertext length
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_mceies_encrypt, (pub, rng, "AES-256/OCB", plaintext.data(),
                        plaintext.size(), ad, ad_len, nullptr, &ciphertext_len));
            std::vector<uint8_t> ciphertext(ciphertext_len);

            // now encrypt
            if(TEST_FFI_OK(botan_mceies_encrypt, (pub, rng, "AES-256/OCB", plaintext.data(), plaintext.size(), ad, ad_len,
                                                  ciphertext.data(), &ciphertext_len)))
               {
               std::vector<uint8_t> decrypted(plaintext.size());
               size_t decrypted_len = plaintext_len;

               TEST_FFI_OK(botan_mceies_decrypt, (priv, "AES-256/OCB", ciphertext.data(), ciphertext.size(), ad, ad_len,
                                                  decrypted.data(), &decrypted_len));

               result.test_eq("MCIES plaintext", decrypted, plaintext);
               }

            TEST_FFI_OK(botan_pubkey_destroy, (pub));
            TEST_FFI_OK(botan_privkey_destroy, (priv));
            }
#else
         // Not included, test that calling the FFI function work (and returns an error)
         TEST_FFI_RC(BOTAN_FFI_ERROR_NOT_IMPLEMENTED, botan_privkey_create_mceliece, (&priv, rng, 2048, 50));
#endif

         return result;
         }

      Test::Result ffi_test_ed25519(botan_rng_t rng)
         {
         Test::Result result("FFI Ed25519");

         botan_pubkey_t pub;
         botan_privkey_t priv;

         // From draft-koch-eddsa-for-openpgp-04
         const std::vector<uint8_t> seed = Botan::hex_decode(
            "1a8b1ff05ded48e18bf50166c664ab023ea70003d78d9e41f5758a91d850f8d2");
         const std::vector<uint8_t> pubkey = Botan::hex_decode(
            "3f098994bdd916ed4053197934e4a87c80733a1280d62f8010992e43ee3b2406");
         const std::vector<uint8_t> message = Botan::hex_decode(
            "4f70656e504750040016080006050255f95f9504ff0000000c");
         const std::vector<uint8_t> exp_sig = Botan::hex_decode(
            "56f90cca98e2102637bd983fdb16c131dfd27ed82bf4dde5606e0d756aed3366"
            "d09c4fa11527f038e0f57f2201d82f2ea2c9033265fa6ceb489e854bae61b404");

         TEST_FFI_OK(botan_privkey_load_ed25519, (&priv, seed.data()));

         uint8_t retr_privkey[64];
         TEST_FFI_OK(botan_privkey_ed25519_get_privkey, (priv, retr_privkey));

         result.test_eq(nullptr, "Public key matches", retr_privkey + 32, 32,
                        pubkey.data(), pubkey.size());

         TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));

         uint8_t retr_pubkey[32];
         TEST_FFI_OK(botan_pubkey_ed25519_get_pubkey, (pub, retr_pubkey));
         result.test_eq(nullptr, "Public key matches", retr_pubkey, 32,
                        pubkey.data(), pubkey.size());

         //TEST_FFI_OK(botan_pubkey_load_ed25519, (&pub, pubkey.data()));

         botan_pk_op_sign_t signer;
         std::vector<uint8_t> signature;

         if(TEST_FFI_OK(botan_pk_op_sign_create, (&signer, priv, "SHA-256", 0)))
            {
            TEST_FFI_OK(botan_pk_op_sign_update, (signer, message.data(), message.size()));

            signature.resize(128);
            size_t sig_len = signature.size();
            TEST_FFI_OK(botan_pk_op_sign_finish, (signer, rng, signature.data(), &sig_len));
            signature.resize(sig_len);

            TEST_FFI_OK(botan_pk_op_sign_destroy, (signer));
            }

         result.test_eq("Expected signature", signature, exp_sig);

         botan_pk_op_verify_t verifier;

         if(TEST_FFI_OK(botan_pk_op_verify_create, (&verifier, pub, "SHA-256", 0)))
            {
            TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
            TEST_FFI_OK(botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));
            }


         return result;
         }

      Test::Result ffi_test_elgamal(botan_rng_t rng)
         {
         Test::Result result("FFI ELGAMAL");

         botan_privkey_t priv;

         if(TEST_FFI_OK(botan_privkey_create, (&priv, "ElGamal", nullptr, rng)))
            {
            TEST_FFI_OK(botan_privkey_check_key, (priv, rng, 0));

            botan_pubkey_t pub;
            TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));
            TEST_FFI_OK(botan_pubkey_check_key, (pub, rng, 0));

            ffi_test_pubkey_export(result, pub, priv, rng);
            botan_mp_t p, g, x, y;
            botan_mp_init(&p);
            botan_mp_init(&g);
            botan_mp_init(&x);
            botan_mp_init(&y);

            TEST_FFI_OK(botan_pubkey_get_field, (p, pub, "p"));
            TEST_FFI_OK(botan_pubkey_get_field, (g, pub, "g"));
            TEST_FFI_OK(botan_pubkey_get_field, (y, pub, "y"));
            TEST_FFI_OK(botan_privkey_get_field, (x, priv, "x"));

            size_t p_len = 0;
            TEST_FFI_OK(botan_mp_num_bytes, (p, &p_len));

            botan_privkey_t loaded_privkey;
            TEST_FFI_OK(botan_privkey_load_elgamal, (&loaded_privkey, p, g, x));
            TEST_FFI_OK(botan_privkey_check_key, (loaded_privkey, rng, 0));

            botan_pubkey_t loaded_pubkey;
            TEST_FFI_OK(botan_pubkey_load_elgamal, (&loaded_pubkey, p, g, y));
            TEST_FFI_OK(botan_pubkey_check_key, (loaded_pubkey, rng, 0));

            botan_mp_destroy(p);
            botan_mp_destroy(g);
            botan_mp_destroy(y);
            botan_mp_destroy(x);


            std::vector<uint8_t> plaintext(16, 0xFF);
            std::vector<uint8_t> ciphertext(p_len*2, 0);
            std::vector<uint8_t> decryption(16, 0);

            // Test encryption
            botan_pk_op_encrypt_t op_enc;
            size_t ct_len = ciphertext.size();
            REQUIRE_FFI_OK(botan_pk_op_encrypt_create, (&op_enc, loaded_pubkey, "Raw", 0));
            TEST_FFI_OK(botan_pk_op_encrypt, (op_enc, rng, ciphertext.data(), &ct_len, plaintext.data(), plaintext.size()));
            TEST_FFI_OK(botan_pk_op_encrypt_destroy, (op_enc));

            // Test decryption
            botan_pk_op_decrypt_t op_dec;
            size_t pt_len = decryption.size();
            REQUIRE_FFI_OK(botan_pk_op_decrypt_create, (&op_dec, loaded_privkey, "Raw", 0));
            TEST_FFI_OK(botan_pk_op_decrypt, (op_dec, decryption.data(), &pt_len, ciphertext.data(), ct_len));
            TEST_FFI_OK(botan_pk_op_decrypt_destroy, (op_dec));

            TEST_FFI_OK(botan_pubkey_destroy, (loaded_pubkey));
            TEST_FFI_OK(botan_pubkey_destroy, (pub));
            TEST_FFI_OK(botan_privkey_destroy, (loaded_privkey));
            TEST_FFI_OK(botan_privkey_destroy, (priv));
            }

         return result;
         }


   };

BOTAN_REGISTER_TEST("ffi", FFI_Unit_Tests);

#endif

}

}

