/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_SODIUM_API)
   #include <botan/sodium.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_SODIUM_API)

class Sodium_API_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(aead_chacha20poly1305());
         results.push_back(aead_chacha20poly1305_ietf());
         results.push_back(aead_xchacha20poly1305());
         results.push_back(auth_hmacsha256());
         results.push_back(auth_hmacsha512());
         results.push_back(auth_hmacsha512256());
         results.push_back(auth_poly1305());
         results.push_back(box_curve25519xsalsa20poly1305());
         results.push_back(hash_sha256());
         results.push_back(hash_sha512());
         results.push_back(randombytes_buf_deterministic());
         results.push_back(secretbox_xsalsa20poly1305());
         results.push_back(secretbox_xsalsa20poly1305_detached());
         results.push_back(shorthash_siphash24());
         results.push_back(stream_chacha20());
         results.push_back(stream_chacha20_ietf());
         results.push_back(stream_salsa20());
         results.push_back(stream_xchacha20());
         results.push_back(stream_xsalsa20());
         results.push_back(sign_ed25519());
         results.push_back(sodium_malloc());
         results.push_back(sodium_utils());

         return results;
         }

   private:

      Test::Result sodium_malloc()
         {
         Test::Result result("sodium_malloc");

         void* p = Botan::Sodium::sodium_malloc(50);
         std::memset(p, 0xFF, 50);

         Botan::Sodium::sodium_free(p);
         Botan::Sodium::sodium_free(nullptr);

         result.test_success("Didn't crash");

         return result;
         }

      Test::Result sodium_utils()
         {
         Test::Result result("sodium math utils");

         result.confirm("sodium_is_zero", Botan::Sodium::sodium_is_zero(nullptr, 0) == 1);

         std::vector<uint8_t> a(5);
         result.confirm("sodium_is_zero", Botan::Sodium::sodium_is_zero(a.data(), a.size()) == 1);
         Botan::Sodium::sodium_increment(a.data(), a.size());
         result.test_eq("sodium_increment", a, "0100000000");
         result.confirm("sodium_is_zero", Botan::Sodium::sodium_is_zero(a.data(), a.size()) == 0);

         std::memset(a.data(), 0xFF, a.size());
         Botan::Sodium::sodium_increment(a.data(), a.size());
         result.test_eq("sodium_increment", a, "0000000000");
         Botan::Sodium::sodium_increment(a.data(), a.size());
         result.test_eq("sodium_increment", a, "0100000000");

         result.confirm("sodium_compare", Botan::Sodium::sodium_compare(a.data(), a.data(), a.size()) == 0);
         result.confirm("sodium_memcmp", Botan::Sodium::sodium_memcmp(a.data(), a.data(), a.size()) == 0);

         std::vector<uint8_t> b(5, 0x10);
         result.confirm("sodium_compare a<b", Botan::Sodium::sodium_compare(a.data(), b.data(), a.size()) == -1);
         result.confirm("sodium_compare b<a", Botan::Sodium::sodium_compare(b.data(), a.data(), a.size()) == 1);
         result.confirm("sodium_memcmp a<b", Botan::Sodium::sodium_memcmp(a.data(), b.data(), a.size()) == -1);
         result.confirm("sodium_memcmp b<a", Botan::Sodium::sodium_memcmp(b.data(), a.data(), a.size()) == -1);

         Botan::Sodium::sodium_add(a.data(), b.data(), a.size());
         result.test_eq("sodium_add", a, "1110101010");
         Botan::Sodium::sodium_add(b.data(), a.data(), a.size());
         result.test_eq("sodium_add", b, "2120202020");
         Botan::Sodium::sodium_add(a.data(), b.data(), a.size());
         result.test_eq("sodium_add", a, "3230303030");
         Botan::Sodium::sodium_add(b.data(), a.data(), a.size());
         result.test_eq("sodium_add", b, "5350505050");

         return result;
         }

      Test::Result randombytes_buf_deterministic()
         {
         Test::Result result("randombytes_buf_deterministic");

         const uint8_t seed[32] = { 1, 0 };
         std::vector<uint8_t> output(18);

         Botan::Sodium::randombytes_buf_deterministic(output.data(), output.size(), seed);

         result.test_eq("output", output, "04069B5F37E82F91DC37FD5EB99F1A4124B1");

         return result;
         }

      Test::Result hash_sha512()
         {
         Test::Result result("crypto_hash_sha512");

         std::vector<uint8_t> output(64);
         Botan::Sodium::crypto_hash_sha512(output.data(), nullptr, 0);

         result.test_eq("expected output", output,
                        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

         return result;
         }

      Test::Result hash_sha256()
         {
         Test::Result result("crypto_hash_sha256");

         std::vector<uint8_t> output(32);
         Botan::Sodium::crypto_hash_sha256(output.data(), nullptr, 0);

         result.test_eq("expected output", output,
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

         return result;
         }

      Test::Result box_curve25519xsalsa20poly1305()
         {
         Test::Result result("crypto_box_curve25519xsalsa20poly1305");

         const std::vector<uint8_t> seed(32);

         std::vector<uint8_t> pk1(32), sk1(32);
         result.test_rc_ok("seed_keypair", Botan::Sodium::crypto_box_seed_keypair(pk1.data(), sk1.data(), seed.data()));
         result.test_eq("pk1", pk1, "5BF55C73B82EBE22BE80F3430667AF570FAE2556A6415E6B30D4065300AA947D");
         result.test_eq("sk1", sk1, "5046ADC1DBA838867B2BBBFDD0C3423E58B57970B5267A90F57960924A87F196");

         std::vector<uint8_t> pk2(32), sk2(32);
         result.test_rc_ok("seed_keypair", Botan::Sodium::crypto_box_seed_keypair(pk2.data(), sk2.data(), sk1.data()));
         result.test_eq("pk2", pk2, "E0CFC9C6B2FE5BF85F48671691225C03D763F2305206FE3D3B0ED7B76153684A");
         result.test_eq("sk2", sk2, "58E2E4C71F138FBC97F9341735B4581746761F9A104540007FE12CFC4D9FDA15");

         const std::vector<uint8_t> ptext(15);
         std::vector<uint8_t> ctext(ptext.size() + 16);
         const std::vector<uint8_t> nonce(Botan::Sodium::crypto_box_noncebytes());

         result.test_rc_ok("crypto_box_easy",
                           Botan::Sodium::crypto_box_easy(ctext.data(), ptext.data(), ptext.size(), nonce.data(),
                                           pk2.data(), sk1.data()));

         result.test_eq("ctext1", ctext, "11D78D4C32C5674390C0425D8BBB5928AFE7F767E2A7E4427E1A1362F1FD92");

         result.test_rc_ok("crypto_box_easy",
                           Botan::Sodium::crypto_box_easy(ctext.data(), ptext.data(), ptext.size(), nonce.data(),
                                           pk1.data(), sk2.data()));

         // same shared secret, same nonce, same data -> same ciphertext
         result.test_eq("ctext2", ctext, "11D78D4C32C5674390C0425D8BBB5928AFE7F767E2A7E4427E1A1362F1FD92");

         std::vector<uint8_t> recovered(15);

         result.test_rc_ok("crypto_box_open_easy",
                           Botan::Sodium::crypto_box_open_easy(recovered.data(), ctext.data(), ctext.size(),
                                                nonce.data(), pk1.data(), sk2.data()));

         result.test_eq("recover1", recovered, ptext);

         result.test_rc_ok("crypto_box_open_easy",
                           Botan::Sodium::crypto_box_open_easy(recovered.data(), ctext.data(), ctext.size(),
                                                nonce.data(), pk2.data(), sk1.data()));

         result.test_eq("recover1", recovered, ptext);

         return result;
         }

      Test::Result aead_chacha20poly1305()
         {
         Test::Result result("crypto_aead_chacha20poly1305");

         const std::vector<uint8_t> key = Botan::hex_decode("0000000000000000000000000000000000000000000000000000000000000000");
         const std::vector<uint8_t> ad;
         const std::vector<uint8_t> nonce = Botan::hex_decode("0000000000000000");
         const std::vector<uint8_t> in = Botan::hex_decode("000000000000000000000000000000");

         result.test_eq("key len", Botan::Sodium::crypto_aead_chacha20poly1305_keybytes(), key.size());
         result.test_eq("nonce len", Botan::Sodium::crypto_aead_chacha20poly1305_npubbytes(), nonce.size());

         std::vector<uint8_t> ctext(in.size());
         std::vector<uint8_t> mac(16);
         unsigned long long maclen = 0;
         Botan::Sodium::crypto_aead_chacha20poly1305_encrypt_detached(
            ctext.data(), mac.data(), &maclen, in.data(), in.size(),
            ad.data(), ad.size(), nullptr, nonce.data(), key.data());

         result.test_eq("maclen", size_t(maclen), 16);
         result.test_eq("mac", mac, "09998877ABA156DDC68F8344098F68B9");
         result.test_eq("ctext", ctext, "9F07E7BE5551387A98BA977C732D08");

         std::vector<uint8_t> recovered(ctext.size());
         result.test_rc_ok("decrypt", Botan::Sodium::crypto_aead_chacha20poly1305_decrypt_detached(
            recovered.data(), nullptr, ctext.data(), ctext.size(), mac.data(),
            ad.data(), ad.size(), nonce.data(), key.data()));

         result.test_eq("plaintext", recovered, in);

         mac[0] ^= 1;
         result.test_rc_fail("decrypt", "invalid ciphertext", Botan::Sodium::crypto_aead_chacha20poly1305_decrypt_detached(
            recovered.data(), nullptr, ctext.data(), ctext.size(), mac.data(),
            ad.data(), ad.size(), nonce.data(), key.data()));

         ctext.resize(in.size() + mac.size());
         unsigned long long ctext_len;
         result.test_rc_ok("encrypt", Botan::Sodium::crypto_aead_chacha20poly1305_encrypt(
            ctext.data(), &ctext_len, in.data(), in.size(),
            ad.data(), ad.size(), nullptr, nonce.data(), key.data()));

         result.test_eq("ctext_len", size_t(ctext_len), ctext.size());
         result.test_eq("ctext", ctext, "9F07E7BE5551387A98BA977C732D0809998877ABA156DDC68F8344098F68B9");

         unsigned long long recovered_len = 0;
         result.test_rc_ok("decrypt", Botan::Sodium::crypto_aead_chacha20poly1305_decrypt(
                              recovered.data(), &recovered_len, nullptr,
                              ctext.data(), ctext.size(), ad.data(), ad.size(), nonce.data(), key.data()));

         result.test_eq("recovered", recovered, in);

         return result;
         }

      Test::Result aead_chacha20poly1305_ietf()
         {
         Test::Result result("crypto_aead_chacha20poly1305_ietf");

         const std::vector<uint8_t> key = Botan::hex_decode("0000000000000000000000000000000000000000000000000000000000000000");
         const std::vector<uint8_t> ad;
         const std::vector<uint8_t> nonce = Botan::hex_decode("000000000000000000000000");
         const std::vector<uint8_t> in = Botan::hex_decode("000000000000000000000000000000");

         result.test_eq("key len", Botan::Sodium::crypto_aead_chacha20poly1305_ietf_keybytes(), key.size());
         result.test_eq("nonce len", Botan::Sodium::crypto_aead_chacha20poly1305_ietf_npubbytes(), nonce.size());

         std::vector<uint8_t> ctext(in.size());
         std::vector<uint8_t> mac(16);
         unsigned long long maclen = 0;
         Botan::Sodium::crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            ctext.data(), mac.data(), &maclen, in.data(), in.size(),
            ad.data(), ad.size(), nullptr, nonce.data(), key.data());

         result.test_eq("maclen", size_t(maclen), 16);
         result.test_eq("mac", mac, "3679F1FB9843FD81E26D962888296954");
         result.test_eq("ctext", ctext, "9F07E7BE5551387A98BA977C732D08");

         std::vector<uint8_t> recovered(ctext.size());
         result.test_rc_ok("decrypt", Botan::Sodium::crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            recovered.data(), nullptr, ctext.data(), ctext.size(), mac.data(),
            ad.data(), ad.size(), nonce.data(), key.data()));

         result.test_eq("plaintext", recovered, in);

         mac[0] ^= 1;
         result.test_rc_fail("decrypt", "invalid ciphertext", Botan::Sodium::crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            recovered.data(), nullptr, ctext.data(), ctext.size(), mac.data(),
            ad.data(), ad.size(), nonce.data(), key.data()));

         ctext.resize(in.size() + mac.size());
         unsigned long long ctext_len;
         result.test_rc_ok("encrypt", Botan::Sodium::crypto_aead_chacha20poly1305_ietf_encrypt(
            ctext.data(), &ctext_len, in.data(), in.size(),
            ad.data(), ad.size(), nullptr, nonce.data(), key.data()));

         result.test_eq("ctext_len", size_t(ctext_len), ctext.size());
         result.test_eq("ctext", ctext, "9F07E7BE5551387A98BA977C732D083679F1FB9843FD81E26D962888296954");

         unsigned long long recovered_len = 0;
         result.test_rc_ok("decrypt", Botan::Sodium::crypto_aead_chacha20poly1305_ietf_decrypt(
                              recovered.data(), &recovered_len, nullptr,
                              ctext.data(), ctext.size(), ad.data(), ad.size(), nonce.data(), key.data()));

         result.test_eq("recovered", recovered, in);

         return result;
         }

      Test::Result aead_xchacha20poly1305()
         {
         Test::Result result("crypto_aead_xchacha20poly1305");

         const std::vector<uint8_t> key = Botan::hex_decode("0000000000000000000000000000000000000000000000000000000000000000");
         const std::vector<uint8_t> ad;
         const std::vector<uint8_t> nonce = Botan::hex_decode("000000000000000000000000000000000000000000000000");
         const std::vector<uint8_t> in = Botan::hex_decode("000000000000000000000000000000");

         result.test_eq("key len", Botan::Sodium::crypto_aead_xchacha20poly1305_ietf_keybytes(), key.size());
         result.test_eq("nonce len", Botan::Sodium::crypto_aead_xchacha20poly1305_ietf_npubbytes(), nonce.size());

         std::vector<uint8_t> ctext(in.size());
         std::vector<uint8_t> mac(16);
         unsigned long long maclen = 0;
         Botan::Sodium::crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            ctext.data(), mac.data(), &maclen, in.data(), in.size(),
            ad.data(), ad.size(), nullptr, nonce.data(), key.data());

         result.test_eq("maclen", size_t(maclen), 16);
         result.test_eq("mac", mac, "b2f7033812ac9ebd3745e2c99c7bbfeb");
         result.test_eq("ctext", ctext, "789e9689e5208d7fd9e1f3c5b5341f");

         std::vector<uint8_t> recovered(ctext.size());
         result.test_rc_ok("decrypt",
                           Botan::Sodium::crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
                              recovered.data(), nullptr, ctext.data(), ctext.size(), mac.data(),
                              ad.data(), ad.size(), nonce.data(), key.data()));

         result.test_eq("plaintext", recovered, in);

         mac[0] ^= 1;
         result.test_rc_fail("decrypt", "invalid ciphertext", Botan::Sodium::crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            recovered.data(), nullptr, ctext.data(), ctext.size(), mac.data(),
            ad.data(), ad.size(), nonce.data(), key.data()));

         ctext.resize(in.size() + mac.size());
         unsigned long long ctext_len;
         result.test_rc_ok("encrypt", Botan::Sodium::crypto_aead_xchacha20poly1305_ietf_encrypt(
            ctext.data(), &ctext_len, in.data(), in.size(),
            ad.data(), ad.size(), nullptr, nonce.data(), key.data()));

         result.test_eq("ctext_len", size_t(ctext_len), ctext.size());
         result.test_eq("ctext", ctext, "789e9689e5208d7fd9e1f3c5b5341fb2f7033812ac9ebd3745e2c99c7bbfeb");

         unsigned long long recovered_len = 0;
         result.test_rc_ok("decrypt", Botan::Sodium::crypto_aead_xchacha20poly1305_ietf_decrypt(
                              recovered.data(), &recovered_len, nullptr,
                              ctext.data(), ctext.size(), ad.data(), ad.size(), nonce.data(), key.data()));

         result.test_eq("recovered", recovered, in);

         return result;
         }

      Test::Result auth_hmacsha512()
         {
         Test::Result result("crypto_auth_hmacsha512");

         const std::vector<uint8_t> key = Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
         const std::vector<uint8_t> in = Botan::hex_decode("616263");

         result.test_eq("key_size", key.size(), Botan::Sodium::crypto_auth_hmacsha512_keybytes());

         std::vector<uint8_t> mac(64);
         Botan::Sodium::crypto_auth_hmacsha512(mac.data(), in.data(), in.size(), key.data());

         result.test_eq("expected mac", mac,
                        "69D4A21E226BF0D348CB9A847C01CF24E93E8AC30D7C951704B936F82F795A624B470E23ABD33AC8700E797F0F2A499B932BAC7D283BBBB37D8FECF70D5E08A7");

         result.test_rc_ok("verify",
                           Botan::Sodium::crypto_auth_hmacsha512_verify(mac.data(), in.data(), in.size(), key.data()));

         mac[0] ^= 1;
         result.test_rc_fail("verify", "invalid mac",
                             Botan::Sodium::crypto_auth_hmacsha512_verify(mac.data(), in.data(), in.size(), key.data()));

         return result;
         }

      Test::Result auth_hmacsha512256()
         {
         Test::Result result("crypto_auth_hmacsha512256");

         const std::vector<uint8_t> key = Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
         const std::vector<uint8_t> in = Botan::hex_decode("616263");

         std::vector<uint8_t> mac(32);
         Botan::Sodium::crypto_auth_hmacsha512256(mac.data(), in.data(), in.size(), key.data());

         result.test_eq("expected mac", mac,
                        "69D4A21E226BF0D348CB9A847C01CF24E93E8AC30D7C951704B936F82F795A62");

         result.test_rc_ok("verify",
                           Botan::Sodium::crypto_auth_hmacsha512256_verify(mac.data(), in.data(), in.size(), key.data()));

         mac[0] ^= 1;
         result.test_rc_fail("verify", "invalid mac",
                             Botan::Sodium::crypto_auth_hmacsha512256_verify(mac.data(), in.data(), in.size(), key.data()));

         return result;
         }

      Test::Result auth_hmacsha256()
         {
         Test::Result result("crypto_auth_hmacsha256");

         const std::vector<uint8_t> key = Botan::hex_decode("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20");
         const std::vector<uint8_t> in = Botan::hex_decode("616263");

         std::vector<uint8_t> mac(32);
         Botan::Sodium::crypto_auth_hmacsha256(mac.data(), in.data(), in.size(), key.data());

         result.test_eq("expected mac", mac,
                        "A21B1F5D4CF4F73A4DD939750F7A066A7F98CC131CB16A6692759021CFAB8181");

         result.test_rc_ok("verify",
                           Botan::Sodium::crypto_auth_hmacsha256_verify(mac.data(), in.data(), in.size(), key.data()));

         mac[0] ^= 1;
         result.test_rc_fail("verify", "invalid mac",
                             Botan::Sodium::crypto_auth_hmacsha256_verify(mac.data(), in.data(), in.size(), key.data()));

         return result;
         }

      Test::Result auth_poly1305()
         {
         Test::Result result("crypto_onetimeauth_poly1305");

         const std::vector<uint8_t> key(Botan::Sodium::crypto_onetimeauth_keybytes(), 0x42);
         const std::vector<uint8_t> in(15);

         std::vector<uint8_t> mac(16);

         result.test_rc_ok("poly1305",
                           Botan::Sodium::crypto_onetimeauth_poly1305(mac.data(), in.data(), in.size(), key.data()));

         result.test_eq("expected mac", mac, "12154512151545121515451215154584");

         result.test_rc_ok("poly1305 verify",
                           Botan::Sodium::crypto_onetimeauth_poly1305_verify(mac.data(), in.data(), in.size(), key.data()));

         mac[0] ^= 1;
         result.test_rc_fail("poly1305 verify", "invalid mac",
                             Botan::Sodium::crypto_onetimeauth_poly1305_verify(mac.data(), in.data(), in.size(), key.data()));

         return result;
         }

      Test::Result shorthash_siphash24()
         {
         Test::Result result("crypto_shorthash_siphash24");

         const std::vector<uint8_t> key = Botan::hex_decode("000102030405060708090A0B0C0D0E0F");
         const std::vector<uint8_t> in = Botan::hex_decode("000102030405060708090A0B0C0D0E");

         std::vector<uint8_t> mac(8);
         Botan::Sodium::crypto_shorthash_siphash24(mac.data(), in.data(), in.size(), key.data());

         result.test_eq("expected mac", mac, "E545BE4961CA29A1");

         return result;
         }

      Test::Result secretbox_xsalsa20poly1305()
         {
         Test::Result result("secretbox_xsalsa20poly1305");

         const std::vector<uint8_t> ptext(33);
         std::vector<uint8_t> ctext(33);
         const std::vector<uint8_t> nonce(Botan::Sodium::crypto_secretbox_xsalsa20poly1305_noncebytes());
         const std::vector<uint8_t> key(Botan::Sodium::crypto_secretbox_xsalsa20poly1305_keybytes());

         result.test_rc_ok("encrypt",
                           Botan::Sodium::crypto_secretbox_xsalsa20poly1305(ctext.data(),
                                                               ptext.data(),
                                                               ptext.size(),
                                                               nonce.data(),
                                                               key.data()));

         result.test_eq("ctext", ctext, "0000000000000000000000000000000042E45EB764A1B706D4776A849BC2526BC6");

         std::vector<uint8_t> recovered(33);
         result.test_rc_ok("decrypt",
                           Botan::Sodium::crypto_secretbox_xsalsa20poly1305_open(
                              recovered.data(),
                              ctext.data(),
                              ctext.size(),
                              nonce.data(),
                              key.data()));

         result.test_eq("decrypted", recovered, ptext);

         return result;
         }

      Test::Result secretbox_xsalsa20poly1305_detached()
         {
         Test::Result result("secretbox_xsalsa20poly1305");

         const std::vector<uint8_t> ptext(33);
         const std::vector<uint8_t> nonce(Botan::Sodium::crypto_secretbox_xsalsa20poly1305_noncebytes());
         const std::vector<uint8_t> key(Botan::Sodium::crypto_secretbox_xsalsa20poly1305_keybytes());
         std::vector<uint8_t> ctext(33);
         std::vector<uint8_t> mac(16);

         result.test_rc_ok("encrypt detached",
                           Botan::Sodium::crypto_secretbox_detached(ctext.data(),
                                                       mac.data(),
                                                       ptext.data(),
                                                       ptext.size(),
                                                       nonce.data(),
                                                       key.data()));

         result.test_eq("ctext", ctext, "C63EBBFFFE85CE2CEBDEF7DC42F494576D05BDD7B929EBB045F2A793F740277D05");
         result.test_eq("mac", mac, "0D6681DCED740667C699F0AC71BFD1BD");

         std::vector<uint8_t> recovered(ctext.size());

         result.test_rc_ok("open detached",
                           Botan::Sodium::crypto_secretbox_open_detached(recovered.data(),
                                                                         ctext.data(),
                                                                         mac.data(),
                                                                         ctext.size(),
                                                                         nonce.data(),
                                                                         key.data()));

         result.test_eq("recovered", recovered, ptext);

         return result;
         }

      Test::Result sign_ed25519()
         {
         Test::Result result("crypto_sign_ed25519");

         const std::vector<uint8_t> seed(32);
         std::vector<uint8_t> pk(32), sk(64);

         result.test_rc_ok("seed_keypair", Botan::Sodium::crypto_sign_ed25519_seed_keypair(pk.data(), sk.data(), seed.data()));

         result.test_eq("pk", pk, "3B6A27BCCEB6A42D62A3A8D02A6F0D73653215771DE243A63AC048A18B59DA29");
         result.test_eq("sk", sk, "00000000000000000000000000000000000000000000000000000000000000003B6A27BCCEB6A42D62A3A8D02A6F0D73653215771DE243A63AC048A18B59DA29");

         const std::vector<uint8_t> msg = { 1, 2, 3 };
         std::vector<uint8_t> sig(64);
         unsigned long long sig_len = 0;
         result.test_rc_ok("sign_detached", Botan::Sodium::crypto_sign_ed25519_detached(sig.data(), &sig_len, msg.data(), msg.size(), sk.data()));
         result.confirm("sig len", sig_len == 64);

         result.test_eq("sig", sig, "2A26779BA6CBB5E54292257F725AF112B273C38728329682D99ED81BA6D7670350AE4CC53C5456FA437128D19298A5D949AB46E3D41AB3DBCFB0B35C895E9304");

         result.test_rc_ok("verify", Botan::Sodium::crypto_sign_ed25519_verify_detached(sig.data(), msg.data(), msg.size(), pk.data()));

         sig[0] ^= 1;
         result.test_rc_fail("verify", "reject invalid",
                             Botan::Sodium::crypto_sign_ed25519_verify_detached(sig.data(), msg.data(), msg.size(), pk.data()));

         return result;
         }

      Test::Result stream_salsa20()
         {
         Test::Result result("crypto_stream_salsa20");

         const std::vector<uint8_t> key = Botan::hex_decode("0F62B5085BAE0154A7FA4DA0F34699EC3F92E5388BDE3184D72A7DD02376C91C");
         const std::vector<uint8_t> nonce = Botan::hex_decode("288FF65DC42B92F9");
         const std::vector<uint8_t> expected = Botan::hex_decode(
            "5E5E71F90199340304ABB22A37B6625BF883FB89CE3B21F54A10B81066EF87DA");

         std::vector<uint8_t> output(32);
         Botan::Sodium::crypto_stream_salsa20(output.data(), output.size(), nonce.data(), key.data());
         result.test_eq("stream", output, expected);

         std::vector<uint8_t> xor_output(32);
         Botan::Sodium::crypto_stream_salsa20_xor(xor_output.data(), output.data(), output.size(), nonce.data(), key.data());
         result.test_eq("stream", xor_output, std::vector<uint8_t>(32)); // all zeros

         return result;
         }

      Test::Result stream_xsalsa20()
         {
         Test::Result result("crypto_stream_xsalsa20");

         const std::vector<uint8_t> key = Botan::hex_decode("1B27556473E985D462CD51197A9A46C76009549EAC6474F206C4EE0844F68389");
         const std::vector<uint8_t> nonce = Botan::hex_decode("69696EE955B62B73CD62BDA875FC73D68219E0036B7A0B37");
         const std::vector<uint8_t> expected = Botan::hex_decode(
            "EEA6A7251C1E72916D11C2CB214D3C252539121D8E234E652D651FA4C8CFF880");

         std::vector<uint8_t> output(32);
         Botan::Sodium::crypto_stream_xsalsa20(output.data(), output.size(), nonce.data(), key.data());
         result.test_eq("stream", output, expected);

         std::vector<uint8_t> xor_output(32);
         Botan::Sodium::crypto_stream_xsalsa20_xor(xor_output.data(), output.data(), output.size(), nonce.data(), key.data());
         result.test_eq("stream", xor_output, std::vector<uint8_t>(32)); // all zeros

         return result;
         }

      Test::Result stream_chacha20()
         {
         Test::Result result("crypto_stream_chacha20");

         const std::vector<uint8_t> key = Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
         const std::vector<uint8_t> nonce = Botan::hex_decode("0001020304050607");
         const std::vector<uint8_t> expected = Botan::hex_decode(
            "F798A189F195E66982105FFB640BB7757F579DA31602FC93EC01AC56F85AC3C1");

         std::vector<uint8_t> output(32);
         Botan::Sodium::crypto_stream_chacha20(output.data(), output.size(), nonce.data(), key.data());
         result.test_eq("stream", output, expected);

         std::vector<uint8_t> xor_output(32);
         Botan::Sodium::crypto_stream_chacha20_xor(xor_output.data(), output.data(), output.size(), nonce.data(), key.data());
         result.test_eq("stream", xor_output, std::vector<uint8_t>(32)); // all zeros

         return result;
         }

      Test::Result stream_chacha20_ietf()
         {
         Test::Result result("crypto_stream_chacha20");

         const std::vector<uint8_t> key = Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
         const std::vector<uint8_t> nonce = Botan::hex_decode("000102030405060708090A0B0C");
         const std::vector<uint8_t> expected = Botan::hex_decode(
            "103AF111C18B549D39248FB07D60C29A95D1DB88D892F7B4AF709A5FD47A9E4B");

         std::vector<uint8_t> output(32);
         Botan::Sodium::crypto_stream_chacha20_ietf(output.data(), output.size(), nonce.data(), key.data());
         result.test_eq("stream", output, expected);

         std::vector<uint8_t> xor_output(32);
         Botan::Sodium::crypto_stream_chacha20_ietf_xor(xor_output.data(), output.data(), output.size(), nonce.data(), key.data());
         result.test_eq("stream", xor_output, std::vector<uint8_t>(32)); // all zeros

         return result;
         }

      Test::Result stream_xchacha20()
         {
         Test::Result result("crypto_stream_xchacha20");

         const std::vector<uint8_t> key = Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
         const std::vector<uint8_t> nonce = Botan::hex_decode("000102030405060708090a0b0c0d0e0f1011121314151617");
         const std::vector<uint8_t> expected = Botan::hex_decode(
            "e53a61cef151e81401067de33adfc02e90ab205361b49b539fda7f0e63b1bc7d");

         std::vector<uint8_t> output(32);
         Botan::Sodium::crypto_stream_xchacha20(output.data(), output.size(), nonce.data(), key.data());
         result.test_eq("stream", output, expected);

         std::vector<uint8_t> xor_output(32);
         Botan::Sodium::crypto_stream_xchacha20_xor(xor_output.data(), output.data(), output.size(), nonce.data(), key.data());
         result.test_eq("stream", xor_output, std::vector<uint8_t>(32)); // all zeros

         return result;
         }

   };

BOTAN_REGISTER_TEST("compat", "sodium", Sodium_API_Tests);

#endif

}
