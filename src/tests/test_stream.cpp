/*
* (C) 2014,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_STREAM_CIPHER)
   #include <botan/exceptn.h>
   #include <botan/rng.h>
   #include <botan/stream_cipher.h>
   #include <botan/internal/fmt.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_STREAM_CIPHER)

namespace {

class Stream_Cipher_Tests final : public Text_Based_Test {
   public:
      Stream_Cipher_Tests() : Text_Based_Test("stream", "Key,Out", "In,Nonce,Seek") {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override {
         const std::vector<uint8_t> key = vars.get_req_bin("Key");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");
         const std::vector<uint8_t> nonce = vars.get_opt_bin("Nonce");
         const uint64_t seek = vars.get_opt_u64("Seek", 0);
         std::vector<uint8_t> input = vars.get_opt_bin("In");

         if(input.empty()) {
            input.resize(expected.size());
         }

         Test::Result result(algo);

         const std::vector<std::string> providers = provider_filter(Botan::StreamCipher::providers(algo));

         if(providers.empty()) {
            result.note_missing("stream cipher " + algo);
            return result;
         }

         for(const auto& provider_ask : providers) {
            auto cipher = Botan::StreamCipher::create(algo, provider_ask);

            if(!cipher) {
               result.test_failure(Botan::fmt("Stream cipher {} supported by {} but not found", algo, provider_ask));
               continue;
            }

            const std::string provider(cipher->provider());
            result.test_str_not_empty("provider", provider);
            result.test_str_eq(provider, cipher->name(), algo);

            result.test_is_true("default iv length is valid", cipher->valid_iv_length(cipher->default_iv_length()));

            result.test_is_true("advertised buffer size is > 0", cipher->buffer_size() > 0);

            if(cipher->default_iv_length() == 0) {
               result.test_is_true("if default iv length is zero, no iv supported", nonce.empty());

               // This should still succeed
               cipher->set_iv(nullptr, 0);
            }

            try {
               std::vector<uint8_t> buf(128);
               cipher->cipher1(buf.data(), buf.size());
               result.test_failure("Was able to encrypt without a key being set");
            } catch(Botan::Invalid_State&) {
               result.test_success("Trying to encrypt with no key set fails");
            }

            const bool supports_seek = cipher->supports_seek();

            if(supports_seek) {
               try {
                  cipher->seek(0);
                  result.test_failure("Was able to seek without a key being set");
               } catch(Botan::Invalid_State&) {
                  result.test_success("Trying to seek with no key set fails");
               }
            } else {
               result.test_throws<Botan::Not_Implemented>("seek() throws Not_Implemented when supports_seek() is false",
                                                          [&]() { cipher->seek(0); });
            }

            if(!cipher->valid_iv_length(nonce.size())) {
               throw Test_Error("Invalid nonce for " + algo);
            }

            bool accepted_nonce_early = false;
            if(!nonce.empty()) {
               try {
                  cipher->set_iv(nonce.data(), nonce.size());
                  accepted_nonce_early = true;
               } catch(Botan::Invalid_State&) {}
            }

            /*
            * Different providers may have additional restrictions on key sizes.
            * Avoid testing the cipher with a key size that it does not natively support.
            */
            if(!cipher->valid_keylength(key.size())) {
               result.test_note("Skipping test with provider " + provider + " as it does not support key length " +
                                std::to_string(key.size()));
               continue;
            }

            result.test_is_false("key not set", cipher->has_keying_material());
            cipher->set_key(key);
            result.test_is_true("key set", cipher->has_keying_material());

            /*
            Test invalid nonce sizes. this assumes no implemented cipher supports a nonce of 65000
            */
            const size_t large_nonce_size = 65000;
            result.test_is_true("Stream cipher does not support very large nonce",
                                cipher->valid_iv_length(large_nonce_size) == false);

            result.test_throws("Throws if invalid nonce size given",
                               [&]() { cipher->set_iv(nullptr, large_nonce_size); });

            /*
            If the set_nonce call earlier succeeded, then we require that it also
            worked (ie saved the nonce for later use) even though the key was
            not set. So, don't set the nonce now, to ensure the previous call
            had an effect.
            */
            if(!nonce.empty() && accepted_nonce_early == false) {
               cipher->set_iv(nonce.data(), nonce.size());
            }

            if(seek != 0) {
               cipher->seek(seek);
            }

            // Test that clone works and does not affect parent object
            auto clone = cipher->new_object();
            result.test_is_true("Clone has different pointer", cipher.get() != clone.get());
            result.test_str_eq("Clone has same name", cipher->name(), clone->name());
            clone->set_key(this->rng().random_vec(cipher->maximum_keylength()));

            {
               std::vector<uint8_t> buf = input;
               cipher->encrypt(buf);
               result.test_bin_eq(provider + " encrypt", buf, expected);
            }

            /*
            * Verify that seek is idempotent
            */
            if(supports_seek && seek > 0) {
               if(!nonce.empty()) {
                  cipher->set_iv(nonce.data(), nonce.size());
               }
               cipher->seek(seek);
               cipher->seek(0);
               cipher->seek(seek);
               std::vector<uint8_t> seek_buf = input;
               cipher->encrypt(seek_buf);
               result.test_bin_eq(provider + " seek is idempotent", seek_buf, expected);

               // After seeking, seek(0) must reset back to original keystream.
               cipher->seek(0);
               std::vector<uint8_t> seek0_buf(input.size());
               cipher->encrypt(seek0_buf);

               auto fresh = cipher->new_object();
               fresh->set_key(key);
               if(!nonce.empty()) {
                  fresh->set_iv(nonce.data(), nonce.size());
               }
               std::vector<uint8_t> fresh_buf(input.size());
               fresh->encrypt(fresh_buf);
               result.test_bin_eq(provider + " seek(0) after high seek round-trips", fresh_buf, seek0_buf);
            }

            {
               if(nonce.empty()) {
                  cipher->set_key(key);
               } else {
                  cipher->set_iv(nonce.data(), nonce.size());
               }
               if(seek != 0) {
                  cipher->seek(seek);
               }
               std::vector<uint8_t> buf = input;
               cipher->encrypt(buf);
               result.test_bin_eq(provider + " encrypt 2", buf, expected);
            }

            if(!nonce.empty()) {
               cipher->set_iv(nonce.data(), nonce.size());
               if(seek != 0) {
                  cipher->seek(seek);
               }
               std::vector<uint8_t> buf = input;
               cipher->encrypt(buf);
               result.test_bin_eq(provider + " second encrypt", buf, expected);
            }

            {
               cipher->set_key(key);

               cipher->set_iv(nonce.data(), nonce.size());

               if(seek != 0) {
                  cipher->seek(seek);
               }

               std::vector<uint8_t> buf(input.size(), 0xAB);

               uint8_t* buf_ptr = buf.data();
               size_t buf_len = buf.size();

               while(buf_len > 0) {
                  const size_t next = std::min<size_t>(buf_len, this->rng().next_byte());
                  cipher->write_keystream(buf_ptr, next);
                  buf_ptr += next;
                  buf_len -= next;
               }

               for(size_t i = 0; i != input.size(); ++i) {
                  buf[i] ^= input[i];
               }
               result.test_bin_eq(provider + " write_keystream", buf, expected);
            }

            result.test_is_true("key set", cipher->has_keying_material());
            cipher->clear();
            result.test_is_false("key not set", cipher->has_keying_material());

            try {
               std::vector<uint8_t> buf(128);
               cipher->cipher1(buf.data(), buf.size());
               result.test_failure("Was able to encrypt without a key being set (after clear)");
            } catch(Botan::Invalid_State&) {
               result.test_success("Trying to encrypt with no key set (after clear) fails");
            }
         }

         return result;
      }
};

BOTAN_REGISTER_SERIALIZED_SMOKE_TEST("stream", "stream_ciphers", Stream_Cipher_Tests);

class Stream_Cipher_Seek_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;
         results.push_back(test_idempotent_and_round_trip());
         results.push_back(test_strict_counter_limits());
         return results;
      }

   private:
      static std::unique_ptr<Botan::StreamCipher> create_with_iv(std::string_view algo, size_t iv_len) {
         auto cipher = Botan::StreamCipher::create(algo);

         if(cipher) {
            std::vector<uint8_t> key(cipher->maximum_keylength(), 0);
            std::vector<uint8_t> iv(iv_len, 0);
            cipher->set_key(key);
            if(iv_len > 0) {
               cipher->set_iv(iv);
            }
         }

         return cipher;
      }

      Test::Result test_idempotent_and_round_trip() {
         Test::Result result("StreamCipher seek idempotence and round-trip at high offsets");

         struct Case {
               std::string algo;
               size_t iv_len;
               uint64_t seek_bytes;
         };

         // Seeks chosen so the high counter word is non-zero
         const std::vector<Case> cases = {
            {"ChaCha(20)", 8, (uint64_t{1} << 32) * 64},
            {"ChaCha(20)", 8, (uint64_t{1} << 32) * 64 + 5 * 64 + 17},
            {"ChaCha(20)", 24, (uint64_t{1} << 32) * 64},
            {"Salsa20", 8, (uint64_t{1} << 32) * 64},
            {"Salsa20", 8, (uint64_t{1} << 32) * 64 + 5 * 64 + 17},
            {"Salsa20", 24, (uint64_t{1} << 32) * 64},
         };

         for(const auto& c : cases) {
            const std::string tag = Botan::fmt("{} iv={} seek={}", c.algo, c.iv_len, c.seek_bytes);

            auto a = create_with_iv(c.algo, c.iv_len);
            if(!a) {
               result.note_missing(c.algo);
               continue;
            }

            constexpr size_t sample_bytes = 128;

            // Take reference value: seek to offset, output sample_bytes bytes of keystream.
            a->seek(c.seek_bytes);
            const auto ks_a = a->keystream_bytes<std::vector<uint8_t>>(sample_bytes);

            auto b = create_with_iv(c.algo, c.iv_len);
            b->seek(c.seek_bytes);
            b->seek(c.seek_bytes);
            const auto ks_b = b->keystream_bytes<std::vector<uint8_t>>(sample_bytes);
            result.test_bin_eq(tag + " idempotent", ks_a, ks_b);

            // seek(0) after a high seek must reproduce the keystream of a fresh cipher.
            auto fresh = create_with_iv(c.algo, c.iv_len);
            const auto ks_fresh = fresh->keystream_bytes<std::vector<uint8_t>>(sample_bytes);

            auto rt = create_with_iv(c.algo, c.iv_len);
            rt->seek(c.seek_bytes);
            (void)rt->keystream_bytes<std::vector<uint8_t>>(64);
            rt->seek(0);
            const auto ks_rt = rt->keystream_bytes<std::vector<uint8_t>>(sample_bytes);
            result.test_bin_eq(tag + " seek(0) round-trip", ks_rt, ks_fresh);
         }

         return result;
      }

      Test::Result test_strict_counter_limits() {
         Test::Result result("StreamCipher seek rejection past counter limits");

         if(auto chacha = create_with_iv("ChaCha(20)", 12)) {
            // Last addressable byte: block 2^32 - 1, offset 63.
            const uint64_t max_ok = (uint64_t{1} << 32) * 64 - 1;
            result.test_no_throw("ChaCha 12-byte nonce seek at counter limit", [&]() { chacha->seek(max_ok); });

            // First rejected byte: block 2^32, offset 0.
            const uint64_t seek_limit = (uint64_t{1} << 32) * 64;

            chacha->seek(seek_limit - 1);  // ok

            result.test_throws<Botan::Invalid_Argument>("ChaCha 12-byte nonce seek past counter limit throws",
                                                        [&]() { chacha->seek(seek_limit); });

            // Test a seek way past that limit:
            result.test_throws<Botan::Invalid_Argument>("ChaCha 12-byte nonce seek well past counter limit throws",
                                                        [&]() { chacha->seek((uint64_t{1} << 40) * 64); });
         }

         if(auto ctr_be = Botan::StreamCipher::create("CTR-BE(AES-128,4)")) {
            std::vector<uint8_t> key(16, 0);
            std::vector<uint8_t> iv(16, 0xFF);
            ctr_be->set_key(key);
            ctr_be->set_iv(iv);

            constexpr uint64_t ctr32_max = (uint64_t{1} << 32) * 16 - 1;

            result.test_no_throw("CTR-BE(AES,4) seek at counter limit", [&]() { ctr_be->seek(ctr32_max); });

            result.test_throws<Botan::Invalid_Argument>("CTR-BE(AES,4) seek past 2^32 blocks throws",
                                                        [&]() { ctr_be->seek(ctr32_max + 1); });
         }

         // With a 64-bit counter, you can go anywhere you want
         if(auto ctr_be = Botan::StreamCipher::create("CTR-BE(AES-128,8)")) {
            std::vector<uint8_t> key(16, 0);
            std::vector<uint8_t> iv(16, 0);
            ctr_be->set_key(key);
            ctr_be->set_iv(iv);
            result.test_no_throw("CTR-BE(AES,8) high seek accepted", [&]() { ctr_be->seek((uint64_t{1} << 40) * 16); });
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("stream", "stream_cipher_seek", Stream_Cipher_Seek_Tests);

class Stream_Cipher_Keystream_Cap_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;
         results.push_back(test_remaining_getter());
         results.push_back(test_exhaustion());
         return results;
      }

   private:
      Test::Result test_remaining_getter() {
         Test::Result result("StreamCipher::remaining_keystream_bytes");

         if(auto chacha = Botan::StreamCipher::create("ChaCha(20)")) {
            // Unkeyed cipher: nullopt regardless
            result.test_is_true("Unkeyed ChaCha returns nullopt", !chacha->remaining_keystream_bytes().has_value());

            // With a 64-bit counter, you can go anywhere you want
            const std::vector<uint8_t> key(32, 0);
            const std::vector<uint8_t> iv8(8, 0);
            chacha->set_key(key);
            chacha->set_iv(iv8);
            result.test_is_true("ChaCha 8-byte nonce returns nullopt",
                                !chacha->remaining_keystream_bytes().has_value());

            const std::vector<uint8_t> iv24(24, 0);
            chacha->set_iv(iv24);
            result.test_is_true("ChaCha 24-byte nonce returns nullopt",
                                !chacha->remaining_keystream_bytes().has_value());

            // 96-bit nonce: cap = 2^32 * 64 = 2^38 bytes from a fresh IV.
            const std::vector<uint8_t> iv12(12, 0);
            chacha->set_key(key);
            chacha->set_iv(iv12);
            constexpr auto cap = uint64_t{1} << 38;
            const auto remaining = chacha->remaining_keystream_bytes();
            result.test_is_true("ChaCha 12-byte nonce returns a value", remaining.has_value());
            result.test_u64_eq("ChaCha 12-byte nonce fresh capacity", *remaining, cap);

            // Consume some bytes, the available keystream decreases
            std::vector<uint8_t> buf(100);
            chacha->write_keystream(buf);
            result.test_opt_u64_eq(
               "ChaCha 12-byte nonce after 100 byte write", chacha->remaining_keystream_bytes(), cap - buf.size());

            // After seek the count tracks the new offset
            chacha->seek(cap - 64);
            result.test_opt_u64_eq("ChaCha 12-byte nonce after near-end seek", chacha->remaining_keystream_bytes(), 64);
         }

         // CTR-BE with 64-bit counter
         if(auto ctr_be = Botan::StreamCipher::create("CTR-BE(AES-128,8)")) {
            const std::vector<uint8_t> key(16, 0);
            const std::vector<uint8_t> iv(16, 0);
            ctr_be->set_key(key);
            ctr_be->set_iv(iv);
            result.test_opt_is_null("CTR-BE(AES,8) remaining_keystream_bytes", ctr_be->remaining_keystream_bytes());
         }

         if(auto ctr_be = Botan::StreamCipher::create("CTR-BE(AES-128,4)")) {
            const std::vector<uint8_t> key(16, 0);
            const std::vector<uint8_t> iv(16, 0);
            ctr_be->set_key(key);
            ctr_be->set_iv(iv);

            constexpr auto cap = (uint64_t{1} << 32) * 16;
            const auto remaining = ctr_be->remaining_keystream_bytes();
            result.test_is_true("CTR-BE(AES,4) returns a value", remaining.has_value());
            result.test_u64_eq("CTR-BE(AES,4) fresh capacity", *remaining, cap);
         }

         // Ciphers without seek also return nullopt.
         if(auto rc4 = Botan::StreamCipher::create("RC4")) {
            std::vector<uint8_t> key(16, 0);
            rc4->set_key(key);
            result.test_is_true("RC4 returns nullopt", !rc4->remaining_keystream_bytes().has_value());
         }

         return result;
      }

      Test::Result test_exhaustion() {
         Test::Result result("StreamCipher keystream exhaustion");

         /*
         * ChaCha 96-bit nonce, near the cap: consume the last 200
         * bytes successfully, then any further byte must throw.
         */
         if(auto chacha = Botan::StreamCipher::create("ChaCha(20)")) {
            const std::vector<uint8_t> key(32, 0);
            const std::vector<uint8_t> iv(12, 0xFF);
            chacha->set_key(key);
            chacha->set_iv(iv);
            constexpr uint64_t cap = uint64_t{1} << 38;
            chacha->seek(cap - 200);

            std::vector<uint8_t> buf(200);
            result.test_no_throw("ChaCha 12-byte nonce: consume up to cap", [&]() { chacha->write_keystream(buf); });
            result.test_opt_u64_eq(
               "ChaCha 12-byte nonce: remaining is 0 at cap", chacha->remaining_keystream_bytes(), 0);

            std::vector<uint8_t> one(1);
            result.test_throws<Botan::Invalid_State>("ChaCha 12-byte nonce: write past cap throws",
                                                     [&]() { chacha->write_keystream(one); });

            chacha->seek(cap - 100);

            const auto orig = buf;
            result.test_throws<Botan::Invalid_State>("ChaCha 12-byte nonce: oversize encrypt throws",
                                                     [&]() { chacha->encrypt(buf); });
            result.test_bin_eq("ChaCha 12-byte nonce: oversize encrypt leaves buffer untouched", buf, orig);
         }

         /*
         * CTR-BE(AES,4) near the end of the counter cycle (set up by
         * a high seek): the cap is 2^36 bytes regardless of IV, and
         * we approach it from the bottom via seek. Consume the last
         * 64 bytes successfully, then the 65th must throw without
         * writing.
         */
         if(auto ctr_be = Botan::StreamCipher::create("CTR-BE(AES-128,4)")) {
            const std::vector<uint8_t> key(16, 0);
            const std::vector<uint8_t> iv(16, 0xFF);
            ctr_be->set_key(key);
            ctr_be->set_iv(iv);

            constexpr uint64_t cap = (uint64_t{1} << 32) * 16;

            result.test_opt_u64_eq("CTR-BE(AES,4): remaining at 0", ctr_be->remaining_keystream_bytes(), cap);

            ctr_be->seek(cap - 64);
            result.test_opt_u64_eq("CTR-BE(AES,4): remaining at 0", ctr_be->remaining_keystream_bytes(), 64);

            std::vector<uint8_t> buf(64);
            result.test_no_throw("CTR-BE(AES,4): consume last 64 bytes before counter cycle",
                                 [&]() { ctr_be->write_keystream(buf); });
            result.test_opt_u64_eq("CTR-BE(AES,4): remaining at 0", ctr_be->remaining_keystream_bytes(), 0);

            const auto orig = buf;
            result.test_throws<Botan::Invalid_State>("CTR-BE(AES,4): write past cap throws",
                                                     [&]() { ctr_be->encrypt(buf); });
            result.test_bin_eq("CTR-BE(AES,4): throw leaves buffer untouched", buf, orig);
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("stream", "stream_cipher_keystream_cap", Stream_Cipher_Keystream_Cap_Tests);

}  // namespace

#endif

}  // namespace Botan_Tests
