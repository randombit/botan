/*
* (C) 2014,2015,2017 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_CIPHER_MODES)
   #include <botan/cipher_mode.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_CIPHER_MODES)

class Cipher_Mode_Tests final : public Text_Based_Test {
   public:
      Cipher_Mode_Tests() : Text_Based_Test("modes", "Key,Nonce,In,Out") {}

      std::vector<std::string> possible_providers(const std::string& algo) override {
         return provider_filter(Botan::Cipher_Mode::providers(algo));
      }

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override {
         const std::vector<uint8_t> key = vars.get_req_bin("Key");
         const std::vector<uint8_t> nonce = vars.get_req_bin("Nonce");
         const std::vector<uint8_t> input = vars.get_req_bin("In");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");

         Test::Result result(algo);

         const std::vector<std::string> providers = possible_providers(algo);

         if(providers.empty()) {
            result.note_missing("cipher mode " + algo);
            return result;
         }

         for(auto&& provider_ask : providers) {
            auto enc = Botan::Cipher_Mode::create(algo, Botan::Cipher_Dir::Encryption, provider_ask);

            auto dec = Botan::Cipher_Mode::create(algo, Botan::Cipher_Dir::Decryption, provider_ask);

            if(!enc || !dec) {
               if(enc) {
                  result.test_failure("Provider " + provider_ask + " has encrypt but not decrypt");
               }
               if(dec) {
                  result.test_failure("Provider " + provider_ask + " has decrypt but not encrypt");
               }
               result.note_missing(algo);
               return result;
            }

            result.test_eq("enc and dec granularity is the same", enc->update_granularity(), dec->update_granularity());

            result.test_gt("update granularity is non-zero", enc->update_granularity(), 0);

            result.test_eq(
               "enc and dec ideal granularity is the same", enc->ideal_granularity(), dec->ideal_granularity());

            result.test_gt(
               "ideal granularity is at least update granularity", enc->ideal_granularity(), enc->update_granularity());

            result.confirm("ideal granularity is a multiple of update granularity",
                           enc->ideal_granularity() % enc->update_granularity() == 0);

            try {
               test_mode(result, algo, provider_ask, "encryption", *enc, key, nonce, input, expected, this->rng());
            } catch(Botan::Exception& e) {
               result.test_failure("Encryption tests failed", e.what());
            }

            try {
               test_mode(result, algo, provider_ask, "decryption", *dec, key, nonce, expected, input, this->rng());
            } catch(Botan::Exception& e) {
               result.test_failure("Decryption tests failed", e.what());
            }
         }

         return result;
      }

   private:
      static void test_mode(Test::Result& result,
                            const std::string& algo,
                            const std::string& provider,
                            const std::string& direction,
                            Botan::Cipher_Mode& mode,
                            const std::vector<uint8_t>& key,
                            const std::vector<uint8_t>& nonce,
                            const std::vector<uint8_t>& input,
                            const std::vector<uint8_t>& expected,
                            Botan::RandomNumberGenerator& rng) {
         const bool is_cbc = (algo.find("/CBC") != std::string::npos);
         const bool is_ctr = (algo.find("CTR") != std::string::npos);

         result.test_eq("name", mode.name(), algo);

         // Some modes report base even if got from another provider
         if(mode.provider() != "base") {
            result.test_eq("provider", mode.provider(), provider);
         }

         result.test_eq("mode not authenticated", mode.authenticated(), false);

         const size_t update_granularity = mode.update_granularity();
         const size_t min_final_bytes = mode.minimum_final_size();

         // FFI currently requires this, so assure it is true for all modes
         result.test_gt("buffer sizes ok", mode.ideal_granularity(), min_final_bytes);

         result.test_eq("key not set", mode.has_keying_material(), false);

         result.test_throws("Unkeyed object throws", [&]() {
            Botan::secure_vector<uint8_t> bad(update_granularity);
            mode.finish(bad);
         });

         if(is_cbc) {
            // can't test equal due to CBC padding

            if(direction == "encryption") {
               result.test_lte("output_length", mode.output_length(input.size()), expected.size());
            } else {
               result.test_gte("output_length", mode.output_length(input.size()), expected.size());
            }
         } else {
            // assume all other modes are not expanding (currently true)
            result.test_eq("output_length", mode.output_length(input.size()), expected.size());
         }

         result.confirm("default nonce size is allowed", mode.valid_nonce_length(mode.default_nonce_length()));

         // Test that disallowed nonce sizes result in an exception
         static constexpr size_t large_nonce_size = 65000;
         result.test_eq("Large nonce not allowed", mode.valid_nonce_length(large_nonce_size), false);
         result.test_throws("Large nonce causes exception", [&mode]() { mode.start(nullptr, large_nonce_size); });

         Botan::secure_vector<uint8_t> garbage = rng.random_vec(update_granularity);

         // Test to make sure reset() resets what we need it to
         result.test_throws("Cannot process data (update) until key is set", [&]() { mode.update(garbage); });
         result.test_throws("Cannot process data (finish) until key is set", [&]() { mode.finish(garbage); });

         mode.set_key(mutate_vec(key, rng));

         if(is_ctr == false) {
            result.test_throws("Cannot process data until nonce is set", [&]() { mode.update(garbage); });
         }

         mode.start(mutate_vec(nonce, rng));
         mode.reset();

         if(is_ctr == false) {
            result.test_throws("Cannot process data until nonce is set (after start/reset)",
                               [&]() { mode.update(garbage); });
         }

         mode.start(mutate_vec(nonce, rng));
         mode.update(garbage);

         mode.reset();

         mode.set_key(key);
         result.test_eq("key is set", mode.has_keying_material(), true);
         mode.start(nonce);

         Botan::secure_vector<uint8_t> buf;

         buf.assign(input.begin(), input.end());
         mode.finish(buf);
         result.test_eq(direction + " all-in-one", buf, expected);

         // additionally test update() and process() if possible
         if(input.size() >= update_granularity + min_final_bytes) {
            const size_t max_blocks_to_process = (input.size() - min_final_bytes) / update_granularity;
            const size_t bytes_to_process = max_blocks_to_process * update_granularity;

            // test update, 1 block at a time
            if(max_blocks_to_process > 1) {
               Botan::secure_vector<uint8_t> block(update_granularity);
               buf.clear();

               mode.start(nonce);
               for(size_t i = 0; i != max_blocks_to_process; ++i) {
                  block.assign(input.data() + i * update_granularity, input.data() + (i + 1) * update_granularity);

                  mode.update(block);
                  buf += block;
               }

               Botan::secure_vector<uint8_t> last_bits(input.data() + bytes_to_process, input.data() + input.size());
               mode.finish(last_bits);
               buf += last_bits;

               result.test_eq(direction + " update-1", buf, expected);
            }

            // test update with maximum length input
            buf.assign(input.data(), input.data() + bytes_to_process);
            Botan::secure_vector<uint8_t> last_bits(input.data() + bytes_to_process, input.data() + input.size());

            mode.start(nonce);
            mode.update(buf);
            mode.finish(last_bits);

            buf += last_bits;

            result.test_eq(direction + " update-all", buf, expected);

            // test process with maximum length input
            mode.start(nonce);
            buf.assign(input.begin(), input.end());

            const size_t bytes_written = mode.process(buf.data(), bytes_to_process);

            result.test_eq("correct number of bytes processed", bytes_written, bytes_to_process);

            mode.finish(buf, bytes_to_process);
            result.test_eq(direction + " process", buf, expected);
         }

         mode.clear();
         result.test_eq("key is not set", mode.has_keying_material(), false);

         result.test_throws("Unkeyed object throws after clear", [&]() {
            Botan::secure_vector<uint8_t> bad(update_granularity);
            mode.finish(bad);
         });
      }
};

BOTAN_REGISTER_SMOKE_TEST("modes", "cipher_modes", Cipher_Mode_Tests);

class Cipher_Mode_IV_Carry_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;
         results.push_back(test_cbc_iv_carry());
         results.push_back(test_cfb_iv_carry());
         results.push_back(test_ctr_iv_carry());
         return results;
      }

   private:
      static Test::Result test_cbc_iv_carry() {
         Test::Result result("CBC IV carry");

   #if defined(BOTAN_HAS_MODE_CBC) && defined(BOTAN_HAS_AES)
         std::unique_ptr<Botan::Cipher_Mode> enc(
            Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::Cipher_Dir::Encryption));
         std::unique_ptr<Botan::Cipher_Mode> dec(
            Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::Cipher_Dir::Decryption));

         const std::vector<uint8_t> key(16, 0xAA);
         const std::vector<uint8_t> iv(16, 0xAA);

         Botan::secure_vector<uint8_t> msg1 =
            Botan::hex_decode_locked("446F6E27742075736520706C61696E20434243206D6F6465");
         Botan::secure_vector<uint8_t> msg2 = Botan::hex_decode_locked("49562063617272796F766572");
         Botan::secure_vector<uint8_t> msg3 = Botan::hex_decode_locked("49562063617272796F76657232");

         enc->set_key(key);
         dec->set_key(key);

         enc->start(iv);
         enc->finish(msg1);
         result.test_eq("First ciphertext", msg1, "9BDD7300E0CB61CA71FFF957A71605DB6836159C36781246A1ADF50982757F4B");

         enc->start();
         enc->finish(msg2);

         result.test_eq("Second ciphertext", msg2, "AA8D682958A4A044735DAC502B274DB2");

         enc->start();
         enc->finish(msg3);

         result.test_eq("Third ciphertext", msg3, "1241B9976F73051BCF809525D6E86C25");

         dec->start(iv);
         dec->finish(msg1);

         dec->start();
         dec->finish(msg2);

         dec->start();
         dec->finish(msg3);
         result.test_eq("Third plaintext", msg3, "49562063617272796F76657232");

   #endif
         return result;
      }

      static Test::Result test_cfb_iv_carry() {
         Test::Result result("CFB IV carry");
   #if defined(BOTAN_HAS_MODE_CFB) && defined(BOTAN_HAS_AES)
         std::unique_ptr<Botan::Cipher_Mode> enc(
            Botan::Cipher_Mode::create("AES-128/CFB(8)", Botan::Cipher_Dir::Encryption));
         std::unique_ptr<Botan::Cipher_Mode> dec(
            Botan::Cipher_Mode::create("AES-128/CFB(8)", Botan::Cipher_Dir::Decryption));

         const std::vector<uint8_t> key(16, 0xAA);
         const std::vector<uint8_t> iv(16, 0xAB);

         Botan::secure_vector<uint8_t> msg1 = Botan::hex_decode_locked("ABCDEF01234567");
         Botan::secure_vector<uint8_t> msg2 = Botan::hex_decode_locked("0000123456ABCDEF");
         Botan::secure_vector<uint8_t> msg3 = Botan::hex_decode_locked("012345");

         enc->set_key(key);
         dec->set_key(key);

         enc->start(iv);
         enc->finish(msg1);
         result.test_eq("First ciphertext", msg1, "a51522387c4c9b");

         enc->start();
         enc->finish(msg2);

         result.test_eq("Second ciphertext", msg2, "105457dc2e0649d4");

         enc->start();
         enc->finish(msg3);

         result.test_eq("Third ciphertext", msg3, "53bd65");

         dec->start(iv);
         dec->finish(msg1);
         result.test_eq("First plaintext", msg1, "ABCDEF01234567");

         dec->start();
         dec->finish(msg2);
         result.test_eq("Second plaintext", msg2, "0000123456ABCDEF");

         dec->start();
         dec->finish(msg3);
         result.test_eq("Third plaintext", msg3, "012345");
   #endif
         return result;
      }

      static Test::Result test_ctr_iv_carry() {
         Test::Result result("CTR IV carry");
   #if defined(BOTAN_HAS_CTR_BE) && defined(BOTAN_HAS_AES)

         std::unique_ptr<Botan::Cipher_Mode> enc(
            Botan::Cipher_Mode::create("AES-128/CTR-BE", Botan::Cipher_Dir::Encryption));
         std::unique_ptr<Botan::Cipher_Mode> dec(
            Botan::Cipher_Mode::create("AES-128/CTR-BE", Botan::Cipher_Dir::Decryption));

         const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");
         const std::vector<uint8_t> iv = Botan::hex_decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");

         enc->set_key(key);
         dec->set_key(key);

         const std::vector<std::string> exp_ciphertext = {
            "EC",
            "8CDF",
            "739860",
            "7CB0F2D2",
            "1675EA9EA1",
            "E4362B7C3C67",
            "73516318A077D7",
            "FC5073AE6A2CC378",
            "7889374FBEB4C81B17",
            "BA6C44E89C399FF0F198C",
         };

         for(size_t i = 1; i != 10; ++i) {
            if(i == 1) {
               enc->start(iv);
               dec->start(iv);
            } else {
               enc->start();
               dec->start();
            }

            Botan::secure_vector<uint8_t> msg(i, 0);
            enc->finish(msg);

            result.test_eq("Ciphertext", msg, exp_ciphertext[i - 1].c_str());

            dec->finish(msg);

            for(size_t j = 0; j != msg.size(); ++j) {
               result.test_eq("Plaintext zeros", static_cast<size_t>(msg[j]), 0);
            }
         }
   #endif
         return result;
      }
};

BOTAN_REGISTER_TEST("modes", "iv_carryover", Cipher_Mode_IV_Carry_Tests);

#endif

}  // namespace Botan_Tests
