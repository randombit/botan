/*
* (C) 2014,2015,2017 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_MODES)
   #include <botan/cipher_mode.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_MODES)

class Cipher_Mode_Tests final : public Text_Based_Test
   {
   public:
      Cipher_Mode_Tests()
         : Text_Based_Test("modes", "Key,Nonce,In,Out") {}

      std::vector<std::string> possible_providers(const std::string& algo) override
         {
         return provider_filter(Botan::Cipher_Mode::providers(algo));
         }

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> key      = get_req_bin(vars, "Key");
         const std::vector<uint8_t> nonce    = get_opt_bin(vars, "Nonce");
         const std::vector<uint8_t> input    = get_req_bin(vars, "In");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Out");

         Test::Result result(algo);

         const std::vector<std::string> providers = possible_providers(algo);

         if(providers.empty())
            {
            result.note_missing("cipher mode " + algo);
            return result;
            }

         for(auto&& provider_ask : providers)
            {
            std::unique_ptr<Botan::Cipher_Mode> enc(Botan::get_cipher_mode(
                  algo, Botan::ENCRYPTION, provider_ask));
            std::unique_ptr<Botan::Cipher_Mode> dec(Botan::get_cipher_mode(
                  algo, Botan::DECRYPTION, provider_ask));

            if(!enc || !dec)
               {
               result.note_missing(algo);
               return result;
               }

            result.test_is_nonempty("provider", enc->provider());
            result.test_eq("name", enc->name(), algo);

            result.test_eq("mode not authenticated", enc->authenticated(), false);

            // Test to make sure reset() resets what we need it to
            enc->set_key(mutate_vec(key));
            Botan::secure_vector<uint8_t> garbage = Test::rng().random_vec(enc->update_granularity());
            enc->start(mutate_vec(nonce));
            enc->update(garbage);

            enc->reset();

            enc->set_key(key);
            enc->start(nonce);

            Botan::secure_vector<uint8_t> buf(input.begin(), input.end());
            // TODO: should first update if possible
            enc->finish(buf);
            result.test_eq("encrypt", buf, expected);

            // additionally test process() if possible
            size_t update_granularity = enc->update_granularity();
            size_t input_length = input.size();
            size_t min_final_bytes = enc->minimum_final_size();
            if(input_length > (update_granularity + min_final_bytes))
               {
               // reset state first
               enc->reset();

               enc->start(nonce);
               buf.assign(input.begin(), input.end());

               // we can process at max input_length
               const size_t max_blocks_to_process = (input_length - min_final_bytes) / update_granularity;
               const size_t bytes_to_process = max_blocks_to_process * update_granularity;

               const size_t bytes_written = enc->process(buf.data(), bytes_to_process);

               result.test_eq("correct number of bytes processed", bytes_written, bytes_to_process);

               enc->finish(buf, bytes_to_process);
               result.test_eq("encrypt", buf, expected);
               }

            // decryption
            buf.assign(expected.begin(), expected.end());

            // Test to make sure reset() resets what we need it to
            dec->set_key(mutate_vec(key));
            garbage = Test::rng().random_vec(dec->update_granularity());
            dec->start(mutate_vec(nonce));
            dec->update(garbage);

            dec->reset();

            dec->set_key(key);
            dec->start(nonce);
            dec->finish(buf);
            result.test_eq("decrypt", buf, input);

            // additionally test process() if possible
            update_granularity = dec->update_granularity();
            input_length = expected.size();
            min_final_bytes = dec->minimum_final_size();
            if(input_length > (update_granularity + min_final_bytes))
               {
               // reset state first
               dec->reset();

               dec->start(nonce);
               buf.assign(expected.begin(), expected.end());

               // we can process at max input_length
               const size_t max_blocks_to_process = (input_length - min_final_bytes) / update_granularity;
               const size_t bytes_to_process = max_blocks_to_process * update_granularity;

               const size_t bytes_written = dec->process(buf.data(), bytes_to_process);

               result.test_eq("correct number of bytes processed", bytes_written, bytes_to_process);

               dec->finish(buf, bytes_to_process);
               result.test_eq("decrypt", buf, input);
               }

            enc->clear();
            dec->clear();
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("modes", Cipher_Mode_Tests);

class Cipher_Mode_IV_Carry_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;
         results.push_back(test_cbc_iv_carry());
         results.push_back(test_cfb_iv_carry());
         results.push_back(test_ctr_iv_carry());
         return results;
         }

   private:
      Test::Result test_cbc_iv_carry()
         {
         Test::Result result("CBC IV carry");

#if defined(BOTAN_HAS_MODE_CBC) && defined(BOTAN_HAS_AES)
         std::unique_ptr<Botan::Cipher_Mode> enc(
            Botan::get_cipher_mode("AES-128/CBC/PKCS7", Botan::ENCRYPTION));
         std::unique_ptr<Botan::Cipher_Mode> dec(
            Botan::get_cipher_mode("AES-128/CBC/PKCS7", Botan::DECRYPTION));

         const std::vector<uint8_t> key(16, 0xAA);
         const std::vector<uint8_t> iv(16, 0xAA);

         Botan::secure_vector<uint8_t> msg1 =
            Botan::hex_decode_locked("446F6E27742075736520706C61696E20434243206D6F6465");
         Botan::secure_vector<uint8_t> msg2 =
            Botan::hex_decode_locked("49562063617272796F766572");
         Botan::secure_vector<uint8_t> msg3 =
            Botan::hex_decode_locked("49562063617272796F76657232");

         enc->set_key(key);
         dec->set_key(key);

         enc->start(iv);
         enc->finish(msg1);
         result.test_eq("First ciphertext", msg1,
                        "9BDD7300E0CB61CA71FFF957A71605DB6836159C36781246A1ADF50982757F4B");

         enc->start();
         enc->finish(msg2);

         result.test_eq("Second ciphertext", msg2,
                        "AA8D682958A4A044735DAC502B274DB2");

         enc->start();
         enc->finish(msg3);

         result.test_eq("Third ciphertext", msg3,
                        "1241B9976F73051BCF809525D6E86C25");

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

      Test::Result test_cfb_iv_carry()
         {
         Test::Result result("CFB IV carry");
#if defined(BOTAN_HAS_MODE_CFB) && defined(BOTAN_HAS_AES)
         std::unique_ptr<Botan::Cipher_Mode> enc(
            Botan::get_cipher_mode("AES-128/CFB(8)", Botan::ENCRYPTION));
         std::unique_ptr<Botan::Cipher_Mode> dec(
            Botan::get_cipher_mode("AES-128/CFB(8)", Botan::DECRYPTION));

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

      Test::Result test_ctr_iv_carry()
         {
         Test::Result result("CTR IV carry");
#if defined(BOTAN_HAS_CTR_BE) && defined(BOTAN_HAS_AES)

         std::unique_ptr<Botan::Cipher_Mode> enc(
            Botan::get_cipher_mode("AES-128/CTR-BE", Botan::ENCRYPTION));
         std::unique_ptr<Botan::Cipher_Mode> dec(
            Botan::get_cipher_mode("AES-128/CTR-BE", Botan::DECRYPTION));

         const std::vector<uint8_t> key =
            Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");
         const std::vector<uint8_t> iv =
            Botan::hex_decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");

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

         for(size_t i = 1; i != 10; ++i)
            {
            if(i == 1)
               {
               enc->start(iv);
               dec->start(iv);
               }
            else
               {
               enc->start();
               dec->start();
               }

            Botan::secure_vector<uint8_t> msg(i, 0);
            enc->finish(msg);

            result.test_eq("Ciphertext", msg, exp_ciphertext[i-1].c_str());

            dec->finish(msg);

            for(size_t j = 0; j != msg.size(); ++j)
               result.test_eq("Plaintext zeros", static_cast<size_t>(msg[j]), 0);

            }
#endif
         return result;
         }
   };


BOTAN_REGISTER_TEST("iv_carryover", Cipher_Mode_IV_Carry_Tests);

#endif

}
