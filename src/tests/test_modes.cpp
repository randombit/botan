/*
* (C) 2014,2015 Jack Lloyd
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

class Cipher_Mode_Tests : public Text_Based_Test
   {
   public:
      Cipher_Mode_Tests() :
         Text_Based_Test("modes", "Key,Nonce,In,Out")
         {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> key      = get_req_bin(vars, "Key");
         const std::vector<uint8_t> nonce    = get_opt_bin(vars, "Nonce");
         const std::vector<uint8_t> input    = get_req_bin(vars, "In");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Out");

         Test::Result result(algo);

         std::unique_ptr<Botan::Cipher_Mode> enc(Botan::get_cipher_mode(algo, Botan::ENCRYPTION));
         std::unique_ptr<Botan::Cipher_Mode> dec(Botan::get_cipher_mode(algo, Botan::DECRYPTION));

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

         return result;
         }
   };

BOTAN_REGISTER_TEST("modes", Cipher_Mode_Tests);

#endif

}
