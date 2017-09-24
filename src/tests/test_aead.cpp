/*
* (C) 2014,2015,2016 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_AEAD_MODES)
   #include <botan/aead.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_AEAD_MODES)

class AEAD_Tests final : public Text_Based_Test
   {
   public:
      AEAD_Tests() : Text_Based_Test("aead", "Key,Nonce,In,Out", "AD") {}

      Test::Result test_enc(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce,
                            const std::vector<uint8_t>& input, const std::vector<uint8_t>& expected,
                            const std::vector<uint8_t>& ad, const std::string& algo)
         {
         Test::Result result(algo);

         std::unique_ptr<Botan::AEAD_Mode> enc(Botan::get_aead(algo, Botan::ENCRYPTION));

         result.test_eq("AEAD encrypt output_length is correct", enc->output_length(input.size()), expected.size());

         result.confirm("AEAD name is not empty", !enc->name().empty());
         result.confirm("AEAD default nonce size is accepted", enc->valid_nonce_length(enc->default_nonce_length()));

         // First some tests for reset() to make sure it resets what we need it to
         // set garbage values
         enc->set_key(mutate_vec(key));
         enc->set_ad(mutate_vec(ad));
         enc->start(mutate_vec(nonce));

         Botan::secure_vector<uint8_t> garbage = Test::rng().random_vec(enc->update_granularity());
         enc->update(garbage);

         // reset message specific state
         enc->reset();

         // now try to encrypt with correct values
         enc->set_key(key);
         enc->set_ad(ad);
         enc->start(nonce);

         Botan::secure_vector<uint8_t> buf(input.begin(), input.end());

         // have to check here first if input is empty if not we can test update() and eventually process()
         if(buf.empty())
            {
            enc->finish(buf);
            result.test_eq("encrypt with empty input", buf, expected);
            }
         else
            {
            // test finish() with full input
            enc->finish(buf);
            result.test_eq("encrypt full", buf, expected);

            // additionally test update() if possible
            const size_t update_granularity = enc->update_granularity();
            if(input.size() > update_granularity)
               {
               // reset state first
               enc->reset();

               enc->set_ad(ad);
               enc->start(nonce);

               buf.assign(input.begin(), input.end());
               size_t input_length = buf.size();
               size_t offset = 0;
               uint8_t* p = buf.data();
               Botan::secure_vector<uint8_t> block(update_granularity);
               Botan::secure_vector<uint8_t> ciphertext(enc->output_length(buf.size()));
               while(input_length > update_granularity && ((input_length - update_granularity) >= enc->minimum_final_size()))
                  {
                  block.assign(p, p + update_granularity);
                  enc->update(block);
                  p += update_granularity;
                  input_length -= update_granularity;
                  buffer_insert(ciphertext, 0 + offset, block);
                  offset += block.size();
                  }

               // encrypt remaining bytes
               block.assign(p, p + input_length);
               enc->finish(block);
               buffer_insert(ciphertext, 0 + offset, block);

               result.test_eq("encrypt update", ciphertext, expected);
               }

            // additionally test process() if possible
            size_t min_final_bytes = enc->minimum_final_size();
            if(input.size() > (update_granularity + min_final_bytes))
               {
               // again reset state first
               enc->reset();

               enc->set_ad(ad);
               enc->start(nonce);

               buf.assign(input.begin(), input.end());

               // we can process at max input.size()
               const size_t max_blocks_to_process = (input.size() - min_final_bytes) / update_granularity;
               const size_t bytes_to_process = max_blocks_to_process * update_granularity;

               const size_t bytes_written = enc->process(buf.data(), bytes_to_process);

               if(bytes_written == 0)
                  {
                  // SIV case
                  buf.erase(buf.begin(), buf.begin() + bytes_to_process);
                  enc->finish(buf);
                  }
               else
                  {
                  result.test_eq("correct number of bytes processed", bytes_written, bytes_to_process);
                  enc->finish(buf, bytes_written);
                  }

               result.test_eq("encrypt process", buf, expected);
               }
            }
         return result;
         }

      Test::Result test_dec(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce,
                            const std::vector<uint8_t>& input, const std::vector<uint8_t>& expected,
                            const std::vector<uint8_t>& ad, const std::string& algo)
         {
         Test::Result result(algo);

         std::unique_ptr<Botan::AEAD_Mode> dec(Botan::get_aead(algo, Botan::DECRYPTION));

         result.test_eq("AEAD decrypt output_length is correct", dec->output_length(input.size()), expected.size());

         // First some tests for reset() to make sure it resets what we need it to
         // set garbage values
         dec->set_key(mutate_vec(key));
         dec->set_ad(mutate_vec(ad));
         dec->start(mutate_vec(nonce));

         Botan::secure_vector<uint8_t> garbage = Test::rng().random_vec(dec->update_granularity());
         dec->update(garbage);

         // reset message specific state
         dec->reset();

         Botan::secure_vector<uint8_t> buf(input.begin(), input.end());
         try
            {
            // now try to decrypt with correct values
            dec->set_key(key);
            dec->set_ad(ad);
            dec->start(nonce);

            // test finish() with full input
            dec->finish(buf);
            result.test_eq("decrypt full", buf, expected);

            // additionally test update() if possible
            const size_t update_granularity = dec->update_granularity();
            if(input.size() > update_granularity)
               {
               // reset state first
               dec->reset();

               dec->set_ad(ad);
               dec->start(nonce);

               buf.assign(input.begin(), input.end());
               size_t input_length = buf.size();
               size_t offset = 0;
               uint8_t* p = buf.data();
               Botan::secure_vector<uint8_t> block(update_granularity);
               Botan::secure_vector<uint8_t> plaintext(dec->output_length(buf.size()));
               while((input_length > update_granularity) && ((input_length - update_granularity) >= dec->minimum_final_size()))
                  {
                  block.assign(p, p + update_granularity);
                  dec->update(block);
                  p += update_granularity;
                  input_length -= update_granularity;
                  buffer_insert(plaintext, 0 + offset, block);
                  offset += block.size();
                  }

               // decrypt remaining bytes
               block.assign(p, p + input_length);
               dec->finish(block);
               buffer_insert(plaintext, 0 + offset, block);

               result.test_eq("decrypt update", plaintext, expected);
               }

            // additionally test process() if possible
            const size_t min_final_size = dec->minimum_final_size();
            if(input.size() > (update_granularity + min_final_size))
               {
               // again reset state first
               dec->reset();

               dec->set_ad(ad);
               dec->start(nonce);

               buf.assign(input.begin(), input.end());

               // we can process at max input.size()
               const size_t max_blocks_to_process = (input.size() - min_final_size) / update_granularity;
               const size_t bytes_to_process = max_blocks_to_process * update_granularity;

               const size_t bytes_written = dec->process(buf.data(), bytes_to_process);

               if(bytes_written == 0)
                  {
                  // SIV case
                  buf.erase(buf.begin(), buf.begin() + bytes_to_process);
                  dec->finish(buf);
                  }
               else
                  {
                  result.test_eq("correct number of bytes processed", bytes_written, bytes_to_process);
                  dec->finish(buf, bytes_to_process);
                  }

               result.test_eq("decrypt process", buf, expected);
               }

            }
         catch(Botan::Exception& e)
            {
            result.test_failure("Failure processing AEAD ciphertext", e.what());
            }

         // test decryption with modified ciphertext
         const std::vector<uint8_t> mutated_input = mutate_vec(input, true);
         buf.assign(mutated_input.begin(), mutated_input.end());

         dec->reset();

         dec->set_ad(ad);
         dec->start(nonce);

         try
            {
            dec->finish(buf);
            result.test_failure("accepted modified message", mutated_input);
            }
         catch(Botan::Integrity_Failure&)
            {
            result.test_success("correctly rejected modified message");
            }
         catch(std::exception& e)
            {
            result.test_failure("unexpected error while rejecting modified message", e.what());
            }

         // test decryption with modified nonce
         if(nonce.size() > 0)
            {
            buf.assign(input.begin(), input.end());
            std::vector<uint8_t> bad_nonce = mutate_vec(nonce);

            dec->reset();
            dec->set_ad(ad);
            dec->start(bad_nonce);

            try
               {
               dec->finish(buf);
               result.test_failure("accepted message with modified nonce", bad_nonce);
               }
            catch(Botan::Integrity_Failure&)
               {
               result.test_success("correctly rejected modified nonce");
               }
            catch(std::exception& e)
               {
               result.test_failure("unexpected error while rejecting modified nonce", e.what());
               }
            }

         // test decryption with modified associated_data
         const std::vector<uint8_t> bad_ad = mutate_vec(ad, true);

         dec->reset();
         dec->set_ad(bad_ad);

         dec->start(nonce);

         try
            {
            buf.assign(input.begin(), input.end());
            dec->finish(buf);
            result.test_failure("accepted message with modified ad", bad_ad);
            }
         catch(Botan::Integrity_Failure&)
            {
            result.test_success("correctly rejected modified ad");
            }
         catch(std::exception& e)
            {
            result.test_failure("unexpected error while rejecting modified nonce", e.what());
            }

         return result;
         }

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> key      = get_req_bin(vars, "Key");
         const std::vector<uint8_t> nonce    = get_opt_bin(vars, "Nonce");
         const std::vector<uint8_t> input    = get_req_bin(vars, "In");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Out");
         const std::vector<uint8_t> ad       = get_opt_bin(vars, "AD");

         Test::Result result(algo);

         std::unique_ptr<Botan::AEAD_Mode> enc(Botan::get_aead(algo, Botan::ENCRYPTION));
         std::unique_ptr<Botan::AEAD_Mode> dec(Botan::get_aead(algo, Botan::DECRYPTION));

         if(!enc || !dec)
            {
            result.note_missing(algo);
            return result;
            }

         // must be authenticated
         result.test_eq("Encryption algo is an authenticated mode", enc->authenticated(), true);
         result.test_eq("Decryption algo is an authenticated mode", dec->authenticated(), true);

         // test enc
         result.merge(test_enc(key, nonce, input, expected, ad, algo));

         // test dec
         result.merge(test_dec(key, nonce, expected, input, ad, algo));

         enc->clear();
         dec->clear();

         return result;
         }
   };

BOTAN_REGISTER_TEST("aead", AEAD_Tests);

#endif

}

}
