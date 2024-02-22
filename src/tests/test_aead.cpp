/*
* (C) 2014,2015,2016,2018 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_AEAD_MODES)
   #include <botan/aead.h>
   #include <botan/mem_ops.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_AEAD_MODES)

class AEAD_Tests final : public Text_Based_Test {
   public:
      AEAD_Tests() : Text_Based_Test("aead", "Key,In,Out", "Nonce,AD") {}

      static Test::Result test_enc(const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& nonce,
                                   const std::vector<uint8_t>& input,
                                   const std::vector<uint8_t>& expected,
                                   const std::vector<uint8_t>& ad,
                                   const std::string& algo,
                                   Botan::RandomNumberGenerator& rng) {
         const bool is_siv = algo.find("/SIV") != std::string::npos;

         Test::Result result(algo);

         auto enc = Botan::AEAD_Mode::create(algo, Botan::Cipher_Dir::Encryption);

         result.test_eq("AEAD encrypt output_length is correct", enc->output_length(input.size()), expected.size());

         result.confirm("AEAD name is not empty", !enc->name().empty());
         result.confirm("AEAD default nonce size is accepted", enc->valid_nonce_length(enc->default_nonce_length()));

         Botan::secure_vector<uint8_t> garbage = rng.random_vec(enc->update_granularity());

         if(is_siv == false) {
            result.test_throws("Unkeyed object throws for encrypt", [&]() { enc->update(garbage); });
         }

         result.test_throws("Unkeyed object throws for encrypt", [&]() { enc->finish(garbage); });

         if(enc->associated_data_requires_key()) {
            result.test_throws("Unkeyed object throws for set AD",
                               [&]() { enc->set_associated_data(ad.data(), ad.size()); });
         }

         result.test_eq("key is not set", enc->has_keying_material(), false);

         // Ensure that test resets AD and message state
         result.test_eq("key is not set", enc->has_keying_material(), false);
         enc->set_key(key);
         result.test_eq("key is set", enc->has_keying_material(), true);

         if(is_siv == false) {
            result.test_throws("Cannot process data until nonce is set (enc)", [&]() { enc->update(garbage); });
            result.test_throws("Cannot process data until nonce is set (enc)", [&]() { enc->finish(garbage); });
         }

         enc->set_associated_data(mutate_vec(ad, rng));
         enc->start(mutate_vec(nonce, rng));
         enc->update(garbage);

         // reset message specific state
         enc->reset();

         /*
         Now try to set the AD *after* setting the nonce
         For some modes this works, for others it does not.
         */
         enc->start(nonce);

         try {
            enc->set_associated_data(ad);
         } catch(Botan::Invalid_State&) {
            // ad after setting nonce rejected, in this case we need to reset
            enc->reset();
            enc->set_associated_data(ad);
            enc->start(nonce);
         }

         Botan::secure_vector<uint8_t> buf(input.begin(), input.end());

         // have to check here first if input is empty if not we can test update() and eventually process()
         if(buf.empty()) {
            enc->finish(buf);
            result.test_eq("encrypt with empty input", buf, expected);
         } else {
            // test finish() with full input
            enc->finish(buf);
            result.test_eq("encrypt full", buf, expected);

            // additionally test update() if possible
            const size_t update_granularity = enc->update_granularity();
            if(input.size() > update_granularity) {
               // reset state first
               enc->reset();

               enc->set_associated_data(ad);
               enc->start(nonce);

               buf.assign(input.begin(), input.end());
               size_t input_length = buf.size();
               uint8_t* p = buf.data();
               Botan::secure_vector<uint8_t> block(update_granularity);
               Botan::secure_vector<uint8_t> ciphertext;
               ciphertext.reserve(enc->output_length(buf.size()));
               while(input_length > update_granularity &&
                     ((input_length - update_granularity) >= enc->minimum_final_size())) {
                  block.assign(p, p + update_granularity);
                  enc->update(block);
                  p += update_granularity;
                  input_length -= update_granularity;

                  ciphertext.insert(ciphertext.end(), block.begin(), block.end());
               }

               // encrypt remaining bytes
               block.assign(p, p + input_length);
               enc->finish(block);
               ciphertext.insert(ciphertext.end(), block.begin(), block.end());

               result.test_eq("encrypt update", ciphertext, expected);
            }

            // additionally test process() if possible
            size_t min_final_bytes = enc->minimum_final_size();
            if(input.size() > (update_granularity + min_final_bytes)) {
               // again reset state first
               enc->reset();

               enc->set_associated_data(ad);
               enc->start(nonce);

               buf.assign(input.begin(), input.end());

               // we can process at max input.size()
               const size_t max_blocks_to_process = (input.size() - min_final_bytes) / update_granularity;
               const size_t bytes_to_process = max_blocks_to_process * update_granularity;

               const size_t bytes_written = enc->process(buf.data(), bytes_to_process);

               result.confirm("Process returns data unless requires_entire_message",
                              enc->requires_entire_message(),
                              bytes_written == 0);

               if(bytes_written == 0) {
                  // SIV case
                  buf.erase(buf.begin(), buf.begin() + bytes_to_process);
                  enc->finish(buf);
               } else {
                  result.test_eq("correct number of bytes processed", bytes_written, bytes_to_process);
                  enc->finish(buf, bytes_written);
               }

               result.test_eq("encrypt process", buf, expected);
            }
         }

         // Make sure we can set the AD after processing a message
         enc->set_associated_data(ad);
         enc->clear();
         result.test_eq("key is not set", enc->has_keying_material(), false);

         result.test_throws("Unkeyed object throws for encrypt after clear", [&]() { enc->finish(buf); });

         if(enc->associated_data_requires_key()) {
            result.test_throws("Unkeyed object throws for set AD after clear",
                               [&]() { enc->set_associated_data(ad.data(), ad.size()); });
         }

         return result;
      }

      static Test::Result test_dec(const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& nonce,
                                   const std::vector<uint8_t>& input,
                                   const std::vector<uint8_t>& expected,
                                   const std::vector<uint8_t>& ad,
                                   const std::string& algo,
                                   Botan::RandomNumberGenerator& rng) {
         const bool is_siv = algo.find("/SIV") != std::string::npos;

         Test::Result result(algo);

         auto dec = Botan::AEAD_Mode::create(algo, Botan::Cipher_Dir::Decryption);

         result.test_eq("AEAD decrypt output_length is correct", dec->output_length(input.size()), expected.size());

         Botan::secure_vector<uint8_t> garbage = rng.random_vec(dec->update_granularity());

         if(is_siv == false) {
            result.test_throws("Unkeyed object throws for decrypt", [&]() { dec->update(garbage); });
         }

         result.test_throws("Unkeyed object throws for decrypt", [&]() { dec->finish(garbage); });

         if(dec->associated_data_requires_key()) {
            result.test_throws("Unkeyed object throws for set AD",
                               [&]() { dec->set_associated_data(ad.data(), ad.size()); });
         }

         // First some tests for reset() to make sure it resets what we need it to
         // set garbage values
         result.test_eq("key is not set", dec->has_keying_material(), false);
         dec->set_key(key);
         result.test_eq("key is set", dec->has_keying_material(), true);
         dec->set_associated_data(mutate_vec(ad, rng));

         if(is_siv == false) {
            result.test_throws("Cannot process data until nonce is set (dec)", [&]() { dec->update(garbage); });
            result.test_throws("Cannot process data until nonce is set (dec)", [&]() { dec->finish(garbage); });
         }

         dec->start(mutate_vec(nonce, rng));

         dec->update(garbage);

         // reset message specific state
         dec->reset();

         Botan::secure_vector<uint8_t> buf(input.begin(), input.end());
         try {
            // now try to decrypt with correct values

            try {
               dec->start(nonce);
               dec->set_associated_data(ad);
            } catch(Botan::Invalid_State&) {
               // ad after setting nonce rejected, in this case we need to reset
               dec->reset();
               dec->set_associated_data(ad);
               dec->start(nonce);
            }

            // test finish() with full input
            dec->finish(buf);
            result.test_eq("decrypt full", buf, expected);

            // additionally test update() if possible
            const size_t update_granularity = dec->update_granularity();
            if(input.size() > update_granularity) {
               // reset state first
               dec->reset();

               dec->set_associated_data(ad);
               dec->start(nonce);

               buf.assign(input.begin(), input.end());
               size_t input_length = buf.size();
               uint8_t* p = buf.data();
               Botan::secure_vector<uint8_t> block(update_granularity);
               Botan::secure_vector<uint8_t> plaintext;
               plaintext.reserve(dec->output_length(buf.size()));
               while((input_length > update_granularity) &&
                     ((input_length - update_granularity) >= dec->minimum_final_size())) {
                  block.assign(p, p + update_granularity);
                  dec->update(block);
                  p += update_granularity;
                  input_length -= update_granularity;
                  plaintext.insert(plaintext.end(), block.begin(), block.end());
               }

               // decrypt remaining bytes
               block.assign(p, p + input_length);
               dec->finish(block);
               plaintext.insert(plaintext.end(), block.begin(), block.end());

               result.test_eq("decrypt update", plaintext, expected);
            }

            // additionally test process() if possible
            const size_t min_final_size = dec->minimum_final_size();
            if(input.size() > (update_granularity + min_final_size)) {
               // again reset state first
               dec->reset();

               dec->set_associated_data(ad);
               dec->start(nonce);

               buf.assign(input.begin(), input.end());

               // we can process at max input.size()
               const size_t max_blocks_to_process = (input.size() - min_final_size) / update_granularity;
               const size_t bytes_to_process = max_blocks_to_process * update_granularity;

               const size_t bytes_written = dec->process(buf.data(), bytes_to_process);

               result.confirm("Process returns data unless requires_entire_message",
                              dec->requires_entire_message(),
                              bytes_written == 0);

               if(bytes_written == 0) {
                  // SIV case
                  buf.erase(buf.begin(), buf.begin() + bytes_to_process);
                  dec->finish(buf);
               } else {
                  result.test_eq("correct number of bytes processed", bytes_written, bytes_to_process);
                  dec->finish(buf, bytes_to_process);
               }

               result.test_eq("decrypt process", buf, expected);
            }

         } catch(Botan::Exception& e) {
            result.test_failure("Failure processing AEAD ciphertext", e.what());
         }

         // test decryption with modified ciphertext
         const std::vector<uint8_t> mutated_input = mutate_vec(input, rng, true);
         buf.assign(mutated_input.begin(), mutated_input.end());

         dec->reset();

         dec->set_associated_data(ad);
         dec->start(nonce);

         try {
            dec->finish(buf);
            result.test_failure("accepted modified message", mutated_input);
         } catch(Botan::Integrity_Failure&) {
            result.test_success("correctly rejected modified message");
         } catch(std::exception& e) {
            result.test_failure("unexpected error while rejecting modified message", e.what());
         }

         // test decryption with modified nonce
         if(!nonce.empty()) {
            buf.assign(input.begin(), input.end());
            std::vector<uint8_t> bad_nonce = mutate_vec(nonce, rng);

            dec->reset();
            dec->set_associated_data(ad);
            dec->start(bad_nonce);

            try {
               dec->finish(buf);
               result.test_failure("accepted message with modified nonce", bad_nonce);
            } catch(Botan::Integrity_Failure&) {
               result.test_success("correctly rejected modified nonce");
            } catch(std::exception& e) {
               result.test_failure("unexpected error while rejecting modified nonce", e.what());
            }
         }

         // test decryption with modified associated_data
         const std::vector<uint8_t> bad_ad = mutate_vec(ad, rng, true);

         dec->reset();
         dec->set_associated_data(bad_ad);

         dec->start(nonce);

         try {
            buf.assign(input.begin(), input.end());
            dec->finish(buf);
            result.test_failure("accepted message with modified ad", bad_ad);
         } catch(Botan::Integrity_Failure&) {
            result.test_success("correctly rejected modified ad");
         } catch(std::exception& e) {
            result.test_failure("unexpected error while rejecting modified nonce", e.what());
         }

         // Make sure we can set the AD after processing a message
         dec->set_associated_data(ad);
         dec->clear();
         result.test_eq("key is not set", dec->has_keying_material(), false);

         result.test_throws("Unkeyed object throws for decrypt", [&]() { dec->finish(buf); });

         if(dec->associated_data_requires_key()) {
            result.test_throws("Unkeyed object throws for set AD",
                               [&]() { dec->set_associated_data(ad.data(), ad.size()); });
         }

         return result;
      }

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override {
         const std::vector<uint8_t> key = vars.get_req_bin("Key");
         const std::vector<uint8_t> nonce = vars.get_opt_bin("Nonce");
         const std::vector<uint8_t> input = vars.get_req_bin("In");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");
         const std::vector<uint8_t> ad = vars.get_opt_bin("AD");

         Test::Result result(algo);

         auto enc = Botan::AEAD_Mode::create(algo, Botan::Cipher_Dir::Encryption);
         auto dec = Botan::AEAD_Mode::create(algo, Botan::Cipher_Dir::Decryption);

         if(!enc || !dec) {
            result.note_missing(algo);
            return result;
         }

         // must be authenticated
         result.test_eq("Encryption algo is an authenticated mode", enc->authenticated(), true);
         result.test_eq("Decryption algo is an authenticated mode", dec->authenticated(), true);

         const std::string enc_provider = enc->provider();
         result.test_is_nonempty("enc provider", enc_provider);
         const std::string dec_provider = enc->provider();
         result.test_is_nonempty("dec provider", dec_provider);

         result.test_eq("same provider", enc_provider, dec_provider);

         // FFI currently requires this, so assure it is true for all modes
         result.test_gt("enc buffer sizes ok", enc->ideal_granularity(), enc->minimum_final_size());
         result.test_gt("dec buffer sizes ok", dec->ideal_granularity(), dec->minimum_final_size());

         result.test_gt("update granularity is non-zero", enc->update_granularity(), 0);

         result.test_eq(
            "enc and dec ideal granularity is the same", enc->ideal_granularity(), dec->ideal_granularity());

         result.test_gt(
            "ideal granularity is at least update granularity", enc->ideal_granularity(), enc->update_granularity());

         result.confirm("ideal granularity is a multiple of update granularity",
                        enc->ideal_granularity() % enc->update_granularity() == 0);

         // test enc
         result.merge(test_enc(key, nonce, input, expected, ad, algo, this->rng()));

         // test dec
         result.merge(test_dec(key, nonce, expected, input, ad, algo, this->rng()));

         return result;
      }
};

BOTAN_REGISTER_SERIALIZED_SMOKE_TEST("modes", "aead", AEAD_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
