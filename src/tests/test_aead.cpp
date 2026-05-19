/*
* (C) 2014,2015,2016,2018 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_AEAD_MODES)
   #include <botan/aead.h>
   #include <botan/exceptn.h>
   #include <botan/rng.h>
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

         result.test_sz_eq("AEAD encrypt output_length is correct", enc->output_length(input.size()), expected.size());

         result.test_is_true("AEAD name is not empty", !enc->name().empty());
         result.test_is_true("AEAD default nonce size is accepted",
                             enc->valid_nonce_length(enc->default_nonce_length()));

         auto get_garbage = [&] { return rng.random_vec(enc->update_granularity()); };

         if(!is_siv) {
            result.test_throws<Botan::Invalid_State>("Unkeyed object throws for encrypt", [&]() {
               auto garbage = get_garbage();
               enc->update(garbage);
            });
         }

         result.test_throws<Botan::Invalid_State>("Unkeyed object throws for encrypt", [&]() {
            auto garbage = get_garbage();
            enc->finish(garbage);
         });

         if(enc->associated_data_requires_key()) {
            result.test_throws<Botan::Invalid_State>("Unkeyed object throws for set AD",
                                                     [&]() { enc->set_associated_data(ad.data(), ad.size()); });
         }

         result.test_is_false("key is not set", enc->has_keying_material());

         // Ensure that test resets AD and message state
         result.test_is_false("key is not set", enc->has_keying_material());
         enc->set_key(key);
         result.test_is_true("key is set", enc->has_keying_material());

         if(!is_siv) {
            result.test_throws<Botan::Invalid_State>("Cannot process data until nonce is set (enc)", [&]() {
               auto garbage = get_garbage();
               enc->update(garbage);
            });
            result.test_throws<Botan::Invalid_State>("Cannot process data until nonce is set (enc)", [&]() {
               auto garbage = get_garbage();
               enc->finish(garbage);
            });
         }

         enc->set_associated_data(mutate_vec(ad, rng));
         enc->start(mutate_vec(nonce, rng));

         auto garbage = get_garbage();
         enc->update(garbage);

         // reset message specific state; AD persists per the AEAD contract
         enc->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)

         // Setting AD after start_msg must always throw
         enc->start(nonce);
         result.test_throws<Botan::Invalid_State>("set_associated_data after start_msg throws (enc)",
                                                  [&]() { enc->set_associated_data(ad); });

         // start_msg called twice without finish/reset must always throw.
         result.test_throws<Botan::Invalid_State>("double start_msg throws (enc)", [&]() { enc->start(nonce); });

         // Recover into the proper state for the actual encryption tests.
         enc->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)
         enc->set_associated_data(ad);
         enc->start(nonce);

         Botan::secure_vector<uint8_t> buf(input.begin(), input.end());

         // have to check here first if input is empty if not we can test update() and eventually process()
         if(buf.empty()) {
            enc->finish(buf);
            result.test_bin_eq("encrypt with empty input", buf, expected);
         } else {
            // test finish() with full input
            enc->finish(buf);
            result.test_bin_eq("encrypt full", buf, expected);

            // AD should be persisted between messages unless reset
            if(!ad.empty()) {
               enc->start(nonce);
               buf.assign(input.begin(), input.end());
               enc->finish(buf);
               result.test_bin_eq("AD persists across messages without re-setting", buf, expected);

               // AD must also persist across reset() per the AEAD contract:
               // reset() only resets message-specific state.
               enc->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)
               enc->start(nonce);
               buf.assign(input.begin(), input.end());
               enc->finish(buf);
               result.test_bin_eq("AD persists across reset()", buf, expected);
            }

            // additionally test update() if possible
            const size_t update_granularity = enc->update_granularity();
            if(input.size() > update_granularity) {
               // reset state first
               enc->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)

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

               result.test_bin_eq("encrypt update", ciphertext, expected);
            }

            // additionally test process() if possible
            const size_t min_final_bytes = enc->minimum_final_size();
            if(input.size() > (update_granularity + min_final_bytes)) {
               // again reset state first
               enc->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)

               enc->set_associated_data(ad);
               enc->start(nonce);

               buf.assign(input.begin(), input.end());

               // we can process at max input.size()
               const size_t max_blocks_to_process = (input.size() - min_final_bytes) / update_granularity;
               const size_t bytes_to_process = max_blocks_to_process * update_granularity;

               const size_t bytes_written = enc->process(buf.data(), bytes_to_process);

               if(enc->requires_entire_message()) {
                  result.test_sz_eq("If requires_entire_message then no output is produced", bytes_written, 0);
               } else {
                  result.test_sz_gt("If !requires_entire_message then some output is produced", bytes_written, 0);
               }

               if(bytes_written == 0) {
                  // SIV case
                  buf.erase(buf.begin(), buf.begin() + bytes_to_process);
                  enc->finish(buf);
               } else {
                  result.test_sz_eq("correct number of bytes processed", bytes_written, bytes_to_process);
                  enc->finish(buf, bytes_written);
               }

               result.test_bin_eq("encrypt process", buf, expected);
            }
         }

         // After reset, a new call to start must be made before finish is called.
         // Also verify that after the exception, the input buffer was not modified.
         if(!is_siv) {
            enc->start(nonce);
            enc->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)
            Botan::secure_vector<uint8_t> tmp(input.begin(), input.end());
            const Botan::secure_vector<uint8_t> tmp_orig = tmp;
            result.test_throws<Botan::Invalid_State>("finish after reset without start throws",
                                                     [&]() { enc->finish(tmp); });
            result.test_bin_eq("finish after reset leaves input buffer unmodified", tmp, tmp_orig);
         }

         // Verify that set_associated_data_n checks its index
         enc->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)
         {
            const size_t max_ad = enc->maximum_associated_data_inputs();
            if(max_ad > 0) {
               result.test_throws<Botan::Invalid_Argument>("set_associated_data_n rejects idx == max",
                                                           [&]() { enc->set_associated_data_n(max_ad, ad); });
            }
         }

         // Verify that finish() with an offset past the end of the buffer throws
         {
            enc->set_associated_data(ad);
            enc->start(nonce);
            result.test_throws<Botan::Invalid_Argument>("finish with offset > size throws", [&]() {
               Botan::secure_vector<uint8_t> tmp(input.begin(), input.end());
               enc->finish(tmp, tmp.size() + 1);
            });
            enc->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)
         }

         // Make sure we can set the AD after processing a message
         enc->set_associated_data(ad);
         enc->clear();
         result.test_is_false("key is not set", enc->has_keying_material());

         result.test_throws<Botan::Invalid_State>("Unkeyed object throws for encrypt after clear",
                                                  [&]() { enc->finish(buf); });

         if(enc->associated_data_requires_key()) {
            result.test_throws<Botan::Invalid_State>("Unkeyed object throws for set AD after clear",
                                                     [&]() { enc->set_associated_data(ad.data(), ad.size()); });
         }

         // Regression test: modes that advertise !associated_data_requires_key()
         // must retain AD set before keying. enc was just cleared above so it
         // is in an unkeyed state ready for this check.
         if(!enc->associated_data_requires_key()) {
            enc->set_associated_data(ad);
            enc->set_key(key);
            enc->start(nonce);
            Botan::secure_vector<uint8_t> tmp(input.begin(), input.end());
            enc->finish(tmp);
            result.test_bin_eq("AD set before key is retained", tmp, expected);
         }

         // Regression test: modes that advertise associated_data_requires_key()
         // must drop ALL key-dependent state on re-key, so that anything set
         // under one key cannot contaminate operations under another.
         if(enc->associated_data_requires_key()) {
            auto enc2 = Botan::AEAD_Mode::create(algo, Botan::Cipher_Dir::Encryption);
            const std::vector<uint8_t> stale_key(key.size(), 0x42);
            const std::vector<uint8_t> stale_ad{0xCC, 0xDD, 0xEE, 0xFF};
            enc2->set_key(stale_key);
            enc2->set_associated_data(stale_ad);

            // Populate per-nonce caches under the stale key. Crucially we
            // do not call finish_msg here, since that would clear the
            // caches via the mode's internal reset() and hide the bug.
            enc2->start(nonce);

            // Re-key, re-set AD, restart with the same nonce. After re-key,
            // every key-dependent piece of state must be dropped; the
            // ciphertext must match what a fresh instance would produce.
            enc2->set_key(key);
            enc2->set_associated_data(ad);
            enc2->start(nonce);
            Botan::secure_vector<uint8_t> tmp(input.begin(), input.end());
            enc2->finish(tmp);
            result.test_bin_eq("re-key drops all stale key-dependent state", tmp, expected);
         }

         // SIV-specific: after finish_msg, the nonce must not be carried
         // over. A subsequent finish_msg without an intervening start_msg
         // must run nonce-less SIV, not silently reuse the prior nonce.
         if(is_siv && !nonce.empty()) {
            auto siv_enc = Botan::AEAD_Mode::create(algo, Botan::Cipher_Dir::Encryption);
            siv_enc->set_key(key);
            siv_enc->set_associated_data(ad);
            siv_enc->start(nonce);
            Botan::secure_vector<uint8_t> with_nonce(input.begin(), input.end());
            siv_enc->finish(with_nonce);

            // No start_msg here.
            Botan::secure_vector<uint8_t> nonceless(input.begin(), input.end());
            siv_enc->finish(nonceless);

            // Compute the reference nonce-less ciphertext from a fresh
            // instance for the same (key, AD, input).
            auto siv_fresh = Botan::AEAD_Mode::create(algo, Botan::Cipher_Dir::Encryption);
            siv_fresh->set_key(key);
            siv_fresh->set_associated_data(ad);
            Botan::secure_vector<uint8_t> nonceless_ref(input.begin(), input.end());
            siv_fresh->finish(nonceless_ref);

            result.test_bin_eq("SIV nonce dropped after finish_msg", nonceless, nonceless_ref);
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

         result.test_sz_eq("AEAD decrypt output_length is correct", dec->output_length(input.size()), expected.size());

         auto get_garbage = [&] { return rng.random_vec(dec->update_granularity()); };
         auto get_ultimate_garbage = [&] { return rng.random_vec(dec->minimum_final_size()); };

         if(!is_siv) {
            result.test_throws<Botan::Invalid_State>("Unkeyed object throws for decrypt", [&]() {
               auto garbage = get_garbage();
               dec->update(garbage);
            });
         }

         result.test_throws<Botan::Invalid_State>("Unkeyed object throws for decrypt", [&]() {
            auto garbage = get_ultimate_garbage();
            dec->finish(garbage);
         });

         if(dec->associated_data_requires_key()) {
            result.test_throws<Botan::Invalid_State>("Unkeyed object throws for set AD",
                                                     [&]() { dec->set_associated_data(ad.data(), ad.size()); });
         }

         // First some tests for reset() to make sure it resets what we need it to
         // set garbage values
         result.test_is_false("key is not set", dec->has_keying_material());
         dec->set_key(key);
         result.test_is_true("key is set", dec->has_keying_material());
         dec->set_associated_data(mutate_vec(ad, rng));

         if(!is_siv) {
            result.test_throws<Botan::Invalid_State>("Cannot process data until nonce is set (dec)", [&]() {
               auto garbage = get_garbage();
               dec->update(garbage);
            });
            result.test_throws<Botan::Invalid_State>("Cannot process data until nonce is set (dec)", [&]() {
               auto garbage = get_ultimate_garbage();
               dec->finish(garbage);
            });
         }

         dec->start(mutate_vec(nonce, rng));
         auto garbage = get_garbage();
         dec->update(garbage);

         // reset message specific state; AD persists per the AEAD contract
         dec->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)

         // Setting AD after start_msg must always throw (uniform behavior).
         dec->start(nonce);
         result.test_throws<Botan::Invalid_State>("set_associated_data after start_msg throws (dec)",
                                                  [&]() { dec->set_associated_data(ad); });

         // start_msg called twice without finish/reset must always throw.
         result.test_throws<Botan::Invalid_State>("double start_msg throws (dec)", [&]() { dec->start(nonce); });

         dec->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)
         dec->set_associated_data(ad);
         dec->start(nonce);

         Botan::secure_vector<uint8_t> buf(input.begin(), input.end());
         try {
            // test finish() with full input
            dec->finish(buf);
            result.test_bin_eq("decrypt full", buf, expected);

            // Verify that AD is retained across messages
            if(!ad.empty()) {
               dec->start(nonce);
               buf.assign(input.begin(), input.end());
               dec->finish(buf);
               result.test_bin_eq("AD persists across messages without re-setting (dec)", buf, expected);

               // AD must also persist across reset() per the AEAD contract.
               dec->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)
               dec->start(nonce);
               buf.assign(input.begin(), input.end());
               dec->finish(buf);
               result.test_bin_eq("AD persists across reset() (dec)", buf, expected);
            }

            // additionally test update() if possible
            const size_t update_granularity = dec->update_granularity();
            if(input.size() > update_granularity) {
               // reset state first
               dec->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)

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

               result.test_bin_eq("decrypt update", plaintext, expected);
            }

            // additionally test process() if possible
            const size_t min_final_size = dec->minimum_final_size();
            if(input.size() > (update_granularity + min_final_size)) {
               // again reset state first
               dec->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)

               dec->set_associated_data(ad);
               dec->start(nonce);

               buf.assign(input.begin(), input.end());

               // we can process at max input.size()
               const size_t max_blocks_to_process = (input.size() - min_final_size) / update_granularity;
               const size_t bytes_to_process = max_blocks_to_process * update_granularity;

               const size_t bytes_written = dec->process(buf.data(), bytes_to_process);

               if(dec->requires_entire_message()) {
                  result.test_sz_eq("If requires_entire_message then no output is produced", bytes_written, 0);
               } else {
                  result.test_sz_gt("If !requires_entire_message then some output is produced", bytes_written, 0);
               }

               if(bytes_written == 0) {
                  // SIV case
                  buf.erase(buf.begin(), buf.begin() + bytes_to_process);
                  dec->finish(buf);
               } else {
                  result.test_sz_eq("correct number of bytes processed", bytes_written, bytes_to_process);
                  dec->finish(buf, bytes_to_process);
               }

               result.test_bin_eq("decrypt process", buf, expected);
            }

         } catch(Botan::Exception& e) {
            result.test_failure("Failure processing AEAD ciphertext", e.what());
         }

         // test decryption with modified ciphertext
         const std::vector<uint8_t> mutated_input = mutate_vec(input, rng, true);
         buf.assign(mutated_input.begin(), mutated_input.end());

         dec->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)

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

            dec->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)
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

         dec->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)
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

         // Verify that the mode checks `start` is called prior to `update`.
         // The state check must fire before the buffer is mutated.
         if(!is_siv) {
            dec->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)
            dec->set_associated_data(ad);
            dec->start(nonce);
            dec->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)
            Botan::secure_vector<uint8_t> tmp(input.begin(), input.end());
            const Botan::secure_vector<uint8_t> tmp_orig = tmp;
            result.test_throws<Botan::Invalid_State>("finish after reset without start throws (dec)",
                                                     [&]() { dec->finish(tmp); });
            result.test_bin_eq("finish after reset leaves input buffer unmodified (dec)", tmp, tmp_orig);
         }

         dec->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)
         {
            const size_t max_ad = dec->maximum_associated_data_inputs();
            if(max_ad > 0) {
               result.test_throws<Botan::Invalid_Argument>("set_associated_data_n rejects idx == max (dec)",
                                                           [&]() { dec->set_associated_data_n(max_ad, ad); });
            }
         }

         // Ensure that finish offsets are checked
         {
            dec->set_associated_data(ad);
            dec->start(nonce);
            result.test_throws<Botan::Invalid_Argument>("finish with offset > size throws (dec)", [&]() {
               Botan::secure_vector<uint8_t> tmp(input.begin(), input.end());
               dec->finish(tmp, tmp.size() + 1);
            });
            dec->reset();  // NOLINT(*-ambiguous-smartptr-reset-call)
         }

         // Make sure we can set the AD after processing a message
         dec->set_associated_data(ad);
         dec->clear();
         result.test_is_false("key is not set", dec->has_keying_material());

         result.test_throws<Botan::Invalid_State>("Unkeyed object throws for decrypt", [&]() { dec->finish(buf); });

         if(dec->associated_data_requires_key()) {
            result.test_throws<Botan::Invalid_State>("Unkeyed object throws for set AD",
                                                     [&]() { dec->set_associated_data(ad.data(), ad.size()); });
         }

         // Regression test: modes that advertise associated_data_requires_key()
         // == false must retain AD set before keying. dec was just cleared
         // above so it is in an unkeyed state ready for this check.
         if(!dec->associated_data_requires_key()) {
            dec->set_associated_data(ad);
            dec->set_key(key);
            dec->start(nonce);
            Botan::secure_vector<uint8_t> tmp(input.begin(), input.end());
            try {
               dec->finish(tmp);
               result.test_bin_eq("AD set before key is retained (dec)", tmp, expected);
            } catch(Botan::Exception& e) {
               result.test_failure("decrypt with AD set pre-key failed", e.what());
            }
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
         result.test_is_true("Encryption algo is an authenticated mode", enc->authenticated());
         result.test_is_true("Decryption algo is an authenticated mode", dec->authenticated());

         const std::string enc_provider = enc->provider();
         result.test_str_not_empty("enc provider", enc_provider);
         const std::string dec_provider = dec->provider();
         result.test_str_not_empty("dec provider", dec_provider);

         result.test_str_eq("same provider", enc_provider, dec_provider);

         // FFI currently requires this, so assure it is true for all modes
         result.test_sz_gt("enc buffer sizes ok", enc->ideal_granularity(), enc->minimum_final_size());
         result.test_sz_gt("dec buffer sizes ok", dec->ideal_granularity(), dec->minimum_final_size());

         result.test_sz_gt("update granularity is non-zero", enc->update_granularity(), 0);

         result.test_sz_eq(
            "enc and dec ideal granularity is the same", enc->ideal_granularity(), dec->ideal_granularity());

         result.test_sz_gt(
            "ideal granularity is at least update granularity", enc->ideal_granularity(), enc->update_granularity());

         result.test_is_true("ideal granularity is a multiple of update granularity",
                             enc->ideal_granularity() % enc->update_granularity() == 0);

         // test enc
         result.merge(test_enc(key, nonce, input, expected, ad, algo, this->rng()));

         // test dec
         // NOLINTNEXTLINE(*-suspicious-call-argument) Yes we are swapping ptext and ctext arguments here
         result.merge(test_dec(key, nonce, expected, input, ad, algo, this->rng()));

         return result;
      }
};

BOTAN_REGISTER_SERIALIZED_SMOKE_TEST("modes", "aead", AEAD_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
