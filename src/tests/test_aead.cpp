/*
* (C) 2014,2015,2016 Jack Lloyd
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

class AEAD_Tests : public Text_Based_Test
   {
   public:
      AEAD_Tests() :
         Text_Based_Test("aead", {"Key", "Nonce", "In", "Out"}, {"AD"})
         {}

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

         enc->set_key(key);
         enc->set_associated_data_vec(ad);
         enc->start(nonce);

         Botan::secure_vector<uint8_t> buf(input.begin(), input.end());
         // TODO: should first update if possible
         enc->finish(buf);

         result.test_eq("encrypt", buf, expected);

         buf.assign(expected.begin(), expected.end());

         try
            {
            dec->set_key(key);
            dec->set_associated_data_vec(ad);
            dec->start(nonce);
            dec->finish(buf);
            }
         catch(Botan::Exception& e)
            {
            result.test_failure("Failure processing AEAD ciphertext");
            }

         if(enc->authenticated())
            {
            const std::vector<byte> mutated_input = mutate_vec(expected, true);
            buf.assign(mutated_input.begin(), mutated_input.end());

            dec->start(nonce);

            try
               {
               dec->finish(buf);
               result.test_failure("accepted modified message", mutated_input);
               }
            catch(Botan::Integrity_Failure&)
               {
               result.test_note("correctly rejected modified message");
               }
            catch(std::exception& e)
               {
               result.test_failure("unexpected error while rejecting modified message", e.what());
               }
            }

         if(nonce.size() > 0)
            {
            buf.assign(expected.begin(), expected.end());
            std::vector<byte> bad_nonce = mutate_vec(nonce);

            dec->start(bad_nonce);

            try
               {
               dec->finish(buf);
               result.test_failure("accepted message with modified nonce", bad_nonce);
               }
            catch(Botan::Integrity_Failure&)
               {
               result.test_note("correctly rejected modified nonce");
               }
            catch(std::exception& e)
               {
               result.test_failure("unexpected error while rejecting modified nonce", e.what());
               }
            }

         const std::vector<byte> bad_ad = mutate_vec(ad, true);

         dec->set_associated_data_vec(bad_ad);

         dec->start(nonce);

         try
            {
            buf.assign(expected.begin(), expected.end());
            dec->finish(buf);
            result.test_failure("accepted message with modified ad", bad_ad);
            }
         catch(Botan::Integrity_Failure&)
            {
            result.test_note("correctly rejected modified ad");
            }
         catch(std::exception& e)
            {
            result.test_failure("unexpected error while rejecting modified nonce", e.what());
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("aead", AEAD_Tests);

#endif

}

}
