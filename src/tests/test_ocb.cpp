/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_AEAD_OCB)
  #include <botan/ocb.h>
  #include <botan/loadstor.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_AEAD_OCB)

class OCB_Long_KAT_Tests : public Text_Based_Test
   {
   public:
      OCB_Long_KAT_Tests() : Text_Based_Test("ocb_long.vec",
                                             "Keylen,Taglen,Output") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         const size_t keylen = get_req_sz(vars, "Keylen");
         const size_t taglen = get_req_sz(vars, "Taglen");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Output");

         // Test from RFC 7253 Appendix A

         const std::string algo = "AES-" + std::to_string(keylen);

         Test::Result result("OCB long");

         std::unique_ptr<Botan::BlockCipher> aes(Botan::BlockCipher::create(algo));
         if(!aes)
            {
            result.note_missing(algo);
            return result;
            }

         Botan::OCB_Encryption enc(aes->clone(), taglen / 8);
         Botan::OCB_Decryption dec(aes->clone(), taglen / 8);

         std::vector<uint8_t> key(keylen/8);
         key[keylen/8-1] = taglen;

         enc.set_key(key);
         dec.set_key(key);

         const std::vector<uint8_t> empty;
         std::vector<uint8_t> N(12);
         std::vector<uint8_t> C;

         for(size_t i = 0; i != 128; ++i)
            {
            const std::vector<uint8_t> S(i);

            Botan::store_be(static_cast<uint32_t>(3*i+1), &N[8]);

            ocb_encrypt(result, C, enc, dec, N, S, S);
            Botan::store_be(static_cast<uint32_t>(3*i+2), &N[8]);
            ocb_encrypt(result, C, enc, dec, N, S, empty);
            Botan::store_be(static_cast<uint32_t>(3*i+3), &N[8]);
            ocb_encrypt(result, C, enc, dec, N, empty, S);
            }

         Botan::store_be(static_cast<uint32_t>(385), &N[8]);
         std::vector<uint8_t> final_result;
         ocb_encrypt(result, final_result, enc, dec, N, empty, C);

         result.test_eq("correct value", final_result, expected);

         return result;
         }
   private:
      void ocb_encrypt(Test::Result& result,
                       std::vector<uint8_t>& output_to,
                       Botan::OCB_Encryption& enc,
                       Botan::OCB_Decryption& dec,
                       const std::vector<uint8_t>& nonce,
                       const std::vector<uint8_t>& pt,
                       const std::vector<uint8_t>& ad)
         {
         enc.set_associated_data(ad.data(), ad.size());

         enc.start(nonce.data(), nonce.size());

         Botan::secure_vector<uint8_t> buf(pt.begin(), pt.end());
         enc.finish(buf, 0);
         output_to.insert(output_to.end(), buf.begin(), buf.end());

         try
            {
            dec.set_associated_data(ad.data(), ad.size());

            dec.start(nonce.data(), nonce.size());

            dec.finish(buf, 0);

            result.test_eq("OCB round tripped", buf, pt);
            }
         catch(std::exception& e)
            {
            result.test_failure("OCB round trip error", e.what());
            }

         }
   };

BOTAN_REGISTER_TEST("ocb_long", OCB_Long_KAT_Tests);

#endif

}

}

