/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_AEAD_SIV)
   #include <botan/aead.h>
   #include <botan/parsing.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_AEAD_SIV)

class SIV_Tests final : public Text_Based_Test
   {
   public:
      SIV_Tests() : Text_Based_Test("siv_ad.vec", "Key,Nonce,ADs,In,Out") {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> key      = vars.get_req_bin("Key");
         const std::vector<uint8_t> nonce    = vars.get_opt_bin("Nonce");
         const std::vector<uint8_t> input    = vars.get_req_bin("In");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");
         const std::vector<std::string> ad_list =
            Botan::split_on(vars.get_req_str("ADs"), ',');

         const std::string siv_name = algo + "/SIV";

         Test::Result result(siv_name);

         auto siv = Botan::AEAD_Mode::create(siv_name, Botan::ENCRYPTION);

         if(!siv)
            {
            result.test_note("Skipping test due to missing cipher");
            return result;
            }

         siv->set_key(key);

         for(size_t i = 0; i != ad_list.size(); ++i)
            {
            std::vector<uint8_t> ad = Botan::hex_decode(ad_list[i]);
            siv->set_associated_data_n(i, ad.data(), ad.size());
            }

         Botan::secure_vector<uint8_t> buf(input.begin(), input.end());
         siv->start(nonce);
         siv->finish(buf, 0);

         result.test_eq("SIV ciphertext", buf, expected);

         return result;
         }

   };

BOTAN_REGISTER_TEST("modes", "siv_ad", SIV_Tests);

#endif

}

}
