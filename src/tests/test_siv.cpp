/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_AEAD_SIV)
   #include <botan/siv.h>
   #include <botan/block_cipher.h>
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
         const std::vector<uint8_t> key      = get_req_bin(vars, "Key");
         const std::vector<uint8_t> nonce    = get_opt_bin(vars, "Nonce");
         const std::vector<uint8_t> input    = get_req_bin(vars, "In");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Out");
         const std::vector<std::string> ad_list =
            Botan::split_on(get_req_str(vars, "ADs"), ',');

         Test::Result result(algo + "/SIV");

         std::unique_ptr<Botan::SIV_Mode> siv(
            new Botan::SIV_Encryption(Botan::BlockCipher::create(algo).release()));

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

BOTAN_REGISTER_TEST("siv_ad", SIV_Tests);

#endif

}

}
