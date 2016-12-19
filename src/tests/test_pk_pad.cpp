/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PK_PADDING)
  #include <botan/emsa.h>
  #include <botan/eme.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_PK_PADDING)

class EME_Decoding_Tests : public Text_Based_Test
   {
   public:
      EME_Decoding_Tests() :
         Text_Based_Test("pk_pad_eme",
                         "RawCiphertext,ValidInput",
                         "Plaintext") {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         Test::Result result(algo + " Decoding");

         std::unique_ptr<Botan::EME> eme;

         try
            {
            eme.reset(Botan::get_eme(algo));
            }
         catch(Botan::Lookup_Error&)
            {
            result.note_missing(algo);
            return result;
            }

         const std::vector<uint8_t> ciphertext = get_req_bin(vars, "RawCiphertext");
         const std::vector<uint8_t> plaintext = get_opt_bin(vars, "Plaintext");
         const bool is_valid = get_req_bool(vars, "ValidInput");

         if(is_valid == false)
            result.test_eq("Plaintext value is empty for invalid EME inputs", plaintext.size(), 0);

         uint8_t valid_mask = 0;
         Botan::secure_vector<uint8_t> decoded =
            eme->unpad(valid_mask, ciphertext.data(), ciphertext.size());

         result.confirm("EME valid_mask has expected value", valid_mask == 0x00 || valid_mask == 0xFF);
         result.test_eq("EME decoding valid/invalid matches", valid_mask == 0xFF, is_valid);

         if(is_valid && valid_mask == 0xFF)
            {
            result.test_eq("EME decoded plaintext correct", decoded, plaintext);
            }

         // TODO: also test that encoding is accepted

         return result;
         }
   };

BOTAN_REGISTER_TEST("pk_pad_eme", EME_Decoding_Tests);

#endif

}


