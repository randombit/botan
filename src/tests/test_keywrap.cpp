/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_RFC3394_KEYWRAP)
   #include <botan/rfc3394.h>
#endif

#if defined(BOTAN_HAS_NIST_KEYWRAP)
   #include <botan/nist_keywrap.h>
   #include <botan/block_cipher.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_RFC3394_KEYWRAP)
class RFC3394_Keywrap_Tests final : public Text_Based_Test
   {
   public:
      RFC3394_Keywrap_Tests() : Text_Based_Test("keywrap/rfc3394.vec", "Key,KEK,Output") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("RFC3394 keywrap");

         try
            {
            const std::vector<uint8_t> expected = vars.get_req_bin("Output");
            const std::vector<uint8_t> key = vars.get_req_bin("Key");
            const std::vector<uint8_t> kek = vars.get_req_bin("KEK");

            const Botan::SymmetricKey kek_sym(kek);
            const Botan::secure_vector<uint8_t> key_l(key.begin(), key.end());
            const Botan::secure_vector<uint8_t> exp_l(expected.begin(), expected.end());

            result.test_eq("encryption", Botan::rfc3394_keywrap(key_l, kek_sym), expected);
            result.test_eq("decryption", Botan::rfc3394_keyunwrap(exp_l, kek_sym), key);
            }
         catch(std::exception& e)
            {
            result.test_failure("", e.what());
            }

         return result;
         }

   };

BOTAN_REGISTER_TEST("keywrap", "rfc3394", RFC3394_Keywrap_Tests);
#endif

#if defined(BOTAN_HAS_NIST_KEYWRAP) && defined(BOTAN_HAS_AES)

class NIST_Keywrap_Tests final : public Text_Based_Test
   {
   public:
      NIST_Keywrap_Tests() : Text_Based_Test("keywrap/nist_key_wrap.vec", "Input,Key,Output") {}

      Test::Result run_one_test(const std::string& typ, const VarMap& vars) override
         {
         Test::Result result("NIST keywrap");

         try
            {
            if(typ != "KW" && typ != "KWP")
               throw Test_Error("Unknown type in NIST key wrap tests");

            const std::vector<uint8_t> expected = vars.get_req_bin("Output");
            const std::vector<uint8_t> input = vars.get_req_bin("Input");
            const std::vector<uint8_t> key = vars.get_req_bin("Key");

            std::unique_ptr<Botan::BlockCipher> bc =
               Botan::BlockCipher::create_or_throw("AES-" + std::to_string(key.size()*8));

            bc->set_key(key);

            std::vector<uint8_t> wrapped;

            if(typ == "KW")
               {
               wrapped = nist_key_wrap(input.data(), input.size(), *bc);
               }
            else if(typ == "KWP")
               {
               wrapped = nist_key_wrap_padded(input.data(), input.size(), *bc);
               }

            result.test_eq("key wrap", wrapped, expected);

            try
               {
               Botan::secure_vector<uint8_t> unwrapped;
               if(typ == "KW")
                  {
                  unwrapped = nist_key_unwrap(expected.data(), expected.size(), *bc);
                  }
               else if(typ == "KWP")
                  {
                  unwrapped = nist_key_unwrap_padded(expected.data(), expected.size(), *bc);
                  }

               result.test_eq("key unwrap", unwrapped, input);
               }
            catch(Botan::Integrity_Failure& e)
               {
               result.test_failure("NIST key unwrap failed with integrity failure", e.what());
               }
            }
         catch(std::exception& e)
            {
            result.test_failure("", e.what());
            }

         return result;
         }

   };

BOTAN_REGISTER_TEST("keywrap", "nist_key_wrap", NIST_Keywrap_Tests);

class NIST_Keywrap_Invalid_Tests final : public Text_Based_Test
   {
   public:
      NIST_Keywrap_Invalid_Tests() : Text_Based_Test("keywrap/nist_key_wrap_invalid.vec", "Key,Input") {}

      Test::Result run_one_test(const std::string& typ, const VarMap& vars) override
         {
         Test::Result result("NIST keywrap (invalid inputs)");

         try
            {
            if(typ != "KW" && typ != "KWP")
               throw Test_Error("Unknown type in NIST key wrap tests");

            const std::vector<uint8_t> input = vars.get_req_bin("Input");
            const std::vector<uint8_t> key = vars.get_req_bin("Key");

            std::unique_ptr<Botan::BlockCipher> bc =
               Botan::BlockCipher::create_or_throw("AES-" + std::to_string(key.size()*8));

            bc->set_key(key);

            try
               {
               Botan::secure_vector<uint8_t> unwrapped;
               if(typ == "KW")
                  {
                  unwrapped = nist_key_unwrap(input.data(), input.size(), *bc);
                  }
               else if(typ == "KWP")
                  {
                  unwrapped = nist_key_unwrap_padded(input.data(), input.size(), *bc);
                  }

               result.test_failure("Was able to unwrap invalid keywrap input");
               }
            catch(Botan::Integrity_Failure&)
               {
               result.test_success("Rejected invalid input");
               }
            }
         catch(std::exception& e)
            {
            result.test_failure("", e.what());
            }

         return result;
         }

   };

BOTAN_REGISTER_TEST("keywrap", "nist_key_wrap_invalid", NIST_Keywrap_Invalid_Tests);
#endif

}

}
