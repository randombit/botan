/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_KDF_BASE)
   #include <botan/kdf.h>
#endif

#if defined(BOTAN_HAS_HKDF)
   #include <botan/hkdf.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_KDF_BASE)
class KDF_KAT_Tests final : public Text_Based_Test
   {
   public:
      KDF_KAT_Tests() : Text_Based_Test("kdf", "Salt,Secret,Label,Output", "IKM,XTS") {}

      Test::Result run_one_test(const std::string& kdf_name, const VarMap& vars) override
         {
         Test::Result result(kdf_name);

         std::unique_ptr<Botan::KDF> kdf(Botan::KDF::create(kdf_name));

         if(!kdf)
            {
            result.note_missing(kdf_name);
            return result;
            }

         const std::vector<uint8_t> salt = get_opt_bin(vars, "Salt");
         const std::vector<uint8_t> secret = get_req_bin(vars, "Secret");
         const std::vector<uint8_t> label = get_opt_bin(vars, "Label");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Output");

         result.test_eq("name", kdf->name(), kdf_name);
         result.test_eq("derived key", kdf->derive_key(expected.size(), secret, salt, label), expected);

         // Test that clone works
         std::unique_ptr<Botan::KDF> clone(kdf->clone());
         result.confirm("Clone has different pointer", kdf.get() != clone.get());
         result.test_eq("Clone has same name", kdf->name(), clone->name());

         return result;
         }

   };

BOTAN_REGISTER_TEST("kdf", KDF_KAT_Tests);

#endif

#if defined(BOTAN_HAS_HKDF)
class HKDF_Expand_Label_Tests final : public Text_Based_Test
   {
   public:
      HKDF_Expand_Label_Tests() :
         Text_Based_Test("hkdf_label.vec", "Secret,Label,HashValue,Output") {}

      Test::Result run_one_test(const std::string& hash_name, const VarMap& vars) override
         {
         Test::Result result("HKDF-Expand-Label(" + hash_name + ")");

         const std::vector<uint8_t> secret = get_req_bin(vars, "Secret");
         const std::vector<uint8_t> hashval = get_req_bin(vars, "HashValue");
         const std::string label = get_req_str(vars, "Label");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Output");

         Botan::secure_vector<uint8_t> output =
            Botan::hkdf_expand_label(hash_name,
                                     secret.data(), secret.size(),
                                     label,
                                     hashval.data(), hashval.size(),
                                     expected.size());

         result.test_eq("Output matches", output, expected);

         return result;
         }

   };

BOTAN_REGISTER_TEST("hkdf_expand_label", HKDF_Expand_Label_Tests);

#endif

}

}
