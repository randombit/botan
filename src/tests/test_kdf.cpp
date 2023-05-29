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
   #include <botan/hash.h>
   #include <botan/internal/hkdf.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_KDF_BASE)
class KDF_KAT_Tests final : public Text_Based_Test {
   public:
      KDF_KAT_Tests() : Text_Based_Test("kdf", "Secret,Output", "Salt,Label,IKM,XTS") {}

      Test::Result run_one_test(const std::string& kdf_name, const VarMap& vars) override {
         Test::Result result(kdf_name);

         auto kdf = Botan::KDF::create(kdf_name);

         if(!kdf) {
            result.note_missing(kdf_name);
            return result;
         }

         const std::vector<uint8_t> salt = vars.get_opt_bin("Salt");
         const std::vector<uint8_t> secret = vars.get_req_bin("Secret");
         const std::vector<uint8_t> label = vars.get_opt_bin("Label");
         const std::vector<uint8_t> expected = vars.get_req_bin("Output");

         result.test_eq("name", kdf->name(), kdf_name);
         result.test_eq("derived key", kdf->derive_key(expected.size(), secret, salt, label), expected);

         // Test that clone works
         auto clone = kdf->new_object();
         result.confirm("Clone has different pointer", kdf.get() != clone.get());
         result.test_eq("Clone has same name", kdf->name(), clone->name());

         return result;
      }
};

BOTAN_REGISTER_SMOKE_TEST("kdf", "kdf_kat", KDF_KAT_Tests);

#endif

#if defined(BOTAN_HAS_HKDF)
class HKDF_Expand_Label_Tests final : public Text_Based_Test {
   public:
      HKDF_Expand_Label_Tests() : Text_Based_Test("hkdf_label.vec", "Secret,Label,HashValue,Output") {}

      Test::Result run_one_test(const std::string& hash_name, const VarMap& vars) override {
         Test::Result result("HKDF-Expand-Label(" + hash_name + ")");

         const std::vector<uint8_t> secret = vars.get_req_bin("Secret");
         const std::vector<uint8_t> hashval = vars.get_req_bin("HashValue");
         const std::string label = vars.get_req_str("Label");
         const std::vector<uint8_t> expected = vars.get_req_bin("Output");

         auto hash = Botan::HashFunction::create(hash_name);

         if(!hash) {
            result.test_note("Skipping test due to missing hash");
            return result;
         }

         Botan::secure_vector<uint8_t> output = Botan::hkdf_expand_label(
            hash_name, secret.data(), secret.size(), label, hashval.data(), hashval.size(), expected.size());

         result.test_eq("Output matches", output, expected);

         return result;
      }
};

BOTAN_REGISTER_TEST("kdf", "hkdf_expand_label", HKDF_Expand_Label_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
