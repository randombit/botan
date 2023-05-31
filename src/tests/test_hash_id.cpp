/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_HASH_ID) && defined(BOTAN_HAS_ASN1)
   #include <botan/asn1_obj.h>
   #include <botan/der_enc.h>
   #include <botan/internal/hash_id.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_HASH_ID) && defined(BOTAN_HAS_ASN1)

class PKCS_HashID_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         const std::vector<std::pair<std::string, size_t>> hash_id_fns = {
            {"MD5", 16},
            {"RIPEMD-160", 20},
            {"SHA-1", 20},
            {"SHA-224", 28},
            {"SHA-256", 32},
            {"SHA-384", 48},
            {"SHA-512", 64},
            {"SHA-512-256", 32},
            {"SHA-3(224)", 28},
            {"SHA-3(256)", 32},
            {"SHA-3(384)", 48},
            {"SHA-3(512)", 64},
            {"SM3", 32},
         };

         std::vector<Test::Result> results;

         for(const auto& hash_info : hash_id_fns) {
            const std::string hash_fn = hash_info.first;
            const size_t hash_len = hash_info.second;

            Test::Result result("PKCS hash id for " + hash_fn);

            try {
               const std::vector<uint8_t> pkcs_id = Botan::pkcs_hash_id(hash_fn);

               const Botan::OID oid = Botan::OID::from_string(hash_fn);
               const Botan::AlgorithmIdentifier alg(oid, Botan::AlgorithmIdentifier::USE_NULL_PARAM);
               const std::vector<uint8_t> dummy_hash(hash_len);

               std::vector<uint8_t> bits;
               Botan::DER_Encoder der(bits);
               der.start_sequence().encode(alg).encode(dummy_hash, Botan::ASN1_Type::OctetString).end_cons();

               result.test_eq("Dummy hash is expected size", bits.size() - pkcs_id.size(), dummy_hash.size());

               for(size_t i = pkcs_id.size(); i != bits.size(); ++i) {
                  if(bits[i] != 0) {
                     result.test_failure("Dummy hash had nonzero value");
                     break;
                  }
               }

               std::vector<uint8_t> encoded_id(bits.begin(), bits.begin() + pkcs_id.size());

               result.test_eq("Encoded ID matches hardcoded", encoded_id, pkcs_id);

            } catch(Botan::Exception& e) {
               result.test_failure(e.what());
            }

            results.push_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("pubkey", "pkcs_hash_id", PKCS_HashID_Test);
#endif

}  // namespace Botan_Tests
