/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_GOST_34_10_2001)
   #include "test_pubkey.h"
   #include <botan/ec_group.h>
   #include <botan/gost_3410.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_GOST_34_10_2001)

class GOST_3410_2001_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override {
         std::vector<std::string> params;
         for(const auto& curve : {"gost_256A", "secp256r1"}) {
            if(Botan::EC_Group::supports_named_group(curve)) {
               params.push_back(curve);
            }
         }
         return params;
      }

      std::string algo_name() const override { return "GOST-34.10"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         const auto group = Botan::EC_Group(keygen_params);
         const auto public_key = Botan::EC_AffinePoint(group, raw_pk);
         return std::make_unique<Botan::GOST_3410_PublicKey>(group, public_key);
      }
};

BOTAN_REGISTER_TEST("pubkey", "gost_3410_keygen", GOST_3410_2001_Keygen_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
