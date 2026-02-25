/*
 * Tests for Crystals Dilithium
 * - KAT tests using the KAT vectors from
 *   https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/Dilithium-Round3.zip
 *
 * (C) 2022,2023 Jack Lloyd
 * (C) 2022 Manuel Glaser, Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "tests.h"

#include <iostream>  // TODO remove
#if defined(BOTAN_HAS_MLDSA_COMPOSITE)
   #include <botan/base64.h>
   #include <botan/hash.h>
   #include <botan/mldsa_comp.h>
   #include <botan/pk_algs.h>
   #include <botan/pubkey.h>

   #include "test_pubkey.h"
   #include "test_rng.h"

#endif

namespace Botan_Tests {
#if defined(BOTAN_HAS_MLDSA_COMPOSITE)

class MLDSA_Composite_KAT_Tests : public Text_Based_Test {
   public:
      // NOLINTNEXTLINE(*crtp-constructor-accessibility)
      MLDSA_Composite_KAT_Tests() :
            Text_Based_Test("pubkey/mldsa_composite.vec", "tcId,pk,x5c,sk,sk_pkcs8,s,sWithContext") {}

      // TODO: NEGATIVE TESTS WITH TOO SHORT PUBLIC AND PRIVATE KEYS
      Test::Result run_one_test(const std::string& name, const VarMap& vars) override {
         Test::Result result(name);
         std::cout << "test name = " << name << std::endl;
         const auto tcId = vars.get_req_str("tcId");
         std::cout << "tcId = " << tcId << std::endl;
         const auto pk = vars.get_req_str("pk");
         const auto pk_bin = Botan::base64_decode(pk);
         const auto comp_parm = Botan::MLDSA_Composite_Param::get_param_by_id_str(tcId);
         Botan::MLDSA_Composite_PublicKey pubkey(comp_parm.id, pk_bin);
         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "mldsa_composite_kat", MLDSA_Composite_KAT_Tests);

#endif
}  // namespace Botan_Tests
