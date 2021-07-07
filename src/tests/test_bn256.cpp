/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PAIRING_BN256)

#include <botan/bn256.h>
#include <botan/bigint.h>

namespace Botan_Tests {

class BN256_KAT : public Text_Based_Test
   {
   public:
      BN256_KAT() : Text_Based_Test("pairings/bn256.vec",
                                    "K1,K2,K3,P1,P2,P3,Q1,Q2,Q3,R")
         {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("BN256");

         const BigInt k1 = vars.get_req_bn("K1");
         const BigInt k2 = vars.get_req_bn("K2");
         const BigInt k3 = vars.get_req_bn("K3");

         Botan::BN_256 bn256;

         const Botan::BN_256::G1 p1 = bn256.g1_generator() * k1;
         const Botan::BN_256::G1 p2 = bn256.g1_generator() * k2;
         const Botan::BN_256::G1 p3 = bn256.g1_generator() * k3;

         result.confirm("p1 valid", p1.valid_element());
         result.confirm("p2 valid", p2.valid_element());
         result.confirm("p3 valid", p3.valid_element());

         result.test_eq("p1 kat", p1.serialize(), vars.get_req_bin("P1"));
         result.test_eq("p2 kat", p2.serialize(), vars.get_req_bin("P2"));
         result.test_eq("p3 kat", p3.serialize(), vars.get_req_bin("P3"));

         const Botan::BN_256::G2 q1 = bn256.g2_generator() * k1;
         const Botan::BN_256::G2 q2 = bn256.g2_generator() * k2;
         const Botan::BN_256::G2 q3 = bn256.g2_generator() * k3;

         result.confirm("q1 valid", q1.valid_element());
         result.confirm("q2 valid", q2.valid_element());
         result.confirm("q3 valid", q3.valid_element());

         result.test_eq("q1 kat", q1.serialize(), vars.get_req_bin("Q1"));
         result.test_eq("q2 kat", q2.serialize(), vars.get_req_bin("Q2"));
         result.test_eq("q3 kat", q3.serialize(), vars.get_req_bin("Q3"));

         const Botan::BN_256::GT r1 = bn256.pairing(p2, q3) * k1;

         const Botan::BN_256::GT r2 = bn256.pairing(p1, q3) * k2;
         const Botan::BN_256::GT r3 = bn256.pairing(p1, q2) * k3;

         const std::vector<uint8_t> r1_vec = r1.serialize();
         const std::vector<uint8_t> r2_vec = r2.serialize();
         const std::vector<uint8_t> r3_vec = r3.serialize();

         result.test_eq("r1 == r2", r1_vec, r2_vec);
         result.test_eq("r1 == r3", r1_vec, r3_vec);

         result.test_eq("Pairing matches expected", r1_vec, vars.get_req_bin("R"));

         return result;
         }
   };

BOTAN_REGISTER_TEST("pairings", "bn256", BN256_KAT);

}

#endif

