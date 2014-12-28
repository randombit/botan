#include "tests.h"
#include "test_pubkey.h"

#if defined(BOTAN_HAS_ECDSA)

#include <botan/pubkey.h>
#include <botan/ecdsa.h>
#include <botan/oids.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t ecdsa_sig_kat(const std::string& group_id,
                     const std::string& x,
                     const std::string& hash,
                     const std::string& msg,
                     const std::string& nonce,
                     const std::string& signature)
   {
   auto& rng = test_rng();

   EC_Group group(OIDS::lookup(group_id));
   ECDSA_PrivateKey ecdsa(rng, group, BigInt(x));

   const std::string padding = "EMSA1(" + hash + ")";

   PK_Verifier verify(ecdsa, padding);
   PK_Signer sign(ecdsa, padding);

   return validate_signature(verify, sign, "DSA/" + hash, msg, rng, nonce, signature);
   }

size_t ecc_point_mul(const std::string& group_id,
                     const std::string& m_s,
                     const std::string& X_s,
                     const std::string& Y_s)
   {
   EC_Group group(OIDS::lookup(group_id));

   const BigInt m(m_s);
   const BigInt X(X_s);
   const BigInt Y(Y_s);

   PointGFp p = group.get_base_point() * m;

   size_t fails = 0;

   if(p.get_affine_x() != X)
      {
      std::cout << p.get_affine_x() << " != " << X << "\n";
      ++fails;
      }

   if(p.get_affine_y() != Y)
      {
      std::cout << p.get_affine_y() << " != " << Y << "\n";
      ++fails;
      }

   return fails;
   }

}

#endif

size_t test_ecc_pointmul()
   {
   size_t fails = 0;

#if defined(BOTAN_HAS_ECC_GROUP)
   std::ifstream ecc_mul(PK_TEST_DATA_DIR "/ecc.vec");

   fails += run_tests_bb(ecc_mul, "ECC Point Mult", "Y", false,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return ecc_point_mul(m["Group"], m["m"], m["X"], m["Y"]);
             });
#endif

   return fails;
   }

size_t test_ecdsa()
   {
   size_t fails = 0;

#if defined(BOTAN_HAS_ECDSA)
   std::ifstream ecdsa_sig(PK_TEST_DATA_DIR "/ecdsa.vec");

   fails += run_tests_bb(ecdsa_sig, "ECDSA Signature", "Signature", false,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return ecdsa_sig_kat(m["Group"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
             });
#endif

   return fails;
   }
