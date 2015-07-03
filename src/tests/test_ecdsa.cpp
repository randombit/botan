/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ECDSA)

#include "test_pubkey.h"

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

   return validate_signature(verify, sign, "ECDSA/" + group_id + '/' + hash,
                             msg, rng, nonce, signature);
   }

}

size_t test_ecdsa()
   {
   size_t fails = 0;

   std::ifstream ecdsa_sig(PK_TEST_DATA_DIR "/ecdsa.vec");

   fails += run_tests_bb(ecdsa_sig, "ECDSA Signature", "Signature", false,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return ecdsa_sig_kat(m["Group"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
             });

   return fails;
   }

#else

SKIP_TEST(ecdsa);

#endif // BOTAN_HAS_ECDSA
