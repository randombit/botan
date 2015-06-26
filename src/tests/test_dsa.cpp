/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DSA)

#include "test_pubkey.h"

#include <botan/pubkey.h>
#include <botan/dsa.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t dsa_sig_kat(const std::string& p,
                   const std::string& q,
                   const std::string& g,
                   const std::string& x,
                   const std::string& hash,
                   const std::string& msg,
                   const std::string& nonce,
                   const std::string& signature)
   {
   auto& rng = test_rng();

   BigInt p_bn("0x" + p), q_bn("0x" + q), g_bn("0x" + g), x_bn("0x" + x);

   DL_Group group(p_bn, q_bn, g_bn);
   DSA_PrivateKey privkey(rng, group, x_bn);

   DSA_PublicKey pubkey = privkey;

   const std::string padding = "EMSA1(" + hash + ")";

   PK_Verifier verify(pubkey, padding);
   PK_Signer sign(privkey, padding);

   return validate_signature(verify, sign, "DSA/" + hash, msg, rng, nonce, signature);
   }

}

size_t test_dsa()
   {
   size_t fails = 0;

   std::ifstream dsa_sig(PK_TEST_DATA_DIR "/dsa.vec");

   fails += run_tests_bb(dsa_sig, "DSA Signature", "Signature", false,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return dsa_sig_kat(m["P"], m["Q"], m["G"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
             });

   return fails;
   }

#else

SKIP_TEST(dsa);

#endif // BOTAN_HAS_DSA
