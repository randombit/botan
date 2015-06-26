/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)

#include "test_pubkey.h"

#include <botan/hex.h>
#include <botan/nr.h>
#include <botan/pubkey.h>
#include <botan/dl_group.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t nr_sig_kat(const std::string& p,
                   const std::string& q,
                   const std::string& g,
                   const std::string& x,
                   const std::string& hash,
                   const std::string& msg,
                   const std::string& nonce,
                   const std::string& signature)
   {
   auto& rng = test_rng();

   BigInt p_bn(p), q_bn(q), g_bn(g), x_bn(x);

   DL_Group group(p_bn, q_bn, g_bn);

   NR_PrivateKey privkey(rng, group, x_bn);

   NR_PublicKey pubkey = privkey;

   const std::string padding = "EMSA1(" + hash + ")";

   PK_Verifier verify(pubkey, padding);
   PK_Signer sign(privkey, padding);

   return validate_signature(verify, sign, "nr/" + hash, msg, rng, nonce, signature);
   }

}

size_t test_nr()
   {
   size_t fails = 0;

   std::ifstream nr_sig(PK_TEST_DATA_DIR "/nr.vec");

   fails += run_tests_bb(nr_sig, "NR Signature", "Signature", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return nr_sig_kat(m["P"], m["Q"], m["G"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
             });

   return fails;
   }

#else

SKIP_TEST(nr);

#endif // BOTAN_HAS_NYBERG_RUEPPEL
