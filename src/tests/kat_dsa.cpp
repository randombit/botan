#include "tests.h"
#include "test_pubkey.h"

#include <botan/auto_rng.h>
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
   AutoSeeded_RNG rng;

   BigInt p_bn(p), q_bn(q), g_bn(g), x_bn(x);

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
   std::ifstream dsa_sig(PK_TEST_DATA_DIR "/dsa.vec");

   size_t fails = 0;

   fails += run_tests_bb(dsa_sig, "DSA Signature", "Signature", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return dsa_sig_kat(m["P"], m["Q"], m["G"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
             });

   return fails;
   }

