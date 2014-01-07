#include "tests.h"
#include "test_pubkey.h"

#include <botan/auto_rng.h>
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
   AutoSeeded_RNG rng;

   EC_Group group(OIDS::lookup(group_id));
   ECDSA_PrivateKey ecdsa(rng, group, BigInt(x));

   const std::string padding = "EMSA1(" + hash + ")";

   PK_Verifier verify(ecdsa, padding);
   PK_Signer sign(ecdsa, padding);

   return validate_signature(verify, sign, "DSA/" + hash, msg, nonce, signature);
   }

}

size_t test_ecdsa()
   {
   std::ifstream ecdsa_sig(TEST_DATA_DIR "/ecdsa.vec");

   size_t fails = 0;

   fails += run_tests_bb(ecdsa_sig, "ECDSA Signature", "Signature", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return ecdsa_sig_kat(m["Group"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
             });

   return fails;
   }

