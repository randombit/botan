#include "tests.h"
#include "test_pubkey.h"

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
  #include <botan/nr.h>
  #include <botan/auto_rng.h>
  #include <botan/pubkey.h>
  #include <botan/dl_group.h>
#endif

#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)

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
   AutoSeeded_RNG rng;

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
#endif

size_t test_nr()
   {
   size_t fails = 0;

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
   std::ifstream nr_sig(PK_TEST_DATA_DIR "/nr.vec");

   fails += run_tests_bb(nr_sig, "NR Signature", "Signature", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return nr_sig_kat(m["P"], m["Q"], m["G"], m["X"], m["Hash"], m["Msg"], m["Nonce"], m["Signature"]);
             });
#endif

   return fails;
   }

