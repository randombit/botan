#include "tests.h"
#include "test_pubkey.h"

#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/dh.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t dh_sig_kat(const std::string& p,
                  const std::string& g,
                  const std::string& x,
                  const std::string& y,
                  std::string kdf,
                  const std::string& outlen,
                  const std::string& key)
   {
   AutoSeeded_RNG rng;

   BigInt p_bn(p), g_bn(g), x_bn(x), y_bn(y);

   DL_Group domain(p_bn, g_bn);

   DH_PrivateKey mykey(rng, domain, x_bn);
   DH_PublicKey otherkey(domain, y_bn);

   if(kdf == "")
      kdf = "Raw";

   size_t keylen = 0;
   if(outlen != "")
      keylen = to_u32bit(outlen);

   PK_Key_Agreement kas(mykey, kdf);

   return validate_kas(kas, "DH/" + kdf, otherkey.public_value(), key, keylen);
   }

}

size_t test_dh()
   {
   std::ifstream dh_sig(TEST_DATA_DIR "/dh.vec");

   size_t fails = 0;

   fails += run_tests_bb(dh_sig, "DH Kex", "K", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return dh_sig_kat(m["P"], m["G"], m["X"], m["Y"], m["KDF"], m["OutLen"], m["K"]);
             });

   return fails;
   }

