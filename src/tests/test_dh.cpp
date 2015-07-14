/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)

#include "test_pubkey.h"

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
   auto& rng = test_rng();

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
   size_t fails = 0;

   std::ifstream dh_sig(TEST_DATA_DIR_PK "/dh.vec");

   fails += run_tests_bb(dh_sig, "DH Kex", "K", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return dh_sig_kat(m["P"], m["G"], m["X"], m["Y"], m["KDF"], m["OutLen"], m["K"]);
             });

   return fails;
   }

#else

SKIP_TEST(dh);

#endif // BOTAN_HAS_DIFFIE_HELLMAN
