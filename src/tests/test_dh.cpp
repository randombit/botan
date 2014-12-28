#include "tests.h"
#include "test_pubkey.h"

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)

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
#endif

size_t test_dh()
   {
   size_t fails = 0;

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   std::ifstream dh_sig(PK_TEST_DATA_DIR "/dh.vec");

   fails += run_tests_bb(dh_sig, "DH Kex", "K", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return dh_sig_kat(m["P"], m["G"], m["X"], m["Y"], m["KDF"], m["OutLen"], m["K"]);
             });
#endif

   return fails;
   }

