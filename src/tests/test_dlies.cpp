/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DLIES)

#include "test_pubkey.h"

#include <iostream>
#include <fstream>

#include <botan/dlies.h>
#include <botan/dh.h>
#include <botan/hex.h>
#include <botan/pubkey.h>
#include <botan/lookup.h>

using namespace Botan;

namespace {

size_t dlies_kat(const std::string& p,
                 const std::string& g,
                 const std::string& x1,
                 const std::string& x2,
                 const std::string& msg,
                 const std::string& ciphertext)
   {
   auto& rng = test_rng();

   BigInt p_bn(p);
   BigInt g_bn(g);
   BigInt x1_bn(x1);
   BigInt x2_bn(x2);

   DL_Group domain(p_bn, g_bn);

   DH_PrivateKey from(rng, domain, x1_bn);
   DH_PrivateKey to(rng, domain, x2_bn);

   const std::string opt_str = "KDF2(SHA-1)/HMAC(SHA-1)/16";

   std::vector<std::string> options = split_on(opt_str, '/');

   if(options.size() != 3)
      throw std::runtime_error("DLIES needs three options: " + opt_str);

   const size_t mac_key_len = to_u32bit(options[2]);

   DLIES_Encryptor e(from,
                     get_kdf(options[0]),
                     get_mac(options[1]),
                     mac_key_len);

   DLIES_Decryptor d(to,
                     get_kdf(options[0]),
                     get_mac(options[1]),
                     mac_key_len);

   e.set_other_key(to.public_value());

   const std::string empty = "";
   return validate_encryption(e, d, "DLIES", msg, empty, ciphertext);
   }

}

size_t test_dlies()
   {
   size_t fails = 0;

   std::ifstream dlies(PK_TEST_DATA_DIR "/dlies.vec");

   fails += run_tests_bb(dlies, "DLIES Encryption", "Ciphertext", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return dlies_kat(m["P"], m["G"], m["X1"], m["X2"], m["Msg"], m["Ciphertext"]);
             });

   return fails;
   }

#else

SKIP_TEST(dlies);

#endif // BOTAN_HAS_DLIES
