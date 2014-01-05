#include "tests.h"
#include "test_pubkey.h"

#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/rw.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

const std::string padding = "EMSA2(SHA-1)";

size_t rw_sig_kat(const std::string& e,
                 const std::string& p,
                 const std::string& q,
                 const std::string& msg,
                 const std::string& signature)
   {
   AutoSeeded_RNG rng;

   RW_PrivateKey privkey(rng, BigInt(p), BigInt(q), BigInt(e));

   RW_PublicKey pubkey = privkey;

   PK_Verifier verify(pubkey, padding);
   PK_Signer sign(privkey, padding);

   return validate_signature(verify, sign, "RW/" + padding, msg, rng, signature);
   }

size_t rw_sig_verify(const std::string& e,
                      const std::string& n,
                      const std::string& msg,
                      const std::string& signature)
   {
   AutoSeeded_RNG rng;

   BigInt e_bn(e);
   BigInt n_bn(n);

   RW_PublicKey key(n_bn, e_bn);

   PK_Verifier verify(key, padding);

   if(!verify.verify_message(hex_decode(msg), hex_decode(signature)))
      return 1;
   return 0;
   }

}

size_t test_rw()
   {
   std::ifstream rw_sig(TEST_DATA_DIR "/rw_sig.vec");
   std::ifstream rw_verify(TEST_DATA_DIR "/rw_verify.vec");

   size_t fails = 0;

   fails += run_tests_bb(rw_sig, "RW Signature", "Signature", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return rw_sig_kat(m["E"], m["P"], m["Q"], m["Msg"], m["Signature"]);
             });

   fails += run_tests_bb(rw_verify, "RW Verify", "Signature", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return rw_sig_verify(m["E"], m["N"], m["Msg"], m["Signature"]);
             });

   return fails;
   }

