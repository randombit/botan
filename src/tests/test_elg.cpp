#include "tests.h"
#include "test_pubkey.h"

#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/elgamal.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t elgamal_kat(const std::string& p,
                   const std::string& g,
                   const std::string& x,
                   const std::string& msg,
                   std::string padding,
                   const std::string& nonce,
                   const std::string& ciphertext)
   {
   AutoSeeded_RNG rng;

   const BigInt p_bn = BigInt(p);
   const BigInt g_bn = BigInt(g);
   const BigInt x_bn = BigInt(x);

   DL_Group group(p_bn, g_bn);
   ElGamal_PrivateKey privkey(rng, group, x_bn);

   ElGamal_PublicKey pubkey = privkey;

   if(padding == "")
      padding = "Raw";

   PK_Encryptor_EME enc(pubkey, padding);
   PK_Decryptor_EME dec(privkey, padding);

   return validate_encryption(enc, dec, "ElGamal/" + padding, msg, nonce, ciphertext);
   }

}

size_t test_elgamal()
   {
   std::ifstream elgamal_enc(TEST_DATA_DIR "/elgamal.vec");

   size_t fails = 0;

   fails += run_tests_bb(elgamal_enc, "ElGamal Encryption", "Ciphertext", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return elgamal_kat(m["P"], m["G"], m["X"], m["Msg"],
                              m["Padding"], m["Nonce"], m["Ciphertext"]);
             });

   return fails;
   }

