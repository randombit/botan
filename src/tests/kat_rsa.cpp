#include "tests.h"
#include "test_pubkey.h"

#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t rsaes_kat(const std::string& e,
                 const std::string& p,
                 const std::string& q,
                 const std::string& msg,
                 std::string padding,
                 const std::string& nonce,
                 const std::string& output)
   {
   AutoSeeded_RNG rng;

   RSA_PrivateKey privkey(rng, BigInt(p), BigInt(q), BigInt(e));

   RSA_PublicKey pubkey = privkey;

   if(padding == "")
      padding = "Raw";

   PK_Encryptor_EME enc(pubkey, padding);
   PK_Decryptor_EME dec(privkey, padding);

   return validate_encryption(enc, dec, "RSAES/" + padding, msg, nonce, output);
   }

size_t rsa_sig_kat(const std::string& e,
                 const std::string& p,
                 const std::string& q,
                 const std::string& msg,
                 std::string padding,
                 const std::string& nonce,
                 const std::string& output)
   {
   AutoSeeded_RNG rng;

   RSA_PrivateKey privkey(rng, BigInt(p), BigInt(q), BigInt(e));

   RSA_PublicKey pubkey = privkey;

   if(padding == "")
      padding = "Raw";

   PK_Verifier verify(pubkey, padding);
   PK_Signer sign(privkey, padding);

   return validate_signature(verify, sign, "RSA/" + padding, msg, nonce, output);
   }

size_t rsa_sig_verify(const std::string& e,
                      const std::string& n,
                      const std::string& msg,
                      std::string padding,
                      const std::string& signature)
   {
   AutoSeeded_RNG rng;

   BigInt e_bn(e);
   BigInt n_bn(n);

   RSA_PublicKey key(n_bn, e_bn);

   if(padding == "")
      padding = "Raw";

   PK_Verifier verify(key, padding);

   if(!verify.verify_message(hex_decode(msg), hex_decode(signature)))
      return 1;
   return 0;
   }

}

size_t test_rsa()
   {
   std::ifstream rsa_enc(TEST_DATA_DIR "/rsaes.vec");
   std::ifstream rsa_sig(TEST_DATA_DIR "/rsa_sig.vec");
   std::ifstream rsa_verify(TEST_DATA_DIR "/rsa_verify.vec");

   size_t fails = 0;

   fails += run_tests_bb(rsa_enc, "RSA Encryption", "Ciphertext", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return rsaes_kat(m["E"], m["P"], m["Q"], m["Msg"],
                              m["Padding"], m["Nonce"], m["Ciphertext"]);
             });

   fails += run_tests_bb(rsa_sig, "RSA Signature", "Signature", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return rsa_sig_kat(m["E"], m["P"], m["Q"], m["Msg"],
                                m["Padding"], m["Nonce"], m["Signature"]);
             });

   fails += run_tests_bb(rsa_verify, "RSA Verify", "Signature", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return rsa_sig_verify(m["E"], m["N"], m["Msg"],
                                   m["Padding"], m["Signature"]);
             });

   return fails;
   }

