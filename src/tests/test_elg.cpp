/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elgamal.h>
  #include "test_pubkey.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ELGAMAL)

class ElGamal_KAT_Tests : public PK_Encryption_Decryption_Test {
public:
  ElGamal_KAT_Tests() : PK_Encryption_Decryption_Test(
      "ElGamal",
      "pubkey/elgamal.vec",
      "P,G,X,Msg,Nonce,Ciphertext",
      "Padding")
  {}

  std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
    const Botan::BigInt p = get_req_bn(vars, "P");
    const Botan::BigInt g = get_req_bn(vars, "G");
    const Botan::BigInt x = get_req_bn(vars, "X");

    const Botan::DL_Group grp(p, g);

    std::unique_ptr<Botan::Private_Key> key(new Botan::ElGamal_PrivateKey(Test::rng(), grp, x));
    return key;
  }
};

class ElGamal_Keygen_Tests : public PK_Key_Generation_Test {
public:
  std::vector<std::string> keygen_params() const override { return { "modp/ietf/1024", "modp/ietf/2048" }; }
  std::string algo_name() const override { return "ElGamal"; }
};

BOTAN_REGISTER_TEST("elgamal_encrypt", ElGamal_KAT_Tests);
BOTAN_REGISTER_TEST("elgamal_keygen", ElGamal_Keygen_Tests);

#endif

}

}
