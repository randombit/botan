/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_CURVE_25519)

#include "test_pubkey.h"

#include <botan/curve25519.h>
#include <botan/pkcs8.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t curve25519_scalar_kat(const std::string& secret_h,
                             const std::string& basepoint_h,
                             const std::string& out_h)
   {
   const std::vector<byte> secret = hex_decode(secret_h);
   const std::vector<byte> basepoint = hex_decode(basepoint_h);
   const std::vector<byte> out = hex_decode(out_h);

   std::vector<byte> got(32);
   curve25519_donna(got.data(), secret.data(), basepoint.data());

   if(got != out)
      {
      std::cout << "Got " << hex_encode(got) << " exp " << hex_encode(out) << std::endl;
      return 1;
      }

   return 0;
   }

size_t c25519_roundtrip()
   {
   auto& rng = test_rng();

   try
      {
      // First create keys
      Curve25519_PrivateKey a_priv_gen(rng);
      Curve25519_PrivateKey b_priv_gen(rng);

      const std::string a_pass = "alice pass";
      const std::string b_pass = "bob pass";

      // Then serialize to encrypted storage
      const auto pbe_time = std::chrono::milliseconds(10);
      const std::string a_priv_pem = PKCS8::PEM_encode(a_priv_gen, rng, a_pass, pbe_time);
      const std::string b_priv_pem = PKCS8::PEM_encode(b_priv_gen, rng, b_pass, pbe_time);

      // Reload back into memory
      DataSource_Memory a_priv_ds(a_priv_pem);
      DataSource_Memory b_priv_ds(b_priv_pem);

      std::unique_ptr<Private_Key> a_priv(PKCS8::load_key(a_priv_ds, rng, [a_pass]() { return a_pass; }));
      std::unique_ptr<Private_Key> b_priv(PKCS8::load_key(b_priv_ds, rng, b_pass));

      // Export public keys as PEM
      const std::string a_pub_pem = X509::PEM_encode(*a_priv);
      const std::string b_pub_pem = X509::PEM_encode(*b_priv);

      DataSource_Memory a_pub_ds(a_pub_pem);
      DataSource_Memory b_pub_ds(b_pub_pem);

      std::unique_ptr<Public_Key> a_pub(X509::load_key(a_pub_ds));
      std::unique_ptr<Public_Key> b_pub(X509::load_key(b_pub_ds));

      Curve25519_PublicKey* a_pub_key = dynamic_cast<Curve25519_PublicKey*>(a_pub.get());
      Curve25519_PublicKey* b_pub_key = dynamic_cast<Curve25519_PublicKey*>(b_pub.get());

      PK_Key_Agreement a_ka(*a_priv, "KDF2(SHA-256)");
      PK_Key_Agreement b_ka(*b_priv, "KDF2(SHA-256)");

      const std::string context = "shared context value";
      SymmetricKey a_key = a_ka.derive_key(32, b_pub_key->public_value(), context);
      SymmetricKey b_key = b_ka.derive_key(32, a_pub_key->public_value(), context);

      if(a_key != b_key)
         return 1;
      }
   catch(std::exception& e)
      {
      std::cout << "C25519 rt fail: " << e.what() << std::endl;
      return 1;
      }

   return 0;
   }


}

size_t test_curve25519()
   {
   test_report("Curve25519", 1, c25519_roundtrip());

   size_t fails = 0;

   std::ifstream c25519_scalar(TEST_DATA_DIR_PK "/c25519_scalar.vec");

   fails += run_tests_bb(c25519_scalar, "Curve25519 ScalarMult", "Out", true,
             [](std::map<std::string, std::string> m) -> size_t
             {
             return curve25519_scalar_kat(m["Secret"], m["Basepoint"], m["Out"]);
             });

   return fails;
   }

#else

SKIP_TEST(curve25519);

#endif // BOTAN_HAS_CURVE_25519
