/*
* ECDH tests
*
* (C) 2007 Manuel Hartl (hartl@flexsecure.de)
*     2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ECDH)
#include <iostream>
#include <fstream>


#include <botan/pubkey.h>
#include <botan/ecdh.h>
#if defined(BOTAN_HAS_X509_CERTIFICATES)
#include <botan/x509self.h>
#endif
#include <botan/der_enc.h>

using namespace Botan;

#define CHECK_MESSAGE(expr, print) try { if(!(expr)) { ++fails; std::cout << print << std::endl; } } catch(std::exception& e) { std::cout << __FUNCTION__ << ": " << e.what() << std::endl; }
#define CHECK(expr) try { if(!(expr)) { ++fails; std::cout << #expr << std::endl; } } catch(std::exception& e) { std::cout << __FUNCTION__ << ": " << e.what() << std::endl; }

namespace {

size_t test_ecdh_normal_derivation(RandomNumberGenerator& rng)
   {
   size_t fails = 0;

   EC_Group dom_pars(OID("1.3.132.0.8"));

   ECDH_PrivateKey private_a(rng, dom_pars);

   ECDH_PrivateKey private_b(rng, dom_pars); //public_a.getCurve()

   PK_Key_Agreement ka(private_a, "KDF2(SHA-1)");
   PK_Key_Agreement kb(private_b, "KDF2(SHA-1)");

   SymmetricKey alice_key = ka.derive_key(32, private_b.public_value());
   SymmetricKey bob_key = kb.derive_key(32, private_a.public_value());

   if(alice_key != bob_key)
      {
      std::cout << "The two keys didn't match!" << std::endl;
      std::cout << "Alice's key was: " << alice_key.as_string() << std::endl;
      std::cout << "Bob's key was: " << bob_key.as_string() << std::endl;
      ++fails;
      }

   return fails;
   }

size_t test_ecdh_some_dp(RandomNumberGenerator& rng)
   {
   size_t fails = 0;

   std::vector<std::string> oids;
   oids.push_back("1.2.840.10045.3.1.7");
   oids.push_back("1.3.132.0.8");
   oids.push_back("1.2.840.10045.3.1.1");

   for(u32bit i = 0; i< oids.size(); i++)
      {
      OID oid(oids[i]);
      EC_Group dom_pars(oid);

      ECDH_PrivateKey private_a(rng, dom_pars);
      ECDH_PrivateKey private_b(rng, dom_pars);

      PK_Key_Agreement ka(private_a, "KDF2(SHA-1)");
      PK_Key_Agreement kb(private_b, "KDF2(SHA-1)");

      SymmetricKey alice_key = ka.derive_key(32, private_b.public_value());
      SymmetricKey bob_key = kb.derive_key(32, private_a.public_value());

      CHECK_MESSAGE(alice_key == bob_key, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
      }

   return fails;
   }

size_t test_ecdh_der_derivation(RandomNumberGenerator& rng)
   {
   size_t fails = 0;

   std::vector<std::string> oids;
   oids.push_back("1.2.840.10045.3.1.7");
   oids.push_back("1.3.132.0.8");
   oids.push_back("1.2.840.10045.3.1.1");

   for(u32bit i = 0; i< oids.size(); i++)
      {
      OID oid(oids[i]);
      EC_Group dom_pars(oid);

      ECDH_PrivateKey private_a(rng, dom_pars);
      ECDH_PrivateKey private_b(rng, dom_pars);

      std::vector<byte> key_a = private_a.public_value();
      std::vector<byte> key_b = private_b.public_value();

      PK_Key_Agreement ka(private_a, "KDF2(SHA-1)");
      PK_Key_Agreement kb(private_b, "KDF2(SHA-1)");

      SymmetricKey alice_key = ka.derive_key(32, key_b);
      SymmetricKey bob_key = kb.derive_key(32, key_a);

      CHECK_MESSAGE(alice_key == bob_key, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());

      }

   return fails;
   }

}

size_t test_ecdh_unit()
   {
   size_t fails = 0;

   auto& rng = test_rng();

   fails += test_ecdh_normal_derivation(rng);
   fails += test_ecdh_some_dp(rng);
   fails += test_ecdh_der_derivation(rng);

   test_report("ECDH", 3, fails);

   return fails;
   }

#else

size_t test_ecdh_unit() { return 0; }

#endif
