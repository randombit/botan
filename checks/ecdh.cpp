/*
* ECDH tests
*
* (C) 2007 Manuel Hartl (hartl@flexsecure.de)
*     2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/build.h>

#include "validate.h"
#include "common.h"

#if defined(BOTAN_HAS_ECDH)

#include <iostream>
#include <fstream>

#include <botan/pubkey.h>
#include <botan/ecdh.h>
#include <botan/x509self.h>
#include <botan/der_enc.h>

using namespace Botan;

#define CHECK_MESSAGE(expr, print) try { if(!(expr)) std::cout << print << "\n"; } catch(std::exception& e) { std::cout << __FUNCTION__ << ": " << e.what() << "\n"; }
#define CHECK(expr) try { if(!(expr)) std::cout << #expr << "\n"; } catch(std::exception& e) { std::cout << __FUNCTION__ << ": " << e.what() << "\n"; }

namespace {

void test_ecdh_normal_derivation(RandomNumberGenerator& rng)
   {
   std::cout << "." << std::flush;

   EC_Group dom_pars(OID("1.3.132.0.8"));

   ECDH_PrivateKey private_a(rng, dom_pars);

   ECDH_PrivateKey private_b(rng, dom_pars); //public_a.getCurve()

   PK_Key_Agreement ka(private_a, "KDF2(SHA-1)");
   PK_Key_Agreement kb(private_b, "KDF2(SHA-1)");

   SymmetricKey alice_key = ka.derive_key(32, private_b.public_value());
   SymmetricKey bob_key = kb.derive_key(32, private_a.public_value());

   if(alice_key != bob_key)
      {
      std::cout << "The two keys didn't match!\n";
      std::cout << "Alice's key was: " << alice_key.as_string() << "\n";
      std::cout << "Bob's key was: " << bob_key.as_string() << "\n";
      }
   }

void test_ecdh_some_dp(RandomNumberGenerator& rng)
   {
   std::vector<std::string> oids;
   oids.push_back("1.2.840.10045.3.1.7");
   oids.push_back("1.3.132.0.8");
   oids.push_back("1.2.840.10045.3.1.1");

   for(u32bit i = 0; i< oids.size(); i++)
      {
      std::cout << "." << std::flush;

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

   }

void test_ecdh_der_derivation(RandomNumberGenerator& rng)
   {
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

      MemoryVector<byte> key_a = private_a.public_value();
      MemoryVector<byte> key_b = private_b.public_value();

      PK_Key_Agreement ka(private_a, "KDF2(SHA-1)");
      PK_Key_Agreement kb(private_b, "KDF2(SHA-1)");

      SymmetricKey alice_key = ka.derive_key(32, key_b);
      SymmetricKey bob_key = kb.derive_key(32, key_a);

      CHECK_MESSAGE(alice_key == bob_key, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
      //cout << "key: " << alice_key.as_string() << endl;
      }
   }

}

u32bit do_ecdh_tests(RandomNumberGenerator& rng)
   {
   std::cout << "Testing ECDH (InSiTo unit tests): ";

   test_ecdh_normal_derivation(rng);
   test_ecdh_some_dp(rng);
   test_ecdh_der_derivation(rng);

   std::cout << std::endl;

   return 0;
   }

#else
u32bit do_ecdh_tests(RandomNumberGenerator&) { return 0; }
#endif
