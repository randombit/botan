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

#include <botan/symkey.h>
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

   /*
   std::string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
   std::string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
   std::string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
   std::string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
   ::Botan::SecureVector<byte> sv_p_secp = decode_hex(p_secp);
   ::Botan::SecureVector<byte> sv_a_secp = decode_hex(a_secp);
   ::Botan::SecureVector<byte> sv_b_secp = decode_hex(b_secp);
   ::Botan::SecureVector<byte> sv_G_secp_comp = decode_hex(G_secp_comp);
   BigInt bi_p_secp = BigInt::decode(sv_p_secp.begin(), sv_p_secp.size());
   BigInt bi_a_secp = BigInt::decode(sv_a_secp.begin(), sv_a_secp.size());
   BigInt bi_b_secp = BigInt::decode(sv_b_secp.begin(), sv_b_secp.size());
   CurveGFp secp160r1(GFpElement(bi_p_secp,bi_a_secp), GFpElement(bi_p_secp, bi_b_secp), bi_p_secp);
   */

   std::string g_secp("024a96b5688ef573284664698968c38bb913cbfc82");
   Botan::SecureVector<Botan::byte> sv_g_secp = decode_hex(g_secp);
   BigInt bi_p_secp("0xffffffffffffffffffffffffffffffff7fffffff");
   BigInt bi_a_secp("0xffffffffffffffffffffffffffffffff7ffffffc");
   BigInt bi_b_secp("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
   BigInt order = BigInt("0x0100000000000000000001f4c8f927aed3ca752257");
   CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);

   BigInt cofactor = BigInt(1);
   PointGFp p_G = OS2ECP ( sv_g_secp, curve );
   Botan::EC_Domain_Params dom_pars = Botan::EC_Domain_Params(curve, p_G, order, cofactor);

   /**
   * begin ECDH
   */
   // alices key (a key constructed by domain parameters IS an ephimeral key!)
   Botan::ECDH_PrivateKey private_a(rng, dom_pars);
   Botan::ECDH_PublicKey public_a = private_a; // Bob gets this

   // Bob creates a key with a matching group
   Botan::ECDH_PrivateKey private_b(rng, dom_pars); //public_a.getCurve()

   // Bob sends the key back to Alice
   Botan::ECDH_PublicKey public_b = private_b; // Alice gets this

   // Both of them create a key using their private key and the other's
   // public key
   Botan::SymmetricKey alice_key = private_a.derive_key(public_b);
   Botan::SymmetricKey bob_key = private_b.derive_key(public_a);

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

   for(Botan::u32bit i = 0; i< oids.size(); i++)
      {
      std::cout << "." << std::flush;

      Botan::OID oid(oids[i]);
      Botan::EC_Domain_Params dom_pars(oid);
      Botan::ECDH_PrivateKey private_a(rng, dom_pars);
      Botan::ECDH_PublicKey public_a = private_a;
      /*auto_ptr<Botan::X509_Encoder> x509_key_enc = public_a.x509_encoder();
      Botan::MemoryVector<Botan::byte> enc_key_a = Botan::DER_Encoder()
      .start_cons(Botan::SEQUENCE)
      .encode(x509_key_enc->alg_id())
      .encode(x509_key_enc->key_bits(), Botan::BIT_STRING)
      .end_cons()
      .get_contents();*/

      Botan::ECDH_PrivateKey private_b(rng, dom_pars);
      Botan::ECDH_PublicKey public_b = private_b;
      // to test the equivalence, we
      // use the direct derivation method here

      Botan::SymmetricKey alice_key = private_a.derive_key(public_b);

      //cout << "encoded key = " << hex_encode(enc_key_a.begin(), enc_key_a.size()) << endl;

      Botan::SymmetricKey bob_key = private_b.derive_key(public_a);
      CHECK_MESSAGE(alice_key == bob_key, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
      //cout << "key: " << alice_key.as_string() << endl;
      }

   }

void test_ecdh_der_derivation(RandomNumberGenerator& rng)
   {
   std::vector<std::string> oids;
   oids.push_back("1.2.840.10045.3.1.7");
   oids.push_back("1.3.132.0.8");
   oids.push_back("1.2.840.10045.3.1.1");

   for(Botan::u32bit i = 0; i< oids.size(); i++)
      {
      Botan::OID oid(oids[i]);
      Botan::EC_Domain_Params dom_pars(oid);

      Botan::ECDH_PrivateKey private_a(rng, dom_pars);
      Botan::ECDH_PublicKey public_a = private_a;

      Botan::ECDH_PrivateKey private_b(rng, dom_pars);
      Botan::ECDH_PublicKey public_b = private_b;

      Botan::MemoryVector<Botan::byte> key_der_a = private_a.public_value();
      Botan::MemoryVector<Botan::byte> key_der_b = private_b.public_value();
      Botan::SymmetricKey alice_key = private_a.derive_key(key_der_b.begin(), key_der_b.size());
      Botan::SymmetricKey bob_key = private_b.derive_key(key_der_a.begin(), key_der_a.size());
      CHECK_MESSAGE(alice_key == bob_key, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
      //cout << "key: " << alice_key.as_string() << endl;
      }
   }

/**
* The following test tests the copy ctors and and copy-assignment operators
*/
void test_ecdh_cp_ctor_as_op(RandomNumberGenerator& rng)
   {
   std::cout << "." << std::flush;

   std::string g_secp("024a96b5688ef573284664698968c38bb913cbfc82");
   Botan::SecureVector<Botan::byte> sv_g_secp = decode_hex(g_secp);
   BigInt bi_p_secp("0xffffffffffffffffffffffffffffffff7fffffff");
   BigInt bi_a_secp("0xffffffffffffffffffffffffffffffff7ffffffc");
   BigInt bi_b_secp("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
   BigInt order = BigInt("0x0100000000000000000001f4c8f927aed3ca752257");
   CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);
   BigInt cofactor = BigInt(1);
   PointGFp p_G = OS2ECP ( sv_g_secp, curve );
   Botan::EC_Domain_Params dom_pars = Botan::EC_Domain_Params(curve, p_G, order, cofactor);

   /**
   * begin ECDH
   */
   // alices key (a key constructed by domain parameters IS an ephimeral key!)
   Botan::ECDH_PrivateKey private_a(rng, dom_pars);
   Botan::ECDH_PrivateKey private_a2(private_a);
   Botan::ECDH_PrivateKey private_a3 = private_a2;

   Botan::ECDH_PublicKey public_a = private_a; // Bob gets this
   Botan::ECDH_PublicKey public_a2(public_a);
   Botan::ECDH_PublicKey public_a3 = public_a;
   // Bob creates a key with a matching group
   Botan::ECDH_PrivateKey private_b(rng, dom_pars); //public_a.getCurve()

   // Bob sends the key back to Alice
   Botan::ECDH_PublicKey public_b = private_b; // Alice gets this

   // Both of them create a key using their private key and the other's
   // public key
   Botan::SymmetricKey alice_key = private_a.derive_key(public_b);
   Botan::SymmetricKey alice_key_2 = private_a2.derive_key(public_b);
   Botan::SymmetricKey alice_key_3 = private_a3.derive_key(public_b);

   Botan::SymmetricKey bob_key = private_b.derive_key(public_a);
   Botan::SymmetricKey bob_key_2 = private_b.derive_key(public_a2);
   Botan::SymmetricKey bob_key_3 = private_b.derive_key(public_a3);

   CHECK_MESSAGE(alice_key == bob_key, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
   CHECK_MESSAGE(alice_key_2 == bob_key_2, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
   CHECK_MESSAGE(alice_key_3 == bob_key_3, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
   CHECK_MESSAGE(alice_key == bob_key_2, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
   CHECK_MESSAGE(alice_key_2 == bob_key_3, "different keys - " << "Alice's key was: " << alice_key.as_string() << ", Bob's key was: " << bob_key.as_string());
   }

}

u32bit do_ecdh_tests(Botan::RandomNumberGenerator& rng)
   {
   std::cout << "Testing ECDH (InSiTo unit tests): ";

   test_ecdh_normal_derivation(rng);
   test_ecdh_some_dp(rng);
   test_ecdh_der_derivation(rng);
   test_ecdh_cp_ctor_as_op(rng);

   std::cout << std::endl;

   return 0;
   }

#else
u32bit do_ecdh_tests(Botan::RandomNumberGenerator&) { return 0; }
#endif
