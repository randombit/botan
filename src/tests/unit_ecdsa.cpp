/*
* ECDSA Tests
*
* (C) 2007 Falko Strenzke
*     2007 Manuel Hartl
*     2008,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <botan/hex.h>

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/pubkey.h>
  #include <botan/ecdsa.h>
  #include <botan/ec_group.h>
  #include <botan/oids.h>
  #include <botan/pkcs8.h>
#endif

#if defined(BOTAN_HAS_X509_CERTIFICATES)
  #include <botan/x509cert.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECDSA)

/**
* Tests whether the the signing routine will work correctly in case
* the integer e that is constructed from the message (thus the hash
* value) is larger than n, the order of the base point.  Tests the
* signing function of the pk signer object
*/
Test::Result test_hash_larger_than_n()
   {
   Test::Result result("ECDSA Unit");

   Botan::EC_Group dom_pars(Botan::OIDS::lookup("1.3.132.0.8")); // secp160r1
   // n = 0x0100000000000000000001f4c8f927aed3ca752257 (21 bytes)
   // -> shouldn't work with SHA224 which outputs 28 bytes

   Botan::ECDSA_PrivateKey priv_key(Test::rng(), dom_pars);

   std::vector<byte> message(20);
   for(size_t i = 0; i != message.size(); ++i)
      message[i] = i;

   Botan::PK_Signer pk_signer_160(priv_key, "EMSA1_BSI(SHA-1)");
   Botan::PK_Verifier pk_verifier_160(priv_key, "EMSA1_BSI(SHA-1)");

   Botan::PK_Signer pk_signer_224(priv_key, "EMSA1_BSI(SHA-224)");

   // Verify we can sign and verify with SHA-160
   std::vector<byte> signature_160 = pk_signer_160.sign_message(message, Test::rng());

   result.test_eq("message verifies", pk_verifier_160.verify_message(message, signature_160), true);

   try
      {
      pk_signer_224.sign_message(message, Test::rng());
      result.test_failure("bad key/hash combination not rejected");
      }
   catch(Botan::Encoding_Error)
      {
      result.test_note("bad key/hash combination rejected");
      }

   // now check that verification alone fails

   // sign it with the normal EMSA1
   Botan::PK_Signer pk_signer(priv_key, "EMSA1(SHA-224)");
   std::vector<byte> signature = pk_signer.sign_message(message, Test::rng());

   Botan::PK_Verifier pk_verifier(priv_key, "EMSA1_BSI(SHA-224)");

   result.test_eq("corrupt message does not verify", pk_verifier.verify_message(message, signature), false);

   return result;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES)
Test::Result test_decode_ecdsa_X509()
   {
   Test::Result result("ECDSA Unit");
   Botan::X509_Certificate cert(Test::data_file("ecc/CSCA.CSCA.csca-germany.1.crt"));

   result.test_eq("correct signature oid", Botan::OIDS::lookup(cert.signature_algorithm().oid), "ECDSA/EMSA1(SHA-224)");

   result.test_eq("serial number", cert.serial_number(), Botan::hex_decode("01"));
   result.test_eq("authority key id", cert.authority_key_id(), cert.subject_key_id());
   result.test_eq("key fingerprint", cert.fingerprint("SHA-1"), "32:42:1C:C3:EC:54:D7:E9:43:EC:51:F0:19:23:BD:85:1D:F2:1B:B9");

   std::unique_ptr<Botan::Public_Key> pubkey(cert.subject_public_key());
   result.test_eq("verify self-signed signature", cert.check_signature(*pubkey), true);

   return result;
   }

Test::Result test_decode_ver_link_SHA256()
   {
   Test::Result result("ECDSA Unit");
   Botan::X509_Certificate root_cert(Test::data_file("ecc/root2_SHA256.cer"));
   Botan::X509_Certificate link_cert(Test::data_file("ecc/link_SHA256.cer"));

   std::unique_ptr<Botan::Public_Key> pubkey(root_cert.subject_public_key());
   result.confirm("verified self-signed signature", link_cert.check_signature(*pubkey));
   return result;
   }

Test::Result test_decode_ver_link_SHA1()
   {
   Botan::X509_Certificate root_cert(Test::data_file("ecc/root_SHA1.163.crt"));
   Botan::X509_Certificate link_cert(Test::data_file("ecc/link_SHA1.166.crt"));

   Test::Result result("ECDSA Unit");
   std::unique_ptr<Botan::Public_Key> pubkey(root_cert.subject_public_key());
   result.confirm("verified self-signed signature", link_cert.check_signature(*pubkey));
   return result;
   }
#endif

Test::Result test_sign_then_ver()
   {
   Test::Result result("ECDSA Unit");

   Botan::EC_Group dom_pars(Botan::OID("1.3.132.0.8"));
   Botan::ECDSA_PrivateKey ecdsa(Test::rng(), dom_pars);

   Botan::PK_Signer signer(ecdsa, "EMSA1(SHA-1)");

   auto msg = Botan::hex_decode("12345678901234567890abcdef12");
   std::vector<byte> sig = signer.sign_message(msg, Test::rng());

   Botan::PK_Verifier verifier(ecdsa, "EMSA1(SHA-1)");

   result.confirm("signature verifies", verifier.verify_message(msg, sig));

   result.confirm("invalid signature rejected", !verifier.verify_message(msg, Test::mutate_vec(sig)));

   return result;
   }

Test::Result test_ec_sign()
   {
   Test::Result result("ECDSA Unit");

   try
      {
      Botan::EC_Group dom_pars(Botan::OID("1.3.132.0.8"));
      Botan::ECDSA_PrivateKey priv_key(Test::rng(), dom_pars);
      Botan::PK_Signer signer(priv_key, "EMSA1(SHA-224)");
      Botan::PK_Verifier verifier(priv_key, "EMSA1(SHA-224)");

      for(size_t i = 0; i != 256; ++i)
         {
         signer.update(static_cast<byte>(i));
         }
      std::vector<byte> sig = signer.signature(Test::rng());

      for(size_t i = 0; i != 256; ++i)
         {
         verifier.update(static_cast<byte>(i));
         }

      result.test_eq("ECDSA signature valid", verifier.check_signature(sig), true);

      // now check valid signature, different input
      for(size_t i = 1; i != 256; ++i) //starting from 1
         {
         verifier.update(static_cast<byte>(i));
         }

      result.test_eq("invalid ECDSA signature invalid", verifier.check_signature(sig), false);

      // now check with original input, modified signature

      sig[sig.size()/2]++;
      for(size_t i = 0; i != 256; ++i)
         verifier.update(static_cast<byte>(i));

      result.test_eq("invalid ECDSA signature invalid", verifier.check_signature(sig), false);
      }
   catch(std::exception& e)
      {
      result.test_failure("test_ec_sign", e.what());
      }

   return result;
   }

Test::Result test_ecdsa_create_save_load()
   {
   Test::Result result("ECDSA Unit");

   std::string ecc_private_key_pem;
   const std::vector<byte> msg = Botan::hex_decode("12345678901234567890abcdef12");
   std::vector<byte> msg_signature;

   try
      {
      Botan::EC_Group dom_pars(Botan::OID("1.3.132.0.8"));
      Botan::ECDSA_PrivateKey key(Test::rng(), dom_pars);

      Botan::PK_Signer signer(key, "EMSA1(SHA-1)");
      msg_signature = signer.sign_message(msg, Test::rng());

      ecc_private_key_pem = Botan::PKCS8::PEM_encode(key);
      }
   catch(std::exception& e)
      {
      result.test_failure("create_pkcs8", e.what());
      }

   Botan::DataSource_Memory pem_src(ecc_private_key_pem);
   std::unique_ptr<Botan::Private_Key> loaded_key(Botan::PKCS8::load_key(pem_src, Test::rng()));
   Botan::ECDSA_PrivateKey* loaded_ec_key = dynamic_cast<Botan::ECDSA_PrivateKey*>(loaded_key.get());
   result.confirm("the loaded key could be converted into an ECDSA_PrivateKey", loaded_ec_key);

   Botan::PK_Verifier verifier(*loaded_ec_key, "EMSA1(SHA-1)");

   result.confirm("generated signature valid", verifier.verify_message(msg, msg_signature));

   return result;
   }

Test::Result test_unusual_curve()
   {
   Test::Result result("ECDSA Unit");

   //calc a curve which is not in the registry
   const std::string G_secp_comp = "04081523d03d4f12cd02879dea4bf6a4f3a7df26ed888f10c5b2235a1274c386a2f218300dee6ed217841164533bcdc903f07a096f9fbf4ee95bac098a111f296f5830fe5c35b3e344d5df3a2256985f64fbe6d0edcc4c61d18bef681dd399df3d0194c5a4315e012e0245ecea56365baa9e8be1f7";
   const Botan::BigInt bi_p_secp("2117607112719756483104013348936480976596328609518055062007450442679169492999007105354629105748524349829824407773719892437896937279095106809");
   const Botan::BigInt bi_a_secp("0x0a377dede6b523333d36c78e9b0eaa3bf48ce93041f6d4fc34014d08f6833807498deedd4290101c5866e8dfb589485d13357b9e78c2d7fbe9fe");
   const Botan::BigInt bi_b_secp("0x0a9acf8c8ba617777e248509bcb4717d4db346202bf9e352cd5633731dd92a51b72a4dc3b3d17c823fcc8fbda4da08f25dea89046087342595a7");
   Botan::BigInt bi_order_g("0x0e1a16196e6000000000bc7f1618d867b15bb86474418f");
   Botan::CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);
   Botan::PointGFp p_G = Botan::OS2ECP(Botan::hex_decode(G_secp_comp), curve);

   Botan::EC_Group dom_params(curve, p_G, bi_order_g, Botan::BigInt(1));
   if(!result.confirm("point is on curve", p_G.on_the_curve()))
      return result;

   Botan::ECDSA_PrivateKey key_odd_curve(Test::rng(), dom_params);
   std::string key_odd_curve_str = Botan::PKCS8::PEM_encode(key_odd_curve);

   Botan::DataSource_Memory key_data_src(key_odd_curve_str);
   std::unique_ptr<Botan::Private_Key> loaded_key(Botan::PKCS8::load_key(key_data_src, Test::rng()));

   result.confirm("reloaded key", loaded_key.get());

   return result;
   }

Test::Result test_read_pkcs8()
   {
   Test::Result result("ECDSA Unit");

   const std::vector<byte> msg = Botan::hex_decode("12345678901234567890abcdef12");

   try
      {
      std::unique_ptr<Botan::Private_Key> loaded_key_nodp(Botan::PKCS8::load_key(Test::data_file("ecc/nodompar_private.pkcs8.pem"), Test::rng()));
      // anew in each test with unregistered domain-parameters
      Botan::ECDSA_PrivateKey* ecdsa_nodp = dynamic_cast<Botan::ECDSA_PrivateKey*>(loaded_key_nodp.get());
      result.confirm("key loaded", ecdsa_nodp);

      Botan::PK_Signer signer(*ecdsa_nodp, "EMSA1(SHA-1)");
      Botan::PK_Verifier verifier(*ecdsa_nodp, "EMSA1(SHA-1)");

      std::vector<byte> signature_nodp = signer.sign_message(msg, Test::rng());

      result.confirm("signature valid", verifier.verify_message(msg, signature_nodp));

      try
         {
         std::unique_ptr<Botan::Private_Key> loaded_key_withdp(
            Botan::PKCS8::load_key(Test::data_file("ecc/withdompar_private.pkcs8.pem"), Test::rng()));

         result.test_failure("loaded key with unknown OID");
         }
      catch(std::exception&)
         {
         result.test_note("rejected key with unknown OID");
         }
      }
   catch(std::exception& e)
      {
      result.test_failure("read_pkcs8", e.what());
      }

   return result;
   }



Test::Result test_curve_registry()
   {
   const std::vector<std::string> oids = {
      "1.3.132.0.8",
      "1.2.840.10045.3.1.1",
      "1.2.840.10045.3.1.2",
      "1.2.840.10045.3.1.3",
      "1.2.840.10045.3.1.4",
      "1.2.840.10045.3.1.5",
      "1.2.840.10045.3.1.6",
      "1.2.840.10045.3.1.7",
      "1.3.132.0.9",
      "1.3.132.0.30",
      "1.3.132.0.31",
      "1.3.132.0.32",
      "1.3.132.0.33",
      "1.3.132.0.10",
      "1.3.132.0.34",
      "1.3.132.0.35",
      "1.3.36.3.3.2.8.1.1.1",
      "1.3.36.3.3.2.8.1.1.3",
      "1.3.36.3.3.2.8.1.1.5",
      "1.3.36.3.3.2.8.1.1.7",
      "1.3.36.3.3.2.8.1.1.9",
      "1.3.36.3.3.2.8.1.1.11",
      "1.3.36.3.3.2.8.1.1.13",
      };

   Test::Result result("ECDSA Unit");

   for(auto&& oid_str : oids)
      {
      try
         {
         Botan::OID oid(oid_str);
         Botan::EC_Group dom_pars(oid);
         Botan::ECDSA_PrivateKey ecdsa(Test::rng(), dom_pars);

         Botan::PK_Signer signer(ecdsa, "EMSA1(SHA-1)");
         Botan::PK_Verifier verifier(ecdsa, "EMSA1(SHA-1)");

         auto msg = Botan::hex_decode("12345678901234567890abcdef12");
         std::vector<byte> sig = signer.sign_message(msg, Test::rng());

         result.confirm("verified signature", verifier.verify_message(msg, sig));
         }
      catch(Botan::Invalid_Argument& e)
         {
         result.test_failure("testing " + oid_str + ": " + e.what());
         }
      }

   return result;
   }

Test::Result test_ecc_key_with_rfc5915_extensions()
   {
   Test::Result result("ECDSA Unit");

   try
      {
      std::unique_ptr<Botan::Private_Key> pkcs8(
         Botan::PKCS8::load_key(Test::data_file("ecc/ecc_private_with_rfc5915_ext.pem"), Test::rng()));

      result.confirm("loaded RFC 5914 key", pkcs8.get());
      result.test_eq("key is ECDSA", pkcs8->algo_name(), "ECDSA");
      result.confirm("key type is ECDSA", dynamic_cast<Botan::ECDSA_PrivateKey*>(pkcs8.get()));
      }
   catch(std::exception& e)
      {
      result.test_failure("load_rfc5915", e.what());
      }

   return result;
   }


class ECDSA_Unit_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;
         results.push_back(test_hash_larger_than_n());
#if defined(BOTAN_HAS_X509_CERTIFICATES)
         results.push_back(test_decode_ecdsa_X509());
         results.push_back(test_decode_ver_link_SHA256());
         results.push_back(test_decode_ver_link_SHA1());
#endif
         results.push_back(test_sign_then_ver());
         results.push_back(test_ec_sign());
         results.push_back(test_read_pkcs8());
         results.push_back(test_ecdsa_create_save_load());
         results.push_back(test_unusual_curve());
         results.push_back(test_curve_registry());
         results.push_back(test_ecc_key_with_rfc5915_extensions());
         return results;
         }
   };

BOTAN_REGISTER_TEST("ecdsa_unit", ECDSA_Unit_Tests);
#endif

}

}
