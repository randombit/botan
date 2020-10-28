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
#include <numeric>

#if defined(BOTAN_HAS_ECDSA)
   #include <botan/pubkey.h>
   #include <botan/ecdsa.h>
   #include <botan/ec_group.h>
   #include <botan/oids.h>
   #include <botan/pkcs8.h>
   #include <botan/hash.h>
   #include <botan/data_src.h>
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

   Botan::EC_Group dom_pars("secp160r1");

   // n = 0x0100000000000000000001f4c8f927aed3ca752257 (21 bytes)

   Botan::ECDSA_PrivateKey priv_key(Test::rng(), dom_pars);

   std::vector<uint8_t> message(20);
   std::iota(message.begin(), message.end(), static_cast<uint8_t>(0));

   auto sha1 = Botan::HashFunction::create("SHA-1");
   auto sha224 = Botan::HashFunction::create("SHA-224");

   if(!sha1 || !sha224)
      {
      result.test_note("Skipping due to missing SHA-1 or SHA-224");
      return result;
      }

   Botan::PK_Signer pk_signer_160(priv_key, Test::rng(), "EMSA1(SHA-1)");
   Botan::PK_Verifier pk_verifier_160(priv_key, "EMSA1(SHA-1)");

   // Verify we can sign and verify with SHA-160
   std::vector<uint8_t> signature_160 = pk_signer_160.sign_message(message, Test::rng());
   result.test_eq("message verifies", pk_verifier_160.verify_message(message, signature_160), true);

   // Verify we can sign and verify with SHA-224
   Botan::PK_Signer pk_signer(priv_key, Test::rng(), "EMSA1(SHA-224)");
   std::vector<uint8_t> signature = pk_signer.sign_message(message, Test::rng());
   Botan::PK_Verifier pk_verifier(priv_key, "EMSA1(SHA-224)");
   result.test_eq("message verifies", pk_verifier.verify_message(message, signature), true);

   return result;
   }

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
Test::Result test_decode_ecdsa_X509()
   {
   Test::Result result("ECDSA Unit");
   Botan::X509_Certificate cert(Test::data_file("x509/ecc/CSCA.CSCA.csca-germany.1.crt"));

   result.test_eq("correct signature oid", cert.signature_algorithm().get_oid().to_formatted_string(), "ECDSA/EMSA1(SHA-224)");

   result.test_eq("serial number", cert.serial_number(), Botan::hex_decode("01"));
   result.test_eq("authority key id", cert.authority_key_id(), cert.subject_key_id());
   result.test_eq("key fingerprint", cert.fingerprint("SHA-1"),
                  "32:42:1C:C3:EC:54:D7:E9:43:EC:51:F0:19:23:BD:85:1D:F2:1B:B9");

   std::unique_ptr<Botan::Public_Key> pubkey(cert.subject_public_key());
   result.test_eq("verify self-signed signature", cert.check_signature(*pubkey), true);

   return result;
   }

Test::Result test_decode_ver_link_SHA256()
   {
   Test::Result result("ECDSA Unit");
   Botan::X509_Certificate root_cert(Test::data_file("x509/ecc/root2_SHA256.cer"));
   Botan::X509_Certificate link_cert(Test::data_file("x509/ecc/link_SHA256.cer"));

   std::unique_ptr<Botan::Public_Key> pubkey(root_cert.subject_public_key());
   result.confirm("verified self-signed signature", link_cert.check_signature(*pubkey));
   return result;
   }

Test::Result test_decode_ver_link_SHA1()
   {
   Botan::X509_Certificate root_cert(Test::data_file("x509/ecc/root_SHA1.163.crt"));
   Botan::X509_Certificate link_cert(Test::data_file("x509/ecc/link_SHA1.166.crt"));

   Test::Result result("ECDSA Unit");
   std::unique_ptr<Botan::Public_Key> pubkey(root_cert.subject_public_key());
   result.confirm("verified self-signed signature", link_cert.check_signature(*pubkey));
   return result;
   }
#endif

Test::Result test_sign_then_ver()
   {
   Test::Result result("ECDSA Unit");

   Botan::EC_Group dom_pars("secp160r1");
   Botan::ECDSA_PrivateKey ecdsa(Test::rng(), dom_pars);

   Botan::PK_Signer signer(ecdsa, Test::rng(), "EMSA1(SHA-256)");

   auto msg = Botan::hex_decode("12345678901234567890abcdef12");
   std::vector<uint8_t> sig = signer.sign_message(msg, Test::rng());

   Botan::PK_Verifier verifier(ecdsa, "EMSA1(SHA-256)");

   result.confirm("signature verifies", verifier.verify_message(msg, sig));

   result.confirm("invalid signature rejected", !verifier.verify_message(msg, Test::mutate_vec(sig)));

   return result;
   }

Test::Result test_ec_sign()
   {
   Test::Result result("ECDSA Unit");

   try
      {
      Botan::EC_Group dom_pars("secp160r1");
      Botan::ECDSA_PrivateKey priv_key(Test::rng(), dom_pars);
      Botan::PK_Signer signer(priv_key, Test::rng(), "EMSA1(SHA-224)");
      Botan::PK_Verifier verifier(priv_key, "EMSA1(SHA-224)");

      for(size_t i = 0; i != 256; ++i)
         {
         signer.update(static_cast<uint8_t>(i));
         }
      std::vector<uint8_t> sig = signer.signature(Test::rng());

      for(size_t i = 0; i != 256; ++i)
         {
         verifier.update(static_cast<uint8_t>(i));
         }

      result.test_eq("ECDSA signature valid", verifier.check_signature(sig), true);

      // now check valid signature, different input
      for(size_t i = 1; i != 256; ++i) //starting from 1
         {
         verifier.update(static_cast<uint8_t>(i));
         }

      result.test_eq("invalid ECDSA signature invalid", verifier.check_signature(sig), false);

      // now check with original input, modified signature

      sig[sig.size() / 2]++;
      for(size_t i = 0; i != 256; ++i)
         {
         verifier.update(static_cast<uint8_t>(i));
         }

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
   const std::vector<uint8_t> msg = Botan::hex_decode("12345678901234567890abcdef12");
   std::vector<uint8_t> msg_signature;

   try
      {
      Botan::EC_Group dom_pars("secp160r1");
      Botan::ECDSA_PrivateKey key(Test::rng(), dom_pars);

      Botan::PK_Signer signer(key, Test::rng(), "EMSA1(SHA-256)");
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
   result.confirm("the loaded key could be converted into an ECDSA_PrivateKey", loaded_ec_key != nullptr);

   if(loaded_ec_key)
      {
      result.confirm("the loaded key produces equal encoding",
                     (ecc_private_key_pem == Botan::PKCS8::PEM_encode(*loaded_ec_key)));
      Botan::PK_Verifier verifier(*loaded_ec_key, "EMSA1(SHA-256)");
      result.confirm("generated signature valid", verifier.verify_message(msg, msg_signature));
      }

   return result;
   }

Test::Result test_unusual_curve()
   {
   Test::Result result("ECDSA Unit");

   //calc a curve which is not in the registry
   const Botan::BigInt p("2117607112719756483104013348936480976596328609518055062007450442679169492999007105354629105748524349829824407773719892437896937279095106809");
   const Botan::BigInt a("0x0a377dede6b523333d36c78e9b0eaa3bf48ce93041f6d4fc34014d08f6833807498deedd4290101c5866e8dfb589485d13357b9e78c2d7fbe9fe");
   const Botan::BigInt b("0x0a9acf8c8ba617777e248509bcb4717d4db346202bf9e352cd5633731dd92a51b72a4dc3b3d17c823fcc8fbda4da08f25dea89046087342595a7");
   const Botan::BigInt order_g("0x0e1a16196e6000000000bc7f1618d867b15bb86474418f");
   const Botan::BigInt cofactor = 1;

   const BigInt Gx("1503931002566715881584977704503341991763310127581173321974500299341775226206001860606586625324214456299149080935147329869147994265934715820");
   const BigInt Gy("1774988776970033741491814582357926984496972046739476148938345272681378523636129776486407268230155403536112014267092770854858769258781598199");

   Botan::EC_Group dom_params(p, a, b, Gx, Gy, order_g, cofactor);

   Botan::PointGFp p_G = dom_params.point(Gx, Gy);

   if(!result.confirm("G is on curve", p_G.on_the_curve()))
      {
      return result;
      }

   Botan::ECDSA_PrivateKey key_odd_curve(Test::rng(), dom_params);
   std::string key_odd_curve_str = Botan::PKCS8::PEM_encode(key_odd_curve);

   Botan::DataSource_Memory key_data_src(key_odd_curve_str);
   std::unique_ptr<Botan::Private_Key> loaded_key(Botan::PKCS8::load_key(key_data_src, Test::rng()));

   result.confirm("reloaded key", loaded_key.get() != nullptr);

   return result;
   }

Test::Result test_encoding_options()
   {
   Test::Result result("ECDSA Unit");

   Botan::EC_Group group("secp256r1");
   Botan::ECDSA_PrivateKey key(Test::rng(), group);

   result.confirm("Default encoding is uncompressed",
                  key.point_encoding() == Botan::PointGFp::UNCOMPRESSED);

   const std::vector<uint8_t> enc_uncompressed = key.public_key_bits();

   key.set_point_encoding(Botan::PointGFp::COMPRESSED);

   result.confirm("set_point_encoding works",
                  key.point_encoding() == Botan::PointGFp::COMPRESSED);

   const std::vector<uint8_t> enc_compressed = key.public_key_bits();

   result.test_lt("Comprssed points are smaller",
                  enc_compressed.size(), enc_uncompressed.size());

   size_t size_diff = enc_uncompressed.size() - enc_compressed.size();

   result.test_gte("Compressed points smaller by group size",
                   size_diff, 32);

   key.set_point_encoding(Botan::PointGFp::HYBRID);

   result.confirm("set_point_encoding works",
                  key.point_encoding() == Botan::PointGFp::HYBRID);

   const std::vector<uint8_t> enc_hybrid = key.public_key_bits();

   result.test_eq("Hybrid point same size as uncompressed",
                  enc_uncompressed.size(), enc_hybrid.size());

#if !defined(BOTAN_HAS_SANITIZER_UNDEFINED)
   auto invalid_format = static_cast<Botan::PointGFp::Compression_Type>(99);

   result.test_throws("Invalid point format throws",
                      "Invalid point encoding for EC_PublicKey",
                      [&] { key.set_point_encoding(invalid_format); });
#endif

   return result;
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

Test::Result test_read_pkcs8()
   {
   Test::Result result("ECDSA Unit");

   const std::vector<uint8_t> msg = Botan::hex_decode("12345678901234567890abcdef12");

   try
      {
      std::unique_ptr<Botan::Private_Key> loaded_key_nodp(Botan::PKCS8::load_key(
               Test::data_file("x509/ecc/nodompar_private.pkcs8.pem"), Test::rng()));
      // anew in each test with unregistered domain-parameters
      Botan::ECDSA_PrivateKey* ecdsa_nodp = dynamic_cast<Botan::ECDSA_PrivateKey*>(loaded_key_nodp.get());
      if(!ecdsa_nodp)
         {
         throw Test_Error("Unable to load valid PKCS8 ECDSA key");
         }

      Botan::PK_Signer signer(*ecdsa_nodp, Test::rng(), "EMSA1(SHA-256)");
      Botan::PK_Verifier verifier(*ecdsa_nodp, "EMSA1(SHA-256)");

      std::vector<uint8_t> signature_nodp = signer.sign_message(msg, Test::rng());

      result.confirm("signature valid", verifier.verify_message(msg, signature_nodp));

      try
         {
         std::unique_ptr<Botan::Private_Key> loaded_key_withdp(
            Botan::PKCS8::load_key(Test::data_file("x509/ecc/withdompar_private.pkcs8.pem"), Test::rng()));

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

Test::Result test_ecc_key_with_rfc5915_extensions()
   {
   Test::Result result("ECDSA Unit");

   try
      {
      std::unique_ptr<Botan::Private_Key> pkcs8(
         Botan::PKCS8::load_key(Test::data_file("x509/ecc/ecc_private_with_rfc5915_ext.pem"), Test::rng()));

      result.confirm("loaded RFC 5915 key", pkcs8.get() != nullptr);
      result.test_eq("key is ECDSA", pkcs8->algo_name(), "ECDSA");
      result.confirm("key type is ECDSA", dynamic_cast<Botan::ECDSA_PrivateKey*>(pkcs8.get()) != nullptr);
      }
   catch(std::exception& e)
      {
      result.test_failure("load_rfc5915_ext", e.what());
      }

   return result;
   }

Test::Result test_ecc_key_with_rfc5915_parameters()
   {
   Test::Result result("ECDSA Unit");

   try
      {
      std::unique_ptr<Botan::Private_Key> pkcs8(
         Botan::PKCS8::load_key(Test::data_file("x509/ecc/ecc_private_with_rfc5915_parameters.pem"), Test::rng()));

      result.confirm("loaded RFC 5915 key", pkcs8.get() != nullptr);
      result.test_eq("key is ECDSA", pkcs8->algo_name(), "ECDSA");
      result.confirm("key type is ECDSA", dynamic_cast<Botan::ECDSA_PrivateKey*>(pkcs8.get()) != nullptr);
      }
   catch(std::exception& e)
      {
      result.test_failure("load_rfc5915_params", e.what());
      }

   return result;
   }

#endif

Test::Result test_curve_registry()
   {
   Test::Result result("ECDSA Unit");

   for(const std::string& group_name : Botan::EC_Group::known_named_groups())
      {
      try
         {
         Botan::EC_Group group(group_name);
         Botan::ECDSA_PrivateKey ecdsa(Test::rng(), group);

         Botan::PK_Signer signer(ecdsa, Test::rng(), "EMSA1(SHA-256)");
         Botan::PK_Verifier verifier(ecdsa, "EMSA1(SHA-256)");

         const std::vector<uint8_t> msg = Botan::hex_decode("12345678901234567890abcdef12");
         const std::vector<uint8_t> sig = signer.sign_message(msg, Test::rng());

         result.confirm("verified signature", verifier.verify_message(msg, sig));
         }
      catch(Botan::Invalid_Argument& e)
         {
         result.test_failure("testing " + group_name + ": " + e.what());
         }
      }

   return result;
   }


class ECDSA_Unit_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
         results.push_back(test_read_pkcs8());
         results.push_back(test_ecc_key_with_rfc5915_extensions());
         results.push_back(test_ecc_key_with_rfc5915_parameters());

#if defined(BOTAN_HAS_X509_CERTIFICATES)
         results.push_back(test_decode_ecdsa_X509());
         results.push_back(test_decode_ver_link_SHA256());
         results.push_back(test_decode_ver_link_SHA1());
#endif

#endif

         results.push_back(test_hash_larger_than_n());
         results.push_back(test_sign_then_ver());
         results.push_back(test_ec_sign());
         results.push_back(test_ecdsa_create_save_load());
         results.push_back(test_unusual_curve());
         results.push_back(test_curve_registry());
         results.push_back(test_encoding_options());
         return results;
         }
   };

BOTAN_REGISTER_TEST("pubkey", "ecdsa_unit", ECDSA_Unit_Tests);
#endif

}

}
