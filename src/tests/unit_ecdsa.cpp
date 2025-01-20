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

#if defined(BOTAN_HAS_ECDSA)
   #include <botan/data_src.h>
   #include <botan/ec_group.h>
   #include <botan/ecdsa.h>
   #include <botan/hash.h>
   #include <botan/pkcs8.h>
   #include <botan/pubkey.h>
#endif

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/x509cert.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECDSA)

   #if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
Test::Result test_decode_ecdsa_X509() {
   Test::Result result("ECDSA Unit");
   Botan::X509_Certificate cert(Test::data_file("x509/ecc/CSCA.CSCA.csca-germany.1.crt"));

   result.test_eq("correct signature oid", cert.signature_algorithm().oid().to_formatted_string(), "ECDSA/SHA-224");

   result.test_eq("serial number", cert.serial_number(), std::vector<uint8_t>{1});
   result.test_eq("authority key id", cert.authority_key_id(), cert.subject_key_id());
   result.test_eq("key fingerprint",
                  cert.fingerprint("SHA-256"),
                  "3B:6C:99:1C:D6:5A:51:FC:EB:17:E3:AA:F6:3C:1A:DA:14:1F:82:41:30:6F:64:EE:FF:63:F3:1F:D6:07:14:9F");

   auto pubkey = cert.subject_public_key();
   result.test_eq("verify self-signed signature", cert.check_signature(*pubkey), true);

   return result;
}

Test::Result test_decode_ver_link_SHA256() {
   Test::Result result("ECDSA Unit");
   Botan::X509_Certificate root_cert(Test::data_file("x509/ecc/root2_SHA256.cer"));
   Botan::X509_Certificate link_cert(Test::data_file("x509/ecc/link_SHA256.cer"));

   auto pubkey = root_cert.subject_public_key();
   result.confirm("verified self-signed signature", link_cert.check_signature(*pubkey));
   return result;
}

Test::Result test_decode_ver_link_SHA1() {
   Botan::X509_Certificate root_cert(Test::data_file("x509/ecc/root_SHA1.163.crt"));
   Botan::X509_Certificate link_cert(Test::data_file("x509/ecc/link_SHA1.166.crt"));

   Test::Result result("ECDSA Unit");
   auto pubkey = root_cert.subject_public_key();

   auto sha1 = Botan::HashFunction::create("SHA-1");

   if(!sha1) {
      result.confirm("verification of self-signed signature failed due to missing SHA-1",
                     !link_cert.check_signature(*pubkey));
      return result;
   }
   result.confirm("verified self-signed signature", link_cert.check_signature(*pubkey));
   return result;
}
   #endif

Test::Result test_encoding_options() {
   Test::Result result("ECDSA Unit");

   auto rng = Test::new_rng("ecdsa_encoding_options");

   const auto group = Botan::EC_Group::from_name("secp256r1");
   Botan::ECDSA_PrivateKey key(*rng, group);

   result.confirm("Default encoding is uncompressed", key.point_encoding() == Botan::EC_Point_Format::Uncompressed);

   const std::vector<uint8_t> enc_uncompressed = key.public_key_bits();

   key.set_point_encoding(Botan::EC_Point_Format::Compressed);

   result.confirm("set_point_encoding works", key.point_encoding() == Botan::EC_Point_Format::Compressed);

   const std::vector<uint8_t> enc_compressed = key.public_key_bits();

   result.test_lt("Compressed points are smaller", enc_compressed.size(), enc_uncompressed.size());

   size_t size_diff = enc_uncompressed.size() - enc_compressed.size();

   result.test_gte("Compressed points smaller by group size", size_diff, 32);

   key.set_point_encoding(Botan::EC_Point_Format::Hybrid);

   result.confirm("set_point_encoding works", key.point_encoding() == Botan::EC_Point_Format::Hybrid);

   const std::vector<uint8_t> enc_hybrid = key.public_key_bits();

   result.test_eq("Hybrid point same size as uncompressed", enc_uncompressed.size(), enc_hybrid.size());

   #if !defined(BOTAN_HAS_SANITIZER_UNDEFINED)
   // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
   auto invalid_format = static_cast<Botan::EC_Point_Format>(99);

   result.test_throws("Invalid point format throws", "Invalid point encoding for EC_PublicKey", [&] {
      key.set_point_encoding(invalid_format);
   });
   #endif

   return result;
}

   #if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

Test::Result test_read_pkcs8() {
   Test::Result result("ECDSA Unit");

   auto rng = Test::new_rng("ecdsa_read_pkcs8");

   try {
      Botan::DataSource_Stream key_stream(Test::data_file("x509/ecc/nodompar_private.pkcs8.pem"));
      auto loaded_key_nodp = Botan::PKCS8::load_key(key_stream);
      // anew in each test with unregistered domain-parameters
      Botan::ECDSA_PrivateKey* ecdsa_nodp = dynamic_cast<Botan::ECDSA_PrivateKey*>(loaded_key_nodp.get());
      if(!ecdsa_nodp) {
         throw Test_Error("Unable to load valid PKCS8 ECDSA key");
      }

      result.confirm("EC_Group is marked as explicit encoding", ecdsa_nodp->domain().used_explicit_encoding());

      auto signer = ecdsa_nodp->signer().with_rng(*rng).with_hash("SHA-256").create();
      auto verifier = ecdsa_nodp->signature_verifier().with_hash("SHA-256").create();

      const auto msg = rng->random_vec(48);

      std::vector<uint8_t> signature_nodp = signer.sign_message(msg, *rng);

      result.confirm("signature valid", verifier.verify_message(msg, signature_nodp));

      try {
         Botan::DataSource_Stream key_stream2(Test::data_file("x509/ecc/withdompar_private.pkcs8.pem"));
         auto should_fail = Botan::PKCS8::load_key(key_stream2);
         result.test_failure("loaded key with unknown OID");
      } catch(std::exception&) {
         result.test_note("rejected key with unknown OID");
      }
   } catch(std::exception& e) {
      result.test_failure("read_pkcs8", e.what());
   }

   return result;
}

Test::Result test_ecc_key_with_rfc5915_extensions() {
   Test::Result result("ECDSA Unit");

   try {
      Botan::DataSource_Stream key_stream(Test::data_file("x509/ecc/ecc_private_with_rfc5915_ext.pem"));
      auto pkcs8 = Botan::PKCS8::load_key(key_stream);

      result.confirm("loaded RFC 5915 key", pkcs8 != nullptr);
      result.test_eq("key is ECDSA", pkcs8->algo_name(), "ECDSA");
      result.confirm("key type is ECDSA", dynamic_cast<Botan::ECDSA_PrivateKey*>(pkcs8.get()) != nullptr);
   } catch(std::exception& e) {
      result.test_failure("load_rfc5915_ext", e.what());
   }

   return result;
}

Test::Result test_ecc_key_with_rfc5915_parameters() {
   Test::Result result("ECDSA Unit");

   try {
      Botan::DataSource_Stream key_stream(Test::data_file("x509/ecc/ecc_private_with_rfc5915_parameters.pem"));
      auto pkcs8 = Botan::PKCS8::load_key(key_stream);

      result.confirm("loaded RFC 5915 key", pkcs8 != nullptr);
      result.test_eq("key is ECDSA", pkcs8->algo_name(), "ECDSA");
      result.confirm("key type is ECDSA", dynamic_cast<Botan::ECDSA_PrivateKey*>(pkcs8.get()) != nullptr);
   } catch(std::exception& e) {
      result.test_failure("load_rfc5915_params", e.what());
   }

   return result;
}

   #endif

class ECDSA_Unit_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
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

         results.push_back(test_encoding_options());
         return results;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecdsa_unit", ECDSA_Unit_Tests);
#endif

}  // namespace

}  // namespace Botan_Tests
