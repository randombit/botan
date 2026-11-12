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
   #include <botan/rng.h>
#endif

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/x509cert.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECDSA)

   #if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
Test::Result test_decode_ecdsa_X509() {
   Test::Result result("Parse CSCA cert");

   if(Botan::EC_Group::supports_application_specific_group()) {
      try {
         const Botan::X509_Certificate cert(Test::data_file("x509/ecc/CSCA.CSCA.csca-germany.1.crt"));

         result.test_opt_str_eq(
            "correct signature oid", cert.signature_algorithm().oid().registered_name(), "ECDSA/SHA-224");

         result.test_bin_eq("serial number", cert.serial_number(), std::vector<uint8_t>{1});
         result.test_bin_eq("authority key id", cert.authority_key_id(), cert.subject_key_id());
         result.test_str_eq(
            "key fingerprint",
            cert.fingerprint("SHA-256"),
            "3B:6C:99:1C:D6:5A:51:FC:EB:17:E3:AA:F6:3C:1A:DA:14:1F:82:41:30:6F:64:EE:FF:63:F3:1F:D6:07:14:9F");

         const auto pubkey = cert.subject_public_key();
         result.test_is_true("verify self-signed signature", cert.check_signature(*pubkey));
      } catch(Botan::Exception& e) {
         result.test_failure(e.what());
      }
   }

   return result;
}

Test::Result test_decode_ver_link_SHA256() {
   Test::Result result("Check ECDSA signature");

   if(Botan::EC_Group::supports_application_specific_group()) {
      try {
         const Botan::X509_Certificate root_cert(Test::data_file("x509/ecc/root2_SHA256.cer"));
         const Botan::X509_Certificate link_cert(Test::data_file("x509/ecc/link_SHA256.cer"));

         const auto pubkey = root_cert.subject_public_key();
         result.test_is_true("verified self-signed signature", link_cert.check_signature(*pubkey));
      } catch(Botan::Exception& e) {
         result.test_failure(e.what());
      }
   }

   return result;
}

Test::Result test_decode_ver_link_SHA1() {
   Test::Result result("Check ECDSA signature SHA-1");

   if(Botan::EC_Group::supports_application_specific_group()) {
      // These certificates use explicit parameters for a non-standard curve,
      // which can only be decoded after the curve has been registered
      const Botan::OID curve_oid("1.3.6.1.4.1.25258.100.63");
      Botan::EC_Group::register_custom_group(
         curve_oid,
         Botan::BigInt("0xD7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF"),
         Botan::BigInt("0x0A2233AB4CAA850891B5CD000A537B4163F6E33386EA714571ACDAD0"),
         Botan::BigInt("0x4C656229EC4916CB18A8519722864AAF005CE53CA9A5F54FB2A1148B"),
         Botan::BigInt("0x590131AD694E4CB1DDE553FEBAEEEF4896B2C003535857907D68778A"),
         Botan::BigInt("0x9C2F5EBAE83EDF237D1DC4FDC575CB048A2EAEA66B7732A68AC7222E"),
         Botan::BigInt("0xD7C134AA264366862A18302575D256A0D0B78486F1C27E6A959507CD"));

      try {
         const Botan::X509_Certificate root_cert(Test::data_file("x509/ecc/root_SHA1.163.crt"));
         const Botan::X509_Certificate link_cert(Test::data_file("x509/ecc/link_SHA1.166.crt"));

         const auto pubkey = root_cert.subject_public_key();

         const auto sha1 = Botan::HashFunction::create("SHA-1");

         if(!sha1) {
            result.test_is_true("verification of self-signed signature failed due to missing SHA-1",
                                !link_cert.check_signature(*pubkey));
         } else {
            result.test_is_true("verified self-signed signature", link_cert.check_signature(*pubkey));
         }
      } catch(Botan::Exception& e) {
         result.test_failure(e.what());
      }

      Botan::EC_Group::unregister(curve_oid);
   }

   return result;
}
   #endif

Test::Result test_encoding_options() {
   Test::Result result("ECDSA encoding");

   try {
      auto rng = Test::new_rng("ecdsa_encoding_options");

      for(const auto& group_id : Botan::EC_Group::known_named_groups()) {
         const auto group = Botan::EC_Group::from_name(group_id);
         Botan::ECDSA_PrivateKey key(*rng, group);

         result.test_is_true("Default encoding is uncompressed",
                             key.point_encoding() == Botan::EC_Point_Format::Uncompressed);

         const std::vector<uint8_t> enc_uncompressed = key.public_key_bits();
         key.set_point_encoding(Botan::EC_Point_Format::Compressed);

         result.test_is_true("set_point_encoding works", key.point_encoding() == Botan::EC_Point_Format::Compressed);

         const std::vector<uint8_t> enc_compressed = key.public_key_bits();
         result.test_sz_lt("Compressed points are smaller", enc_compressed.size(), enc_uncompressed.size());
         const size_t size_diff = enc_uncompressed.size() - enc_compressed.size();
         result.test_sz_gte("Compressed points smaller by group size", size_diff, group.get_p_bytes());
      }
   } catch(Botan::Exception& e) {
      result.test_failure(e.what());
   }

   return result;
}

   #if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

Test::Result test_ecc_key_with_rfc5915_extensions() {
   Test::Result result("ECDSA Unit");

   try {
      if(Botan::EC_Group::supports_named_group("secp256r1")) {
         Botan::DataSource_Stream key_stream(Test::data_file("x509/ecc/ecc_private_with_rfc5915_ext.pem"));
         auto pkcs8 = Botan::PKCS8::load_key(key_stream);

         result.test_is_true("loaded RFC 5915 key", pkcs8 != nullptr);
         result.test_str_eq("key is ECDSA", pkcs8->algo_name(), "ECDSA");
         result.test_is_true("key type is ECDSA", dynamic_cast<Botan::ECDSA_PrivateKey*>(pkcs8.get()) != nullptr);
      }
   } catch(std::exception& e) {
      result.test_failure("load_rfc5915_ext", e.what());
   }

   return result;
}

Test::Result test_ecc_key_with_rfc5915_parameters() {
   Test::Result result("ECDSA Unit");

   try {
      if(Botan::EC_Group::supports_named_group("secp256r1")) {
         Botan::DataSource_Stream key_stream(Test::data_file("x509/ecc/ecc_private_with_rfc5915_parameters.pem"));
         auto pkcs8 = Botan::PKCS8::load_key(key_stream);

         result.test_is_true("loaded RFC 5915 key", pkcs8 != nullptr);
         result.test_str_eq("key is ECDSA", pkcs8->algo_name(), "ECDSA");
         result.test_is_true("key type is ECDSA", dynamic_cast<Botan::ECDSA_PrivateKey*>(pkcs8.get()) != nullptr);
      }
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
