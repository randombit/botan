/*
* PKCS#12 Tests
* (C) 2026 Damiano Mazzella
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PKCS12)
   #include <botan/pkcs12.h>
   #include <botan/rng.h>
   #include <algorithm>

   #if defined(BOTAN_HAS_ECDSA)
      #include <botan/asn1_time.h>
      #include <botan/ec_group.h>
      #include <botan/ecdsa.h>
      #include <botan/pkcs8.h>
      #include <botan/x509_ca.h>
      #include <botan/x509self.h>
   #endif

namespace Botan_Tests {

namespace {

class PKCS12_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         // Tests that only exercise parsing / bundle-shape logic and do not
         // depend on any specific public-key algorithm are always run.

         results.push_back(test_empty_input());
         results.push_back(test_nesting_depth_exceeded());
         results.push_back(test_key_bag());
         results.push_back(test_safe_contents_bag());
         results.push_back(test_end_entity_without_match());
         results.push_back(test_unknown_bag_types());
         results.push_back(test_pfx_invalid_version());
         results.push_back(test_envelopeddata_rejected());
         results.push_back(test_crl_bag_unknown());
         results.push_back(test_add_null_key_rejected());
         results.push_back(test_local_key_id_empty());
         results.push_back(test_export_empty_bundle());

   #if defined(BOTAN_HAS_ECDSA)
         // The remaining tests generate ECDSA credentials on the fly and are
         // therefore only compiled when ECDSA is available in this build.

         results.push_back(test_key_cert_mismatch());
         results.push_back(test_zero_iterations());
         results.push_back(test_max_iterations_exceeded());
         results.push_back(test_wrong_password());
         results.push_back(test_corrupted_pfx());
         results.push_back(test_no_mac());
         results.push_back(test_empty_password());
         results.push_back(test_cert_only());
         results.push_back(test_legacy_compat_flag());
      #if defined(BOTAN_HAS_PKCS5_PBES2)
         results.push_back(test_mac_sha256());
      #endif

         results.push_back(test_basic_roundtrip());
         results.push_back(test_roundtrip_with_chain());
         results.push_back(test_no_friendly_name());
         results.push_back(test_custom_iterations());

         results.push_back(test_builder_workflow());
         results.push_back(test_export_options_fluent());
         results.push_back(test_multiple_keys());
         results.push_back(test_clear_friendly_name());
         results.push_back(test_local_key_id_setters());
         results.push_back(test_options_friendly_name_override());

         results.push_back(test_duplicate_certificate());
         results.push_back(test_friendly_name_non_bmp());
         results.push_back(test_trailing_data());

         results.push_back(test_mac_digest("SHA-224"));
      #if defined(BOTAN_HAS_SHA2_64)
         results.push_back(test_mac_digest("SHA-384"));
         results.push_back(test_mac_digest("SHA-512"));
         results.push_back(test_mac_digest("SHA-512-256"));
      #endif

         results.push_back(test_key_encryption("PBE-SHA1-3DES"));
         results.push_back(test_key_encryption("PBE-SHA1-2DES"));
      #if defined(BOTAN_HAS_PKCS5_PBES2)
         results.push_back(test_key_encryption("PBES2-SHA256-AES256"));
         results.push_back(test_key_encryption("PBES2-SHA256-AES128"));
      #endif

         results.push_back(test_cert_encryption(""));  // Unencrypted certs
         results.push_back(test_cert_encryption("PBE-SHA1-3DES"));
         results.push_back(test_cert_encryption("PBE-SHA1-2DES"));
      #if defined(BOTAN_HAS_PKCS5_PBES2)
         results.push_back(test_cert_encryption("PBES2-SHA256-AES256"));
         results.push_back(test_cert_encryption("PBES2-SHA256-AES128"));

         results.push_back(test_mixed_encryption("PBES2-SHA256-AES256", "PBE-SHA1-3DES"));
         results.push_back(test_mixed_encryption("PBE-SHA1-3DES", "PBES2-SHA256-AES128"));

         results.push_back(test_chain_with_pbes2());
      #endif
   #endif

         // External file parsing tests (do not depend on ECDSA at compile time
         // -- the parser surfaces whatever key type the file contains).
         results.push_back(test_parse_file("openssl_3des.p12", "test123"));
         results.push_back(test_parse_file("cert-none-key-none.p12", "cryptography"));
         results.push_back(test_parse_file("name-1-pwd.p12", "password", true, true, true, true));
         results.push_back(test_parse_file("name-2-3-pwd.p12", "password", true, true, true, true));
         results.push_back(test_parse_file("name-2-pwd.p12", "password", true, true, true, true));
         results.push_back(test_parse_file("name-3-pwd.p12", "password", true, true, true, true));
         results.push_back(test_parse_file("name-all-pwd.p12", "password", true, true, true, true));
         results.push_back(test_parse_file("name-unicode-pwd.p12", "password", true, true, true, true));
         results.push_back(test_parse_file("no-cert-name-2-pwd.p12", "password", true, false, true, true));
         results.push_back(test_parse_file("no-cert-name-3-pwd.p12", "password", true, false, true, true));
         results.push_back(test_parse_file("no-cert-name-all-pwd.p12", "password", true, false, true, true));
         results.push_back(test_parse_file("no-cert-name-unicode-pwd.p12", "password", true, false, true, true));
         results.push_back(test_parse_file("no-cert-no-name-pwd.p12", "password", true, false, true, false));
         results.push_back(test_parse_file("no-name-pwd.p12", "password", true, true, true));
         results.push_back(test_parse_file("java-truststore.p12", "", true, false, true, true));
         // OpenSSL-generated files with an empty password: these use OpenSSL's
         // non-conforming empty-password encoding (empty byte string instead of
         // RFC 7292's {0x00,0x00}). The parser transparently falls back to it.
         results.push_back(test_parse_file("name-1-no-pwd.p12", "", true, true, true, true));
         results.push_back(test_parse_file("name-2-3-no-pwd.p12", "", true, true, true, true));
         results.push_back(test_parse_file("name-2-no-pwd.p12", "", true, true, true, true));
         results.push_back(test_parse_file("no-cert-no-name-no-pwd.p12", "", true, false, true, false));
         results.push_back(test_parse_file("no-name-no-pwd.p12", "", true, true, true, false));
         results.push_back(test_parse_file("name-3-no-pwd.p12", "", true, true, true, true));
         results.push_back(test_parse_file("no-cert-name-all-no-pwd.p12", "", true, false, true, true));
         results.push_back(test_parse_file("name-all-no-pwd.p12", "", true, true, true, true));
         results.push_back(test_parse_file("name-unicode-no-pwd.p12", "", true, true, true, true));
         results.push_back(test_parse_file("no-cert-name-2-no-pwd.p12", "", true, false, true, true));
         results.push_back(test_parse_file("no-cert-name-3-no-pwd.p12", "", true, false, true, true));
         results.push_back(test_parse_file("no-cert-name-unicode-no-pwd.p12", "", true, false, true, true));
         // OpenSSL empty password (RC2 branch -- key encryption not supported,
         // so parsing still fails, but with Decoding_Error, not auth-tag).
         results.push_back(test_parse_file_unsupported_algorithm("no-password.p12", ""));
         // Wrong password
         results.push_back(test_parse_file_wrong_password("name-1-pwd.p12", "wrongpassword"));
         // RC2 unsupported algorithm
         results.push_back(test_parse_file_unsupported_algorithm("cert-rc2-key-3des.p12", "cryptography"));
   #if defined(BOTAN_HAS_PKCS5_PBES2)
         results.push_back(test_parse_file("openssl_aes256.p12", "test123"));
         results.push_back(test_parse_file("cert-aes256cbc-no-key.p12", "cryptography", true, false));
         results.push_back(test_parse_file("cert-key-aes256cbc.p12", "cryptography"));
         results.push_back(test_parse_file("no-cert-key-aes256cbc.p12", "cryptography", false, true));
   #endif

         return results;
      }

   private:
   #if defined(BOTAN_HAS_ECDSA)
      // Helper to generate a test key and certificate
      struct TestCredentials {
            std::shared_ptr<Botan::ECDSA_PrivateKey> key;
            Botan::X509_Certificate cert;
      };

      TestCredentials generate_credentials(Botan::RandomNumberGenerator& rng,
                                           const std::string& cn = "Test Certificate") {
         TestCredentials creds;
         creds.key = std::make_shared<Botan::ECDSA_PrivateKey>(rng, Botan::EC_Group::from_name("secp256r1"));

         Botan::X509_Cert_Options opts;
         opts.common_name = cn;
         opts.country = "US";
         opts.dns = "localhost";

         creds.cert = Botan::X509::create_self_signed_cert(opts, *creds.key, "SHA-256", rng);
         return creds;
      }

      // Verify parsed PKCS12 data matches original
      void verify_parsed_data(Test::Result& result,
                              const Botan::PKCS12& parsed,
                              const Botan::ECDSA_PrivateKey& orig_key,
                              const Botan::X509_Certificate& orig_cert,
                              const std::string& expected_friendly_name = "") {
         result.test_is_true("Has private key", !parsed.private_keys().empty());
         result.test_is_true("Has certificate", parsed.end_entity_certificate().has_value());

         if(!expected_friendly_name.empty()) {
            result.test_str_eq("Friendly name", parsed.friendly_name().value_or(""), expected_friendly_name);
         }

         if(!parsed.private_keys().empty()) {
            result.test_str_eq("Key algorithm", parsed.private_keys().front()->algo_name(), "ECDSA");
            const auto parsed_bits = parsed.private_keys().front()->private_key_bits();
            const auto orig_bits = orig_key.private_key_bits();
            result.test_is_true("Key matches", parsed_bits == orig_bits);
         }

         if(parsed.end_entity_certificate()) {
            result.test_is_true("Certificate matches",
                                parsed.end_entity_certificate()->BER_encode() == orig_cert.BER_encode());
         }
      }

      Test::Result test_key_cert_mismatch() {
         Test::Result result("PKCS12 key-cert mismatch rejected");

         auto rng = Test::new_rng("PKCS12_mismatch");
         const auto creds = generate_credentials(*rng);
         const auto other = generate_credentials(*rng, "Other");

         result.test_throws<Botan::Invalid_Argument>("mismatched key and certificate throws", [&]() {
            Botan::PKCS12 bundle;
            bundle.add_key(other.key);
            bundle.add_certificate(creds.cert);
            (void)bundle.export_to(Botan::PKCS12_Export_Options::legacy_compat("testpassword"), *rng);
         });

         return result;
      }

      Test::Result test_basic_roundtrip() {
         Test::Result result("PKCS12 basic roundtrip");

         auto rng = Test::new_rng("PKCS12_basic");
         auto creds = generate_credentials(*rng);

         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         bundle.set_friendly_name("Basic Test Key");
         const std::vector<uint8_t> pfx =
            bundle.export_to(Botan::PKCS12_Export_Options::legacy_compat("testpassword"), *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         const Botan::PKCS12 parsed(pfx, "testpassword");
         verify_parsed_data(result, parsed, *creds.key, creds.cert, "Basic Test Key");

         return result;
      }

      Test::Result test_roundtrip_with_chain() {
         Test::Result result("PKCS12 roundtrip with certificate chain");

         auto rng = Test::new_rng("PKCS12_chain");

         // Generate CA
         const auto ca_key = std::make_shared<Botan::ECDSA_PrivateKey>(*rng, Botan::EC_Group::from_name("secp256r1"));
         Botan::X509_Cert_Options ca_opts;
         ca_opts.common_name = "Test CA";
         ca_opts.country = "US";
         ca_opts.CA_key();
         const Botan::X509_Certificate ca_cert =
            Botan::X509::create_self_signed_cert(ca_opts, *ca_key, "SHA-256", *rng);

         // Create CA signer
         const Botan::X509_CA ca(ca_cert, *ca_key, "SHA-256", *rng);

         // Generate end-entity
         const auto ee_key = std::make_shared<Botan::ECDSA_PrivateKey>(*rng, Botan::EC_Group::from_name("secp256r1"));
         Botan::X509_Cert_Options ee_opts;
         ee_opts.common_name = "End Entity";
         ee_opts.country = "US";
         ee_opts.dns = "localhost";

         const Botan::PKCS10_Request csr = Botan::X509::create_cert_req(ee_opts, *ee_key, "SHA-256", *rng);
         const Botan::X509_Certificate ee_cert =
            ca.sign_request(csr, *rng, Botan::X509_Time("200101000000Z"), Botan::X509_Time("300101000000Z"));

         // Create PKCS#12 with chain
         const auto opts = Botan::PKCS12_Export_Options::modern("chaintest");
         const std::vector<Botan::X509_Certificate> chain = {ca_cert};
         Botan::PKCS12 bundle;
         bundle.add_key(ee_key);
         bundle.add_certificate(ee_cert);
         for(const auto& chain_cert : chain) {
            bundle.add_certificate(chain_cert);
         }
         bundle.set_friendly_name("Chain Test Key");
         const std::vector<uint8_t> pfx = bundle.export_to(opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         const Botan::PKCS12 parsed(pfx, "chaintest");

         result.test_is_true("Has private key", !parsed.private_keys().empty());
         result.test_is_true("Has certificate", parsed.end_entity_certificate().has_value());
         result.test_sz_eq("CA certificates count", parsed.ca_certificates().size(), 1);
         result.test_str_eq("Friendly name", parsed.friendly_name().value_or(""), "Chain Test Key");

         // Verify CA cert in chain
         if(!parsed.ca_certificates().empty()) {
            result.test_is_true("CA cert matches", parsed.ca_certificates()[0].BER_encode() == ca_cert.BER_encode());
         }

         return result;
      }

      Test::Result test_no_friendly_name() {
         Test::Result result("PKCS12 without friendly name");

         auto rng = Test::new_rng("PKCS12_no_name");
         auto creds = generate_credentials(*rng);

         // No friendly_name set on bundle or in options.
         const auto opts = Botan::PKCS12_Export_Options::legacy_compat("noname");
         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         const std::vector<uint8_t> pfx = bundle.export_to(opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         const Botan::PKCS12 parsed(pfx, "noname");

         result.test_is_true("Has private key", !parsed.private_keys().empty());
         result.test_is_true("Has certificate", parsed.end_entity_certificate().has_value());
         result.test_is_true("No friendly name", !parsed.friendly_name().has_value());

         return result;
      }

      Test::Result test_custom_iterations() {
         Test::Result result("PKCS12 with custom iterations");

         auto rng = Test::new_rng("PKCS12_iterations");
         auto creds = generate_credentials(*rng);

         // Test with non-default iteration count
         const auto opts = Botan::PKCS12_Export_Options::legacy_compat("itertest").with_iterations(5000);
         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         const std::vector<uint8_t> pfx = bundle.export_to(opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         const Botan::PKCS12 parsed(pfx, "itertest");
         verify_parsed_data(result, parsed, *creds.key, creds.cert);

         return result;
      }

      Test::Result test_key_encryption(const std::string& algo) {
         Test::Result result("PKCS12 key encryption: " + algo);

         auto rng = Test::new_rng("PKCS12_key_enc_" + algo);
         auto creds = generate_credentials(*rng);

         const auto opts =
            Botan::PKCS12_Export_Options("keyenctest").with_key_encryption_algo(algo).with_iterations(2048);
         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         bundle.set_friendly_name("Key Enc Test");
         const std::vector<uint8_t> pfx = bundle.export_to(opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         const Botan::PKCS12 parsed(pfx, "keyenctest");
         verify_parsed_data(result, parsed, *creds.key, creds.cert, "Key Enc Test");

         return result;
      }

      Test::Result test_cert_encryption(const std::string& algo) {
         const std::string test_name =
            algo.empty() ? "PKCS12 cert encryption: unencrypted" : "PKCS12 cert encryption: " + algo;
         Test::Result result(test_name);

         auto rng = Test::new_rng("PKCS12_cert_enc_" + (algo.empty() ? "none" : algo));
         auto creds = generate_credentials(*rng);

         auto opts = Botan::PKCS12_Export_Options("certenctest").with_iterations(2048);
         if(!algo.empty()) {
            opts.with_cert_encryption_algo(algo);
         }
         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         bundle.set_friendly_name("Cert Enc Test");
         const std::vector<uint8_t> pfx = bundle.export_to(opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         const Botan::PKCS12 parsed(pfx, "certenctest");
         verify_parsed_data(result, parsed, *creds.key, creds.cert, "Cert Enc Test");

         return result;
      }

      Test::Result test_mixed_encryption(const std::string& key_algo, const std::string& cert_algo) {
         Test::Result result("PKCS12 mixed encryption: key=" + key_algo + " cert=" + cert_algo);

         auto rng = Test::new_rng("PKCS12_mixed_" + key_algo + "_" + cert_algo);
         auto creds = generate_credentials(*rng);

         const auto opts = Botan::PKCS12_Export_Options("mixedtest")
                              .with_key_encryption_algo(key_algo)
                              .with_cert_encryption_algo(cert_algo)
                              .with_iterations(2048);
         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         bundle.set_friendly_name("Mixed Enc Test");
         const std::vector<uint8_t> pfx = bundle.export_to(opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         const Botan::PKCS12 parsed(pfx, "mixedtest");
         verify_parsed_data(result, parsed, *creds.key, creds.cert, "Mixed Enc Test");

         return result;
      }

      Test::Result test_chain_with_pbes2() {
         Test::Result result("PKCS12 chain with PBES2 encryption");

         auto rng = Test::new_rng("PKCS12_chain_pbes2");

         // Generate CA
         const auto ca_key = std::make_shared<Botan::ECDSA_PrivateKey>(*rng, Botan::EC_Group::from_name("secp256r1"));
         Botan::X509_Cert_Options ca_opts;
         ca_opts.common_name = "PBES2 CA";
         ca_opts.country = "US";
         ca_opts.CA_key();
         const Botan::X509_Certificate ca_cert =
            Botan::X509::create_self_signed_cert(ca_opts, *ca_key, "SHA-256", *rng);

         // Create intermediate CA
         const Botan::X509_CA root_ca(ca_cert, *ca_key, "SHA-256", *rng);

         const auto int_key = std::make_shared<Botan::ECDSA_PrivateKey>(*rng, Botan::EC_Group::from_name("secp256r1"));
         Botan::X509_Cert_Options int_opts;
         int_opts.common_name = "Intermediate CA";
         int_opts.country = "US";
         int_opts.CA_key();

         const Botan::PKCS10_Request int_csr = Botan::X509::create_cert_req(int_opts, *int_key, "SHA-256", *rng);
         const Botan::X509_Certificate int_cert =
            root_ca.sign_request(int_csr, *rng, Botan::X509_Time("200101000000Z"), Botan::X509_Time("300101000000Z"));

         // Create end-entity cert signed by intermediate
         const Botan::X509_CA int_ca(int_cert, *int_key, "SHA-256", *rng);

         const auto ee_key = std::make_shared<Botan::ECDSA_PrivateKey>(*rng, Botan::EC_Group::from_name("secp256r1"));
         Botan::X509_Cert_Options ee_opts;
         ee_opts.common_name = "End Entity";
         ee_opts.country = "US";
         ee_opts.dns = "localhost";

         const Botan::PKCS10_Request ee_csr = Botan::X509::create_cert_req(ee_opts, *ee_key, "SHA-256", *rng);
         const Botan::X509_Certificate ee_cert =
            int_ca.sign_request(ee_csr, *rng, Botan::X509_Time("200101000000Z"), Botan::X509_Time("300101000000Z"));

         // Create PKCS#12 with full chain and PBES2
         const auto opts = Botan::PKCS12_Export_Options("chainpbes2")
                              .with_key_encryption_algo("PBES2-SHA256-AES256")
                              .with_cert_encryption_algo("PBES2-SHA256-AES128")
                              .with_iterations(10000);

         const std::vector<Botan::X509_Certificate> chain = {int_cert, ca_cert};
         Botan::PKCS12 bundle;
         bundle.add_key(ee_key);
         bundle.add_certificate(ee_cert);
         for(const auto& ca : chain) {
            bundle.add_certificate(ca);
         }
         bundle.set_friendly_name("Chain PBES2 Key");
         const std::vector<uint8_t> pfx = bundle.export_to(opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         const Botan::PKCS12 parsed(pfx, "chainpbes2");

         result.test_is_true("Has private key", !parsed.private_keys().empty());
         result.test_is_true("Has certificate", parsed.end_entity_certificate().has_value());
         result.test_sz_eq("CA certificates count", parsed.ca_certificates().size(), 2);
         result.test_str_eq("Friendly name", parsed.friendly_name().value_or(""), "Chain PBES2 Key");

         // Verify key
         if(!parsed.private_keys().empty()) {
            const auto parsed_bits = parsed.private_keys().front()->private_key_bits();
            const auto orig_bits = ee_key->private_key_bits();
            result.test_is_true("Key matches", parsed_bits == orig_bits);
         }

         // Verify end-entity cert
         if(parsed.end_entity_certificate()) {
            result.test_is_true("EE cert matches",
                                parsed.end_entity_certificate()->BER_encode() == ee_cert.BER_encode());
         }

         return result;
      }
   #endif

      Test::Result test_parse_file_wrong_password(const std::string& filename, const std::string& password = "") {
         Test::Result result("PKCS12 parse file wrong password: " + filename);

         try {
            const std::vector<uint8_t> pfx_data = Test::read_binary_data_file("pkcs12/" + filename);
            result.test_throws<Botan::Invalid_Authentication_Tag>("wrong password throws",
                                                                  [&]() { Botan::PKCS12(pfx_data, password); });
         } catch(const std::exception& e) {
            result.test_failure("Failed to read PFX file", e.what());
         }

         return result;
      }

      Test::Result test_parse_file_unsupported_algorithm(const std::string& filename,
                                                         const std::string& password = "") {
         Test::Result result("PKCS12 parse file unsupported algorithm: " + filename);

         try {
            const std::vector<uint8_t> pfx_data = Test::read_binary_data_file("pkcs12/" + filename);
            result.test_throws<Botan::Decoding_Error>("unsupported algorithm throws",
                                                      [&]() { Botan::PKCS12(pfx_data, password); });
         } catch(const std::exception& e) {
            result.test_failure("Failed to read PFX file", e.what());
         }

         return result;
      }

      Test::Result test_parse_file(const std::string& filename,
                                   const std::string& password = "",
                                   bool has_cert = true,
                                   bool has_key = true,
                                   bool has_ca = false,
                                   bool has_friendly_name = false,
                                   const std::string& expected_friendly_name = "") {
         Test::Result result("PKCS12 parse file: " + filename);

         try {
            const std::vector<uint8_t> pfx_data = Test::read_binary_data_file("pkcs12/" + filename);
            const Botan::PKCS12 parsed(pfx_data, password);

            // has_cert here means "bundle contains at least one certificate"
            // (not specifically an end-entity); has_ca means "bundle contains
            // certificates other than the end-entity".
            result.test_is_true("Has private key", !parsed.private_keys().empty() == has_key);
            result.test_is_true("Has certificate", !parsed.certificates().empty() == has_cert);
            result.test_is_true("Has CA certificates", !parsed.ca_certificates().empty() == has_ca);
            result.test_is_true("Has friendly name", parsed.friendly_name().has_value() == has_friendly_name);
            if(has_key && !parsed.private_keys().empty()) {
               result.test_str_not_empty("Key algorithm", parsed.private_keys().front()->algo_name());
            }

            if(has_cert && !parsed.certificates().empty()) {
               result.test_str_not_empty("Certificate CN", parsed.certificates().front().subject_info("CN").at(0));
            }

            if(has_ca && !parsed.ca_certificates().empty()) {
               for(size_t i = 0; i < parsed.ca_certificates().size(); ++i) {
                  result.test_str_not_empty("CA certificate " + std::to_string(i) + " CN",
                                            parsed.ca_certificates()[i].subject_info("CN").at(0));
               }
            }

            if(has_friendly_name && parsed.friendly_name().has_value()) {
               result.test_str_not_empty("Friendly name", *parsed.friendly_name());
               if(!expected_friendly_name.empty()) {
                  result.test_str_eq("Friendly name value", *parsed.friendly_name(), expected_friendly_name);
               }
            }

            result.test_success("Parsed PFX successfully");
         } catch(const std::exception& e) {
            result.test_failure("Failed to parse PFX", e.what());
         }

         return result;
      }
   #if defined(BOTAN_HAS_ECDSA)

      Test::Result test_wrong_password() {
         Test::Result result("PKCS12 wrong password rejected");

         auto rng = Test::new_rng("PKCS12_wrong_pass");
         auto creds = generate_credentials(*rng);

         const auto opts = Botan::PKCS12_Export_Options::legacy_compat("correct");
         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         const auto pfx = bundle.export_to(opts, *rng);

         result.test_throws<Botan::Invalid_Authentication_Tag>("wrong password throws",
                                                               [&]() { Botan::PKCS12(pfx, "wrong"); });

         return result;
      }

      Test::Result test_corrupted_pfx() {
         Test::Result result("PKCS12 corrupted data rejected");

         auto rng = Test::new_rng("PKCS12_corrupt");
         auto creds = generate_credentials(*rng);

         const auto opts = Botan::PKCS12_Export_Options::legacy_compat("test");
         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         auto pfx = bundle.export_to(opts, *rng);

         // Corrupt bytes in the middle of the data
         pfx[pfx.size() / 2] ^= 0xFF;

         result.test_throws("corrupted pfx throws", [&]() { Botan::PKCS12(pfx, "test"); });

         return result;
      }

      Test::Result test_no_mac() {
         Test::Result result("PKCS12 without MAC");

         auto rng = Test::new_rng("PKCS12_no_mac");
         auto creds = generate_credentials(*rng);

         const auto opts = Botan::PKCS12_Export_Options::legacy_compat("nomactest").without_mac();
         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         const auto pfx = bundle.export_to(opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         const auto parsed = Botan::PKCS12(pfx, "nomactest");

         result.test_is_true("Has private key", !parsed.private_keys().empty());
         result.test_is_true("Has certificate", parsed.end_entity_certificate().has_value());

         return result;
      }

      Test::Result test_empty_password() {
         Test::Result result("PKCS12 empty password roundtrip");

         auto rng = Test::new_rng("PKCS12_empty_pass");
         auto creds = generate_credentials(*rng);

         // Empty password requires include_mac=false.
         const auto opts = Botan::PKCS12_Export_Options::legacy_compat("").without_mac();
         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         const auto pfx = bundle.export_to(opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         const auto parsed = Botan::PKCS12(pfx, "");
         result.test_is_true("Has private key", !parsed.private_keys().empty());
         result.test_is_true("Has certificate", parsed.end_entity_certificate().has_value());

         return result;
      }

      Test::Result test_cert_only() {
         Test::Result result("PKCS12 cert-only bundle");

         auto rng = Test::new_rng("PKCS12_cert_only");
         auto creds = generate_credentials(*rng);

         const auto opts = Botan::PKCS12_Export_Options::legacy_compat("certonly");
         Botan::PKCS12 bundle;
         bundle.add_certificate(creds.cert);
         const auto pfx = bundle.export_to(opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         const auto parsed = Botan::PKCS12(pfx, "certonly");
         result.test_is_false("No private key", !parsed.private_keys().empty());
         result.test_is_true("Has certificate", !parsed.certificates().empty());
         result.test_is_false("No end-entity (no key)", parsed.end_entity_certificate().has_value());

         return result;
      }
   #endif

      Test::Result test_empty_input() {
         Test::Result result("PKCS12 empty input rejected");

         result.test_throws<Botan::Decoding_Error>("empty bytes throws",
                                                   []() { Botan::PKCS12(std::span<const uint8_t>{}, "pass"); });

         return result;
      }
   #if defined(BOTAN_HAS_ECDSA)

      Test::Result test_zero_iterations() {
         Test::Result result("PKCS12 zero iterations rejected");

         auto rng = Test::new_rng("PKCS12_zero_iter");
         auto creds = generate_credentials(*rng);

         const auto opts = Botan::PKCS12_Export_Options("test").with_iterations(0);

         result.test_throws<Botan::Invalid_Argument>("zero iterations throws", [&]() {
            Botan::PKCS12 bundle;
            bundle.add_key(creds.key);
            bundle.add_certificate(creds.cert);
            (void)bundle.export_to(opts, *rng);
         });

         return result;
      }

      Test::Result test_max_iterations_exceeded() {
         Test::Result result("PKCS12 max iterations exceeded rejected");

         auto rng = Test::new_rng("PKCS12_max_iter");
         auto creds = generate_credentials(*rng);

         // PKCS12_MAX_ITERATIONS + 1
         const auto opts = Botan::PKCS12_Export_Options("test").with_iterations(1'000'001);

         result.test_throws<Botan::Invalid_Argument>("max iterations exceeded throws", [&]() {
            Botan::PKCS12 bundle;
            bundle.add_key(creds.key);
            bundle.add_certificate(creds.cert);
            (void)bundle.export_to(opts, *rng);
         });

         return result;
      }
   #endif

      Test::Result test_nesting_depth_exceeded() {
         Test::Result result("PKCS12 nesting depth exceeded rejected");
         const auto pfx = Test::read_binary_data_file("pkcs12/nesting_too_deep.pfx");
         result.test_throws<Botan::Decoding_Error>("nesting too deep throws", [&]() { Botan::PKCS12(pfx, ""); });
         return result;
      }
   #if defined(BOTAN_HAS_ECDSA)

      Test::Result test_legacy_compat_flag() {
         Test::Result result("PKCS12 legacy_compat flag");

         auto rng = Test::new_rng("PKCS12_legacy_compat");
         auto creds = generate_credentials(*rng);

         // legacy_compat should produce a file readable with "old" defaults
         const auto opts = Botan::PKCS12_Export_Options::legacy_compat("legacytest");
         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         const auto pfx = bundle.export_to(opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         const auto parsed = Botan::PKCS12(pfx, "legacytest");
         result.test_is_true("Has private key", !parsed.private_keys().empty());
         result.test_is_true("Has certificate", parsed.end_entity_certificate().has_value());

         return result;
      }
   #endif

      // Build a PFX (no MAC) with a KeyBag containing an unencrypted private key
      // Parse a PFX containing an unencrypted KeyBag (RFC 7292 sec.4.2.1) --
      // rarely seen in the wild but explicitly allowed by the spec.
      Test::Result test_key_bag() {
         Test::Result result("PKCS12 KeyBag (unencrypted key)");
         const auto pfx = Test::read_binary_data_file("pkcs12/key_bag_unencrypted.pfx");
         const Botan::PKCS12 parsed(pfx, "");
         result.test_sz_eq("One private key", parsed.private_keys().size(), 1);
         result.test_is_true("End-entity present", parsed.end_entity_certificate().has_value());
         return result;
      }

      // Parse a PFX with a SafeContentsBag wrapping a CertBag (RFC 7292 sec.4.2.6).
      Test::Result test_safe_contents_bag() {
         Test::Result result("PKCS12 SafeContentsBag (nested)");
         const auto pfx = Test::read_binary_data_file("pkcs12/safe_contents_bag_nested.pfx");
         const Botan::PKCS12 parsed(pfx, "");
         result.test_is_false("No private key", !parsed.private_keys().empty());
         result.test_is_true("Has certificate", !parsed.certificates().empty());
         return result;
      }
   #if defined(BOTAN_HAS_ECDSA)

      // Exercise the builder workflow:
      //   default ctor -> add_key / add_certificate / set_friendly_name -> export_to
      //   -> re-parse and verify.
      Test::Result test_builder_workflow() {
         Test::Result result("PKCS12 builder workflow (new API)");

         auto rng = Test::new_rng("PKCS12_builder");
         auto creds = generate_credentials(*rng, "Builder Test");

         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         bundle.set_friendly_name("Builder Bundle");

         const auto opts = Botan::PKCS12_Export_Options::modern("builderpw");
         const auto pfx = bundle.export_to(opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         const Botan::PKCS12 parsed(pfx, "builderpw");
         result.test_sz_eq("One private key", parsed.private_keys().size(), 1);
         result.test_sz_eq("One certificate", parsed.certificates().size(), 1);
         result.test_is_true("End-entity present", parsed.end_entity_certificate().has_value());
         result.test_is_true("Friendly name present", parsed.friendly_name().has_value());
         if(parsed.friendly_name().has_value()) {
            result.test_str_eq("Friendly name value", *parsed.friendly_name(), "Builder Bundle");
         }
         if(!parsed.private_keys().empty()) {
            result.test_is_true("Key matches",
                                parsed.private_keys().front()->private_key_bits() == creds.key->private_key_bits());
         }
         if(parsed.end_entity_certificate()) {
            result.test_is_true("Certificate matches",
                                parsed.end_entity_certificate()->BER_encode() == creds.cert.BER_encode());
         }

         return result;
      }

      // Verify the chainable PKCS12_Export_Options builder produces an
      // equivalent file regardless of which mutator combination is used.
      Test::Result test_export_options_fluent() {
         Test::Result result("PKCS12_Export_Options fluent API");

         auto rng = Test::new_rng("PKCS12_fluent");
         auto creds = generate_credentials(*rng);

         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);

         // Chain several with_* mutators; each returns *this.
         auto opts = Botan::PKCS12_Export_Options("fluentpw")
                        .with_friendly_name("Fluent Key")
                        .with_iterations(2048)
                        .with_key_encryption_algo("PBE-SHA1-3DES")
                        .with_mac_digest("SHA-1");

         const auto pfx = bundle.export_to(opts, *rng);
         result.test_sz_gt("PFX generated", pfx.size(), 0);

         const Botan::PKCS12 parsed(pfx, "fluentpw");
         result.test_is_true("Key parsed", !parsed.private_keys().empty());
         result.test_is_true("End-entity parsed", parsed.end_entity_certificate().has_value());
         result.test_is_true("Friendly name parsed", parsed.friendly_name().has_value());
         if(parsed.friendly_name().has_value()) {
            result.test_str_eq("Friendly name from options", *parsed.friendly_name(), "Fluent Key");
         }

         // without_mac() returns *this and disables the MAC. The parser must
         // accept the file without a MAC trailer.
         auto opts_no_mac = Botan::PKCS12_Export_Options::legacy_compat("nomacpw").without_mac().with_iterations(2048);
         const auto pfx_no_mac = bundle.export_to(opts_no_mac, *rng);
         result.test_sz_gt("PFX (no MAC) generated", pfx_no_mac.size(), 0);
         const Botan::PKCS12 parsed_no_mac(pfx_no_mac, "nomacpw");
         result.test_is_true("Key parsed (no MAC)", !parsed_no_mac.private_keys().empty());

         return result;
      }
   #endif

      // export_to on an empty bundle must throw.
      Test::Result test_export_empty_bundle() {
         Test::Result result("PKCS12 export of empty bundle rejected");

         auto rng = Test::new_rng("PKCS12_empty_export");
         Botan::PKCS12 bundle;

         result.test_throws<Botan::Invalid_Argument>(
            "empty bundle throws", [&]() { (void)bundle.export_to(Botan::PKCS12_Export_Options::modern("pw"), *rng); });

         return result;
      }
   #if defined(BOTAN_HAS_ECDSA)

      // Build a bundle with two private keys; verify both survive the
      // export/parse roundtrip. PKCS#12 supports multiple key bags per file.
      // The end-entity attribute (localKeyId, friendly name) is anchored to
      // the first key/cert pair only by this implementation.
      Test::Result test_multiple_keys() {
         Test::Result result("PKCS12 multiple private keys");

         auto rng = Test::new_rng("PKCS12_multi_key");
         auto creds1 = generate_credentials(*rng, "Primary");
         auto creds2 = generate_credentials(*rng, "Secondary");

         // Clone both keys via PKCS#8 so the bundle owns its own copies.
         auto clone_key = [](const Botan::Private_Key& k) {
            Botan::DataSource_Memory s(Botan::PKCS8::BER_encode(k));
            return std::shared_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(s));
         };

         Botan::PKCS12 bundle;
         bundle.add_key(clone_key(*creds1.key));
         bundle.add_key(clone_key(*creds2.key));
         bundle.add_certificate(creds1.cert);
         bundle.add_certificate(creds2.cert);

         const auto opts = Botan::PKCS12_Export_Options::modern("multipw", "Multi Key Bundle");
         const auto pfx = bundle.export_to(opts, *rng);
         result.test_sz_gt("PFX generated", pfx.size(), 0);

         const Botan::PKCS12 parsed(pfx, "multipw");
         result.test_sz_eq("Two private keys", parsed.private_keys().size(), 2);
         result.test_sz_eq("Two certificates", parsed.certificates().size(), 2);
         result.test_is_true("End-entity present (paired with first key)", parsed.end_entity_certificate().has_value());

         // The first parsed key should match one of the originals; same for
         // the second. Order isn't guaranteed across producers, so compare
         // the SET of SubjectPublicKeyInfo encodings.
         std::vector<std::vector<uint8_t>> orig_spki = {creds1.key->subject_public_key(),
                                                        creds2.key->subject_public_key()};
         std::vector<std::vector<uint8_t>> parsed_spki;
         for(const auto& k : parsed.private_keys()) {
            parsed_spki.push_back(k->subject_public_key());
         }
         std::sort(orig_spki.begin(), orig_spki.end());
         std::sort(parsed_spki.begin(), parsed_spki.end());
         result.test_is_true("Both keys' public material round-tripped", parsed_spki == orig_spki);

         return result;
      }

      // clear_friendly_name() must remove a previously set friendly name
      // and the exported PFX must then carry no friendly-name attribute.
      Test::Result test_clear_friendly_name() {
         Test::Result result("PKCS12 clear_friendly_name");

         auto rng = Test::new_rng("PKCS12_clear_fn");
         auto creds = generate_credentials(*rng);
         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         bundle.set_friendly_name("Will Be Cleared");
         result.test_is_true("Friendly name set", bundle.friendly_name().has_value());
         bundle.clear_friendly_name();
         result.test_is_false("Friendly name cleared", bundle.friendly_name().has_value());

         const auto pfx = bundle.export_to(Botan::PKCS12_Export_Options::modern("clearpw"), *rng);
         const Botan::PKCS12 parsed(pfx, "clearpw");
         result.test_is_false("No friendly name in parsed PFX", parsed.friendly_name().has_value());

         return result;
      }

      // set_local_key_id() / clear_local_key_id() must round-trip the
      // attribute bytes verbatim through the PFX.
      Test::Result test_local_key_id_setters() {
         Test::Result result("PKCS12 set_local_key_id / clear_local_key_id");

         auto rng = Test::new_rng("PKCS12_lki");
         auto creds = generate_credentials(*rng);
         const std::vector<uint8_t> custom_id = {0xDE, 0xAD, 0xBE, 0xEF, 0x42};

         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         bundle.set_local_key_id(custom_id);
         result.test_is_true("Local key id set", bundle.local_key_id().has_value());
         if(bundle.local_key_id()) {
            result.test_is_true("Local key id matches", *bundle.local_key_id() == custom_id);
         }

         const auto pfx = bundle.export_to(Botan::PKCS12_Export_Options::modern("lkipw"), *rng);
         const Botan::PKCS12 parsed(pfx, "lkipw");
         result.test_is_true("Local key id present in parsed PFX", parsed.local_key_id().has_value());
         if(parsed.local_key_id()) {
            result.test_is_true("Local key id round-tripped", *parsed.local_key_id() == custom_id);
         }

         // clear_local_key_id removes the explicit value (export then falls
         // back to deriving the id from the cert's SPKI BIT STRING).
         bundle.clear_local_key_id();
         result.test_is_false("Local key id cleared", bundle.local_key_id().has_value());
         const auto pfx2 = bundle.export_to(Botan::PKCS12_Export_Options::modern("lkipw"), *rng);
         const Botan::PKCS12 parsed2(pfx2, "lkipw");
         result.test_is_true("Local key id auto-derived from cert", parsed2.local_key_id().has_value());

         return result;
      }
   #endif

      // A parsed bundle with a key whose SPKI doesn't match any of the
      // included certificates must report end_entity_certificate() == nullopt
      // while still surfacing both the key and the cert(s).
      // A parsed bundle whose (single) key SPKI doesn't match the (single)
      // certificate: end_entity_certificate() must be nullopt while both are
      // surfaced by private_keys() / certificates().
      Test::Result test_end_entity_without_match() {
         Test::Result result("PKCS12 end_entity_certificate nullopt when no match");
         const auto pfx = Test::read_binary_data_file("pkcs12/key_cert_spki_mismatch.pfx");
         const Botan::PKCS12 parsed(pfx, "");
         result.test_is_true("Key parsed", !parsed.private_keys().empty());
         result.test_is_true("Cert parsed", !parsed.certificates().empty());
         result.test_is_false("No end-entity (SPKI mismatch)", parsed.end_entity_certificate().has_value());
         // ca_certificates() falls back to "all but first" when there is no
         // end-entity; with a single mismatched cert it must therefore be empty.
         result.test_is_true("ca_certificates empty", parsed.ca_certificates().empty());
         return result;
      }

      // A bag with an OID the parser doesn't handle (e.g. PKCS12.SecretBag)
      // must be silently skipped but recorded in unknown_bag_types().
      Test::Result test_unknown_bag_types() {
         Test::Result result("PKCS12 unknown_bag_types reported");
         const auto pfx = Test::read_binary_data_file("pkcs12/unknown_bag_secret.pfx");
         const Botan::PKCS12 parsed(pfx, "");
         result.test_sz_eq("One unknown bag recorded", parsed.unknown_bag_types().size(), 1);
         if(!parsed.unknown_bag_types().empty()) {
            result.test_str_eq("Unknown bag is SecretBag",
                               parsed.unknown_bag_types().front().to_formatted_string(),
                               Botan::OID::from_string("PKCS12.SecretBag").to_formatted_string());
         }
         result.test_is_true("Cert still parsed", !parsed.certificates().empty());
         return result;
      }
   #if defined(BOTAN_HAS_ECDSA)

      // When PKCS12_Export_Options::with_friendly_name is set, it must
      // override the bundle-level friendly_name() during export.
      Test::Result test_options_friendly_name_override() {
         Test::Result result("PKCS12_Export_Options friendly_name overrides bundle");

         auto rng = Test::new_rng("PKCS12_fn_override");
         auto creds = generate_credentials(*rng);
         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         bundle.set_friendly_name("Bundle-Level Name");

         auto opts = Botan::PKCS12_Export_Options::modern("ovrpw").with_friendly_name("Options-Level Name");
         const auto pfx = bundle.export_to(opts, *rng);

         const Botan::PKCS12 parsed(pfx, "ovrpw");
         result.test_is_true("Parsed has friendly name", parsed.friendly_name().has_value());
         if(parsed.friendly_name()) {
            result.test_str_eq("Options FN wins over bundle FN", *parsed.friendly_name(), "Options-Level Name");
         }

         // Also verify the opposite path: with no override in options, the
         // bundle FN is what ends up in the PFX.
         auto opts_no_ovr = Botan::PKCS12_Export_Options::modern("ovrpw");
         const auto pfx2 = bundle.export_to(opts_no_ovr, *rng);
         const Botan::PKCS12 parsed2(pfx2, "ovrpw");
         result.test_is_true("Parsed has bundle FN", parsed2.friendly_name().has_value());
         if(parsed2.friendly_name()) {
            result.test_str_eq("Bundle FN used when options unset", *parsed2.friendly_name(), "Bundle-Level Name");
         }

         return result;
      }
   #endif

      // add_key(nullptr) must throw Invalid_Argument.
      Test::Result test_add_null_key_rejected() {
         Test::Result result("PKCS12::add_key(nullptr) rejected");

         Botan::PKCS12 bundle;
         result.test_throws<Botan::Invalid_Argument>("add_key(nullptr) throws",
                                                     [&]() { bundle.add_key(std::shared_ptr<Botan::Private_Key>{}); });

         return result;
      }
   #if defined(BOTAN_HAS_ECDSA)

      // add_certificate does NOT deduplicate: the same certificate added twice
      // appears twice in certificates() and the resulting PFX contains two CertBags.
      Test::Result test_duplicate_certificate() {
         Test::Result result("PKCS12 duplicate certificate not deduplicated");

         auto rng = Test::new_rng("PKCS12_dup_cert");
         auto creds = generate_credentials(*rng);

         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         bundle.add_certificate(creds.cert);  // duplicate
         result.test_sz_eq("Bundle keeps both copies", bundle.certificates().size(), 2);

         const auto pfx = bundle.export_to(Botan::PKCS12_Export_Options::modern("duppw"), *rng);
         const Botan::PKCS12 parsed(pfx, "duppw");
         result.test_sz_eq("Parsed bundle keeps both copies", parsed.certificates().size(), 2);
         // end_entity_certificate picks the first match by SPKI; ca_certificates
         // returns the duplicate.
         result.test_is_true("End-entity present", parsed.end_entity_certificate().has_value());
         result.test_sz_eq("ca_certificates() returns the duplicate", parsed.ca_certificates().size(), 1);

         return result;
      }
   #endif

      // set_local_key_id({}) records an explicit-but-empty value: has_value() is
      // true and the contained vector is empty. (Distinct from "never set".)
      Test::Result test_local_key_id_empty() {
         Test::Result result("PKCS12 set_local_key_id with empty vector");

         Botan::PKCS12 bundle;
         result.test_is_false("Initially unset", bundle.local_key_id().has_value());
         bundle.set_local_key_id({});
         result.test_is_true("Explicit empty has_value", bundle.local_key_id().has_value());
         if(bundle.local_key_id()) {
            result.test_is_true("Contained vector is empty", bundle.local_key_id()->empty());
         }
         bundle.clear_local_key_id();
         result.test_is_false("Cleared", bundle.local_key_id().has_value());

         return result;
      }
   #if defined(BOTAN_HAS_ECDSA)

      // A friendly name containing characters outside the BMP (codepoints
      // above U+FFFF) cannot be encoded as BMPString and must be rejected
      // during export. "\xF0\x9F\x94\x91" is U+1F511 (KEY).
      Test::Result test_friendly_name_non_bmp() {
         Test::Result result("PKCS12 non-BMP friendly name rejected on export");

         auto rng = Test::new_rng("PKCS12_non_bmp");
         auto creds = generate_credentials(*rng);

         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         bundle.set_friendly_name("\xF0\x9F\x94\x91");  // U+1F511

         result.test_throws<Botan::Decoding_Error>("non-BMP friendly name throws", [&]() {
            (void)bundle.export_to(Botan::PKCS12_Export_Options::modern("bmppw"), *rng);
         });

         return result;
      }
   #endif

      // A PFX with version=2 (only 3 is accepted).
      Test::Result test_pfx_invalid_version() {
         Test::Result result("PKCS12 unsupported version rejected");
         const auto pfx = Test::read_binary_data_file("pkcs12/pfx_version_2.pfx");
         result.test_throws<Botan::Decoding_Error>("version != 3 throws", [&]() { Botan::PKCS12(pfx, ""); });
         return result;
      }
   #if defined(BOTAN_HAS_ECDSA)

      // Trailing bytes after a valid PFX must be rejected (pfx_seq.verify_end()).
      Test::Result test_trailing_data() {
         Test::Result result("PKCS12 trailing data rejected");

         auto rng = Test::new_rng("PKCS12_trailing");
         auto creds = generate_credentials(*rng);

         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         auto pfx = bundle.export_to(Botan::PKCS12_Export_Options::modern("trailpw"), *rng);

         pfx.push_back(0x42);
         pfx.push_back(0x42);
         pfx.push_back(0x42);

         result.test_throws<Botan::Decoding_Error>("trailing bytes throw", [&]() { Botan::PKCS12(pfx, "trailpw"); });

         return result;
      }
   #endif

      // An AuthenticatedSafe ContentInfo carrying EnvelopedData (PKCS7) must be
      // rejected. EnvelopedData is in the spec but not implemented here.
      Test::Result test_envelopeddata_rejected() {
         Test::Result result("PKCS12 EnvelopedData content type rejected");
         const auto pfx = Test::read_binary_data_file("pkcs12/envelopeddata_content.pfx");
         result.test_throws<Botan::Decoding_Error>("EnvelopedData throws", [&]() { Botan::PKCS12(pfx, ""); });
         return result;
      }

      // A PFX with a CrlBag (RFC 7292 sec.4.2.4) -- not implemented here -- must be
      // skipped but recorded in unknown_bag_types().
      Test::Result test_crl_bag_unknown() {
         Test::Result result("PKCS12 CrlBag reported as unknown");
         const auto pfx = Test::read_binary_data_file("pkcs12/unknown_bag_crl.pfx");
         const Botan::PKCS12 parsed(pfx, "");
         result.test_sz_eq("One unknown bag reported", parsed.unknown_bag_types().size(), 1);
         if(!parsed.unknown_bag_types().empty()) {
            result.test_str_eq("Reported OID is CrlBag",
                               parsed.unknown_bag_types().front().to_formatted_string(),
                               Botan::OID::from_string("PKCS12.CRLBag").to_formatted_string());
         }
         return result;
      }
   #if defined(BOTAN_HAS_ECDSA)

      // Roundtrip a PFX with a configurable MAC digest. Used to exercise the
      // SHA-2 family beyond SHA-256 (the latter is covered by test_mac_sha256).
      Test::Result test_mac_digest(const std::string& digest) {
         Test::Result result("PKCS12 MAC digest: " + digest);

         auto rng = Test::new_rng("PKCS12_mac_" + digest);
         auto creds = generate_credentials(*rng);

         const auto opts = Botan::PKCS12_Export_Options::legacy_compat("digestpw").with_mac_digest(digest);
         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         const auto pfx = bundle.export_to(opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         const Botan::PKCS12 parsed(pfx, "digestpw");
         result.test_is_true("Has private key", !parsed.private_keys().empty());
         result.test_is_true("Has certificate", parsed.end_entity_certificate().has_value());

         return result;
      }
   #endif

   #if defined(BOTAN_HAS_PKCS5_PBES2)
      #if defined(BOTAN_HAS_ECDSA)
      Test::Result test_mac_sha256() {
         Test::Result result("PKCS12 MAC SHA-256 roundtrip");

         auto rng = Test::new_rng("PKCS12_mac_sha256");
         auto creds = generate_credentials(*rng);

         // Modern defaults: PBES2-SHA256-AES256 key encryption, SHA-256 MAC.
         const auto opts = Botan::PKCS12_Export_Options::modern("mactest").with_iterations(2048);
         Botan::PKCS12 bundle;
         bundle.add_key(creds.key);
         bundle.add_certificate(creds.cert);
         const auto pfx = bundle.export_to(opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         const auto parsed = Botan::PKCS12(pfx, "mactest");
         result.test_is_true("Has private key", !parsed.private_keys().empty());
         result.test_is_true("Has certificate", parsed.end_entity_certificate().has_value());

         return result;
      }
      #endif
   #endif
};

BOTAN_REGISTER_TEST("pkcs12", "pkcs12_format", PKCS12_Tests);

}  // namespace

}  // namespace Botan_Tests

#endif
