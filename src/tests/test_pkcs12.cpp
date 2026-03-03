/*
* PKCS#12 Tests
* (C) 2026
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PKCS12)
   #include <botan/pkcs12.h>
   #include <botan/pkcs8.h>
   #include <botan/rng.h>
   #include <botan/rsa.h>
   #include <botan/x509_ca.h>
   #include <botan/x509self.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_PKCS12) && defined(BOTAN_HAS_RSA)

class PKCS12_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         // Basic functionality tests
         results.push_back(test_basic_roundtrip());
         results.push_back(test_roundtrip_with_chain());
         results.push_back(test_no_friendly_name());
         results.push_back(test_custom_iterations());

         // Key encryption algorithms
         results.push_back(test_key_encryption("PBE-SHA1-3DES"));
         results.push_back(test_key_encryption("PBE-SHA1-2DES"));
#if defined(BOTAN_HAS_RC2)
         results.push_back(test_key_encryption("PBE-SHA1-RC2-40"));
         results.push_back(test_key_encryption("PBE-SHA1-RC2-128"));
#endif
         results.push_back(test_key_encryption("PBES2-SHA256-AES256"));
         results.push_back(test_key_encryption("PBES2-SHA256-AES128"));

         // Certificate encryption algorithms
         results.push_back(test_cert_encryption(""));  // Unencrypted certs
         results.push_back(test_cert_encryption("PBE-SHA1-3DES"));
         results.push_back(test_cert_encryption("PBE-SHA1-2DES"));
#if defined(BOTAN_HAS_RC2)
         results.push_back(test_cert_encryption("PBE-SHA1-RC2-40"));
         results.push_back(test_cert_encryption("PBE-SHA1-RC2-128"));
#endif
         results.push_back(test_cert_encryption("PBES2-SHA256-AES256"));
         results.push_back(test_cert_encryption("PBES2-SHA256-AES128"));

         // Mixed encryption combinations
         results.push_back(test_mixed_encryption("PBES2-SHA256-AES256", "PBE-SHA1-3DES"));
         results.push_back(test_mixed_encryption("PBE-SHA1-3DES", "PBES2-SHA256-AES128"));
#if defined(BOTAN_HAS_RC2)
         results.push_back(test_mixed_encryption("PBE-SHA1-3DES", "PBE-SHA1-RC2-40"));  // Common legacy combination
#endif

         // Chain with different encryptions
         results.push_back(test_chain_with_pbes2());

         return results;
      }

   private:
      // Helper to generate a test key and certificate
      struct TestCredentials {
            std::unique_ptr<Botan::RSA_PrivateKey> key;
            Botan::X509_Certificate cert;
      };

      TestCredentials generate_credentials(Botan::RandomNumberGenerator& rng,
                                           const std::string& cn = "Test Certificate") {
         TestCredentials creds;
         creds.key = std::make_unique<Botan::RSA_PrivateKey>(rng, 2048);

         Botan::X509_Cert_Options opts;
         opts.common_name = cn;
         opts.country = "US";
         opts.dns = "localhost";

         creds.cert = Botan::X509::create_self_signed_cert(opts, *creds.key, "SHA-256", rng);
         return creds;
      }

      // Verify parsed PKCS12 data matches original
      void verify_parsed_data(Test::Result& result,
                              const Botan::PKCS12_Data& parsed,
                              const Botan::RSA_PrivateKey& orig_key,
                              const Botan::X509_Certificate& orig_cert,
                              const std::string& expected_friendly_name = "") {
         result.test_is_true("Has private key", parsed.has_private_key());
         result.test_is_true("Has certificate", parsed.has_certificate());

         if(!expected_friendly_name.empty()) {
            result.test_str_eq("Friendly name", parsed.friendly_name(), expected_friendly_name);
         }

         if(parsed.private_key()) {
            result.test_str_eq("Key algorithm", parsed.private_key()->algo_name(), "RSA");
            const auto parsed_bits = parsed.private_key()->private_key_bits();
            const auto orig_bits = orig_key.private_key_bits();
            result.test_is_true("Key matches", parsed_bits == orig_bits);
         }

         if(parsed.certificate()) {
            result.test_is_true("Certificate matches", parsed.certificate()->BER_encode() == orig_cert.BER_encode());
         }
      }

      Test::Result test_basic_roundtrip() {
         Test::Result result("PKCS12 basic roundtrip");

         auto rng = Test::new_rng("PKCS12_basic");
         auto creds = generate_credentials(*rng);

         Botan::PKCS12_Options opts;
         opts.password = "testpassword";
         opts.friendly_name = "Basic Test Key";

         std::vector<uint8_t> pfx = Botan::PKCS12::create(*creds.key, creds.cert, opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         Botan::PKCS12_Data parsed = Botan::PKCS12::parse(pfx, "testpassword");
         verify_parsed_data(result, parsed, *creds.key, creds.cert, "Basic Test Key");

         return result;
      }

      Test::Result test_roundtrip_with_chain() {
         Test::Result result("PKCS12 roundtrip with certificate chain");

         auto rng = Test::new_rng("PKCS12_chain");

         // Generate CA
         Botan::RSA_PrivateKey ca_key(*rng, 2048);
         Botan::X509_Cert_Options ca_opts;
         ca_opts.common_name = "Test CA";
         ca_opts.country = "US";
         ca_opts.CA_key();
         Botan::X509_Certificate ca_cert = Botan::X509::create_self_signed_cert(ca_opts, ca_key, "SHA-256", *rng);

         // Create CA signer
         Botan::X509_CA ca(ca_cert, ca_key, "SHA-256", *rng);

         // Generate end-entity
         Botan::RSA_PrivateKey ee_key(*rng, 2048);
         Botan::X509_Cert_Options ee_opts;
         ee_opts.common_name = "End Entity";
         ee_opts.country = "US";
         ee_opts.dns = "localhost";

         Botan::PKCS10_Request csr = Botan::X509::create_cert_req(ee_opts, ee_key, "SHA-256", *rng);
         Botan::X509_Certificate ee_cert =
            ca.sign_request(csr, *rng, Botan::X509_Time("200101000000Z"), Botan::X509_Time("300101000000Z"));

         // Create PKCS#12 with chain
         Botan::PKCS12_Options opts;
         opts.password = "chaintest";
         opts.friendly_name = "Chain Test Key";

         std::vector<Botan::X509_Certificate> chain = {ca_cert};
         std::vector<uint8_t> pfx = Botan::PKCS12::create(ee_key, ee_cert, chain, opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         Botan::PKCS12_Data parsed = Botan::PKCS12::parse(pfx, "chaintest");

         result.test_is_true("Has private key", parsed.has_private_key());
         result.test_is_true("Has certificate", parsed.has_certificate());
         result.test_sz_eq("CA certificates count", parsed.ca_certificates().size(), 1);
         result.test_str_eq("Friendly name", parsed.friendly_name(), "Chain Test Key");

         // Verify CA cert in chain
         if(!parsed.ca_certificates().empty()) {
            result.test_is_true("CA cert matches", parsed.ca_certificates()[0]->BER_encode() == ca_cert.BER_encode());
         }

         return result;
      }

      Test::Result test_no_friendly_name() {
         Test::Result result("PKCS12 without friendly name");

         auto rng = Test::new_rng("PKCS12_no_name");
         auto creds = generate_credentials(*rng);

         Botan::PKCS12_Options opts;
         opts.password = "noname";
         // No friendly_name set

         std::vector<uint8_t> pfx = Botan::PKCS12::create(*creds.key, creds.cert, opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         Botan::PKCS12_Data parsed = Botan::PKCS12::parse(pfx, "noname");

         result.test_is_true("Has private key", parsed.has_private_key());
         result.test_is_true("Has certificate", parsed.has_certificate());
         result.test_is_true("No friendly name", parsed.friendly_name().empty());

         return result;
      }

      Test::Result test_custom_iterations() {
         Test::Result result("PKCS12 with custom iterations");

         auto rng = Test::new_rng("PKCS12_iterations");
         auto creds = generate_credentials(*rng);

         // Test with high iteration count
         Botan::PKCS12_Options opts;
         opts.password = "itertest";
         opts.iterations = 50000;

         std::vector<uint8_t> pfx = Botan::PKCS12::create(*creds.key, creds.cert, opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         Botan::PKCS12_Data parsed = Botan::PKCS12::parse(pfx, "itertest");
         verify_parsed_data(result, parsed, *creds.key, creds.cert);

         return result;
      }

      Test::Result test_key_encryption(const std::string& algo) {
         Test::Result result("PKCS12 key encryption: " + algo);

         auto rng = Test::new_rng("PKCS12_key_enc_" + algo);
         auto creds = generate_credentials(*rng);

         Botan::PKCS12_Options opts;
         opts.password = "keyenctest";
         opts.friendly_name = "Key Enc Test";
         opts.key_encryption_algo = algo;
         opts.iterations = 2048;

         std::vector<uint8_t> pfx = Botan::PKCS12::create(*creds.key, creds.cert, opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         Botan::PKCS12_Data parsed = Botan::PKCS12::parse(pfx, "keyenctest");
         verify_parsed_data(result, parsed, *creds.key, creds.cert, "Key Enc Test");

         return result;
      }

      Test::Result test_cert_encryption(const std::string& algo) {
         std::string test_name = algo.empty() ? "PKCS12 cert encryption: unencrypted" : "PKCS12 cert encryption: " + algo;
         Test::Result result(test_name);

         auto rng = Test::new_rng("PKCS12_cert_enc_" + (algo.empty() ? "none" : algo));
         auto creds = generate_credentials(*rng);

         Botan::PKCS12_Options opts;
         opts.password = "certenctest";
         opts.friendly_name = "Cert Enc Test";
         opts.cert_encryption_algo = algo;
         opts.iterations = 2048;

         std::vector<uint8_t> pfx = Botan::PKCS12::create(*creds.key, creds.cert, opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         Botan::PKCS12_Data parsed = Botan::PKCS12::parse(pfx, "certenctest");
         verify_parsed_data(result, parsed, *creds.key, creds.cert, "Cert Enc Test");

         return result;
      }

      Test::Result test_mixed_encryption(const std::string& key_algo, const std::string& cert_algo) {
         Test::Result result("PKCS12 mixed encryption: key=" + key_algo + " cert=" + cert_algo);

         auto rng = Test::new_rng("PKCS12_mixed_" + key_algo + "_" + cert_algo);
         auto creds = generate_credentials(*rng);

         Botan::PKCS12_Options opts;
         opts.password = "mixedtest";
         opts.friendly_name = "Mixed Enc Test";
         opts.key_encryption_algo = key_algo;
         opts.cert_encryption_algo = cert_algo;
         opts.iterations = 2048;

         std::vector<uint8_t> pfx = Botan::PKCS12::create(*creds.key, creds.cert, opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         Botan::PKCS12_Data parsed = Botan::PKCS12::parse(pfx, "mixedtest");
         verify_parsed_data(result, parsed, *creds.key, creds.cert, "Mixed Enc Test");

         return result;
      }

      Test::Result test_chain_with_pbes2() {
         Test::Result result("PKCS12 chain with PBES2 encryption");

         auto rng = Test::new_rng("PKCS12_chain_pbes2");

         // Generate CA
         Botan::RSA_PrivateKey ca_key(*rng, 2048);
         Botan::X509_Cert_Options ca_opts;
         ca_opts.common_name = "PBES2 CA";
         ca_opts.country = "US";
         ca_opts.CA_key();
         Botan::X509_Certificate ca_cert = Botan::X509::create_self_signed_cert(ca_opts, ca_key, "SHA-256", *rng);

         // Create intermediate CA
         Botan::X509_CA root_ca(ca_cert, ca_key, "SHA-256", *rng);

         Botan::RSA_PrivateKey int_key(*rng, 2048);
         Botan::X509_Cert_Options int_opts;
         int_opts.common_name = "Intermediate CA";
         int_opts.country = "US";
         int_opts.CA_key();

         Botan::PKCS10_Request int_csr = Botan::X509::create_cert_req(int_opts, int_key, "SHA-256", *rng);
         Botan::X509_Certificate int_cert =
            root_ca.sign_request(int_csr, *rng, Botan::X509_Time("200101000000Z"), Botan::X509_Time("300101000000Z"));

         // Create end-entity cert signed by intermediate
         Botan::X509_CA int_ca(int_cert, int_key, "SHA-256", *rng);

         Botan::RSA_PrivateKey ee_key(*rng, 2048);
         Botan::X509_Cert_Options ee_opts;
         ee_opts.common_name = "End Entity";
         ee_opts.country = "US";
         ee_opts.dns = "localhost";

         Botan::PKCS10_Request ee_csr = Botan::X509::create_cert_req(ee_opts, ee_key, "SHA-256", *rng);
         Botan::X509_Certificate ee_cert =
            int_ca.sign_request(ee_csr, *rng, Botan::X509_Time("200101000000Z"), Botan::X509_Time("300101000000Z"));

         // Create PKCS#12 with full chain and PBES2
         Botan::PKCS12_Options opts;
         opts.password = "chainpbes2";
         opts.friendly_name = "Chain PBES2 Key";
         opts.key_encryption_algo = "PBES2-SHA256-AES256";
         opts.cert_encryption_algo = "PBES2-SHA256-AES128";
         opts.iterations = 10000;

         std::vector<Botan::X509_Certificate> chain = {int_cert, ca_cert};
         std::vector<uint8_t> pfx = Botan::PKCS12::create(ee_key, ee_cert, chain, opts, *rng);
         result.test_sz_gt("PFX data generated", pfx.size(), 0);

         Botan::PKCS12_Data parsed = Botan::PKCS12::parse(pfx, "chainpbes2");

         result.test_is_true("Has private key", parsed.has_private_key());
         result.test_is_true("Has certificate", parsed.has_certificate());
         result.test_sz_eq("CA certificates count", parsed.ca_certificates().size(), 2);
         result.test_str_eq("Friendly name", parsed.friendly_name(), "Chain PBES2 Key");

         // Verify key
         if(parsed.private_key()) {
            const auto parsed_bits = parsed.private_key()->private_key_bits();
            const auto orig_bits = ee_key.private_key_bits();
            result.test_is_true("Key matches", parsed_bits == orig_bits);
         }

         // Verify end-entity cert
         if(parsed.certificate()) {
            result.test_is_true("EE cert matches", parsed.certificate()->BER_encode() == ee_cert.BER_encode());
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("x509", "pkcs12", PKCS12_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
