/*
* (C) 2025 Jack Lloyd
*     2025 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "perf.h"
#include <algorithm>

// Always available:
#include <botan/assert.h>

#if defined(BOTAN_HAS_X509)
   #include <botan/ber_dec.h>
   #include <botan/bigint.h>
   #include <botan/der_enc.h>
   #include <botan/pk_algs.h>
   #include <botan/x509_builder.h>
   #include <botan/x509_ca.h>
   #include <botan/x509_ext.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_X509) && defined(BOTAN_HAS_ML_DSA)

class PerfTest_ASN1_Parsing final : public PerfTest {
   private:
      struct CA {
            std::unique_ptr<Botan::Private_Key> root_key;
            Botan::X509_CA ca;
      };

   private:
      static std::string_view get_hash_function() { return "SHAKE-256(512)"; }

      static std::unique_ptr<Botan::Private_Key> create_private_key(Botan::RandomNumberGenerator& rng) {
         return Botan::create_private_key("ML-DSA", rng, "ML-DSA-6x5");
      }

      static CA create_ca(Botan::RandomNumberGenerator& rng) {
         auto root_key = create_private_key(rng);
         BOTAN_ASSERT_NONNULL(root_key);

         Botan::CertificateParametersBuilder root_cert_params;
         root_cert_params.add_common_name("Benchmark Root")
            .add_country("DE")
            .add_organization("RS")
            .add_organizational_unit("CS")
            .add_dns("unobtainium.example.com")
            .add_email("idont@exist.com")
            .set_as_ca_certificate();

         const auto not_before = std::chrono::system_clock::now();
         const auto not_after = not_before + std::chrono::seconds(86400);

         auto root_cert =
            root_cert_params.into_self_signed_cert(not_before, not_after, *root_key, rng, get_hash_function());
         auto ca = Botan::X509_CA(root_cert, *root_key, get_hash_function(), rng);

         return CA{
            std::move(root_key),
            std::move(ca),
         };
      }

      static Botan::X509_Certificate make_certificate(std::string_view common_name,
                                                      CA& ca,
                                                      Botan::RandomNumberGenerator& rng) {
         Botan::X509_DN subject;
         subject.add_attribute("X520.CommonName", common_name);
         subject.add_attribute("X520.Country", "DE");
         subject.add_attribute("X520.State", "Berlin");
         subject.add_attribute("X520.Organization", "RS");
         subject.add_attribute("X520.OrganizationalUnit", "CS");

         Botan::AlternativeName an;
         an.add_dns("gibtsnicht.example.com");
         an.add_email("not.available@anywhere.com");

         Botan::Extensions exts;
         exts.add(std::make_unique<Botan::Cert_Extension::Subject_Alternative_Name>(an));

         const auto cert_key = create_private_key(rng);
         BOTAN_ASSERT_NONNULL(cert_key);
         const auto cert_req = Botan::PKCS10_Request::create(*cert_key, subject, exts, get_hash_function(), rng);

         const auto now = std::chrono::system_clock::now();
         using namespace std::chrono_literals;
         return ca.ca.sign_request(cert_req, rng, Botan::X509_Time(now), Botan::X509_Time(now + 24h * 365));
      }

      static Botan::X509_CRL make_revocation_list(size_t entries, CA& ca, Botan::RandomNumberGenerator& rng) {
         const auto empty_crl = ca.ca.new_crl(rng);

         std::vector<Botan::CRL_Entry> crl_entries(entries);
         std::generate(crl_entries.begin(), crl_entries.end(), [&] {
            std::vector<uint8_t> crl_entry_buffer;

            // Generating the CRL entries through their ASN.1 structure because
            // our public API does not allow creating them without the actual
            // certificate that is supposed to be revoked.
            Botan::Extensions exts;
            exts.add(std::make_unique<Botan::Cert_Extension::CRL_ReasonCode>(Botan::CRL_Code::KeyCompromise));
            Botan::DER_Encoder(crl_entry_buffer)
               .start_sequence()
               .encode(Botan::BigInt::from_bytes(rng.random_array<16>()))
               .encode(Botan::X509_Time(std::chrono::system_clock::now()))
               .start_sequence()
               .encode(exts)
               .end_cons()
               .end_cons();

            Botan::BER_Decoder ber(crl_entry_buffer);

            Botan::CRL_Entry entry;
            entry.decode_from(ber);
            return entry;
         });

         return ca.ca.update_crl(empty_crl, crl_entries, rng);
      }

   public:
      void go(const PerfConfig& config) override {
         auto ca = create_ca(config.rng());
         auto cert = make_certificate("Test Certificate", ca, config.rng());
         auto crl = make_revocation_list(500, ca, config.rng());

         const auto cert_encoded = cert.BER_encode();
         const auto crl_encoded = crl.BER_encode();

         auto cert_timer = config.make_timer("X509 Certificate Parsing");
         auto crl_timer = config.make_timer("X509 CRL Parsing");

         const auto runtime = config.runtime();

         while(cert_timer->under(runtime)) {
            cert_timer->start();
            std::ignore = Botan::X509_Certificate(cert_encoded);
            cert_timer->stop();
         }

         while(crl_timer->under(runtime)) {
            crl_timer->start();
            std::ignore = Botan::X509_CRL(crl_encoded);
            crl_timer->stop();
         }

         config.record_result(*cert_timer);
         config.record_result(*crl_timer);
      }
};

BOTAN_REGISTER_PERF_TEST("asn1_parsing", PerfTest_ASN1_Parsing);

#endif

}  // namespace Botan_CLI
