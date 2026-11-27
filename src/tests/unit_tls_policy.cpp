/*
* TLS Policy tests
*
* (C) 2016 Juraj Somorovsky
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS)
   #include <botan/assert.h>
   #include <botan/certstor.h>
   #include <botan/ocsp.h>
   #include <botan/pk_keys.h>
   #include <botan/tls_callbacks.h>
   #include <botan/tls_ciphersuite.h>
   #include <botan/tls_exceptn.h>
   #include <botan/tls_policy.h>
   #include <botan/x509_crl.h>
   #include <botan/x509cert.h>
   #include <botan/internal/calendar.h>
#endif

#if defined(BOTAN_HAS_RSA)
   #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_group.h>
#endif

#if defined(BOTAN_HAS_ECDH)
   #include <botan/ecdh.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
   #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   #include <botan/dh.h>
   #include <botan/dl_group.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_TLS)
class Null_Callbacks final : public Botan::TLS::Callbacks {
   public:
      void tls_emit_data(std::span<const uint8_t> /*data*/) override {}

      void tls_record_received(uint64_t /*seq_no*/, std::span<const uint8_t> /*data*/) override {}

      void tls_alert(Botan::TLS::Alert /*alert*/) override {}
};

class TLS_Policy_Unit_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_peer_key_acceptable_rsa(this->rng()));
         results.push_back(test_peer_key_acceptable_ecdh(this->rng()));
         results.push_back(test_peer_key_acceptable_ecdsa(this->rng()));
         results.push_back(test_peer_key_acceptable_dh());
         results.push_back(test_key_exchange_groups_to_offer());
         results.push_back(test_require_extended_master_secret());
         results.push_back(test_dtls_refuses_weak_ciphersuites());
         results.push_back(test_default_groups_are_available());
         results.push_back(test_group_availability_matches_key_generation(this->rng()));
         results.push_back(test_cert_chain_validation());
   #if defined(BOTAN_HAS_TLS_13_PQC) && defined(BOTAN_HAS_ML_KEM) && defined(BOTAN_HAS_X25519)
         results.push_back(test_hybrid_peer_key_acceptable(this->rng()));
   #endif

         return results;
      }

   #if defined(BOTAN_HAS_TLS_13_PQC) && defined(BOTAN_HAS_ML_KEM) && defined(BOTAN_HAS_X25519)
      static Test::Result test_hybrid_peer_key_acceptable(Botan::RandomNumberGenerator& rng) {
         Test::Result result("TLS Policy minimum ECDH group size applies to hybrid groups");

         class Min_ECDH_384_Policy final : public Botan::TLS::Policy {
            public:
               size_t minimum_ecdh_group_size() const override { return 384; }
         };

         Null_Callbacks callbacks;
         const auto group = Botan::TLS::Group_Params::HYBRID_X25519_ML_KEM_768;
         const auto key = callbacks.tls_kem_generate_key(group, rng);
         const auto key_share = key->raw_public_key_bits();

         result.test_throws<Botan::TLS::TLS_Exception>("X25519 component is too small", [&] {
            callbacks.tls_kem_encapsulate(group, key_share, rng, Min_ECDH_384_Policy());
         });
         result.test_no_throw("accepted by the default policy",
                              [&] { callbacks.tls_kem_encapsulate(group, key_share, rng, Botan::TLS::Policy()); });

         return result;
      }
   #endif

      static Test::Result test_default_groups_are_available() {
         Test::Result result("TLS Policy default groups are available");

         const Botan::TLS::Policy policy;
         for(const auto group : policy.key_exchange_groups()) {
            result.test_is_true(group.to_string().value_or("unknown") + " is available", group.is_available());
         }

         return result;
      }

      static Test::Result test_group_availability_matches_key_generation(Botan::RandomNumberGenerator& rng) {
         Test::Result result("TLS group availability matches key generation");

         Null_Callbacks callbacks;
         for(uint32_t code = 0; code <= 0xFFFF; ++code) {
            const Botan::TLS::Group_Params group(static_cast<uint16_t>(code));
            const auto name = group.to_string();
            if(!name.has_value()) {
               continue;
            }

            bool generated = false;
            try {
               generated = callbacks.tls_kem_generate_key(group, rng) != nullptr;
            } catch(const std::exception&) {}

            result.test_bool_eq(name.value() + " is available", group.is_available(), generated);
         }

         return result;
      }

      // RFC 9147 4.5.3 forbids _CCM_8 in DTLS absent forgery safeguards Botan does
      // not implement, and CBC+HMAC keeps a residual timing channel that DTLS
      // makes observable many times per association. Both are refused for DTLS
      // while remaining available to stream TLS.
      static Test::Result test_dtls_refuses_weak_ciphersuites() {
         Test::Result result("TLS Policy DTLS ciphersuite refusals");

         class Permissive_Policy final : public Botan::TLS::Policy {
            public:
               std::vector<std::string> allowed_ciphers() const override {
                  return {"AES-256/CCM(8)", "AES-128/CCM(8)", "AES-256/CCM", "AES-128/CCM", "AES-128/GCM", "AES-128"};
               }

               std::vector<std::string> allowed_macs() const override { return {"AEAD", "SHA-256", "SHA-1"}; }

               bool allow_tls12() const override { return true; }

               bool allow_dtls12() const override { return true; }
         };

         const Permissive_Policy policy;

         const auto classify = [&](Botan::TLS::Protocol_Version version) {
            size_t ccm_8 = 0;
            size_t cbc = 0;
            for(const auto id : policy.ciphersuite_list(version)) {
               const auto suite = Botan::TLS::Ciphersuite::by_id(id);
               if(!suite.has_value()) {
                  continue;
               }
               if(suite->uses_short_authentication_tag()) {
                  ccm_8 += 1;
               }
               if(suite->cbc_ciphersuite()) {
                  cbc += 1;
               }
            }
            return std::make_pair(ccm_8, cbc);
         };

         const auto [tls_ccm_8, tls_cbc] = classify(Botan::TLS::Protocol_Version::TLS_V12);
         const auto [dtls_ccm_8, dtls_cbc] = classify(Botan::TLS::Protocol_Version::DTLS_V12);

         // Guard against the test passing because the policy offered none at all.
   #if defined(BOTAN_HAS_AEAD_CCM)
         result.test_is_true("TLS 1.2 still offers CCM_8 suites", tls_ccm_8 > 0);
   #endif
   #if defined(BOTAN_HAS_TLS_CBC)
         result.test_is_true("TLS 1.2 still offers CBC suites", tls_cbc > 0);
   #endif
         BOTAN_UNUSED(tls_ccm_8, tls_cbc);

         result.test_sz_eq("DTLS 1.2 offers no CCM_8 suite", dtls_ccm_8, 0);
         result.test_sz_eq("DTLS 1.2 offers no CBC suite", dtls_cbc, 0);
         result.test_sz_gte("DTLS 1.2 still has usable suites",
                            policy.ciphersuite_list(Botan::TLS::Protocol_Version::DTLS_V12).size(),
                            1);

         return result;
      }

      static Test::Result test_require_extended_master_secret() {
         Test::Result result("TLS Policy require_extended_master_secret");

         const Botan::TLS::Policy default_policy;
         result.test_is_true("default Policy requires EMS", default_policy.require_extended_master_secret());

         using TP = Botan::TLS::Text_Policy;
         result.test_is_true("default text policy requires EMS", TP("").require_extended_master_secret());
         result.test_is_true("text policy override disables EMS requirement",
                             !TP("require_extended_master_secret = false").require_extended_master_secret());
         result.test_is_true("text policy override re-enables EMS requirement",
                             TP("require_extended_master_secret = true").require_extended_master_secret());
         return result;
      }

   private:
      static Test::Result test_peer_key_acceptable_rsa([[maybe_unused]] Botan::RandomNumberGenerator& rng) {
         Test::Result result("TLS Policy RSA key verification");
   #if defined(BOTAN_HAS_RSA)
         const auto rsa_key_1024 = std::make_unique<Botan::RSA_PrivateKey>(rng, 1024);
         const Botan::TLS::Policy policy;

         try {
            policy.check_peer_key_acceptable(*rsa_key_1024);
            result.test_failure("Incorrectly accepting 1024 bit RSA keys");
         } catch(Botan::TLS::TLS_Exception&) {
            result.test_success("Correctly rejecting 1024 bit RSA keys");
         }

         const auto rsa_key_2048 = std::make_unique<Botan::RSA_PrivateKey>(rng, 2048);
         policy.check_peer_key_acceptable(*rsa_key_2048);
         result.test_success("Correctly accepting 2048 bit RSA keys");
   #endif
         return result;
      }

      static Test::Result test_peer_key_acceptable_ecdh([[maybe_unused]] Botan::RandomNumberGenerator& rng) {
         Test::Result result("TLS Policy ECDH key verification");
   #if defined(BOTAN_HAS_ECDH)

         const Botan::TLS::Policy policy;

         if(Botan::EC_Group::supports_named_group("secp192r1")) {
            const auto group_192 = Botan::EC_Group::from_name("secp192r1");
            const auto ecdh_192 = std::make_unique<Botan::ECDH_PrivateKey>(rng, group_192);

            try {
               policy.check_peer_key_acceptable(*ecdh_192);
               result.test_failure("Incorrectly accepting 192 bit EC keys");
            } catch(Botan::TLS::TLS_Exception&) {
               result.test_success("Correctly rejecting 192 bit EC keys");
            }
         }

         if(Botan::EC_Group::supports_named_group("secp256r1")) {
            const auto group_256 = Botan::EC_Group::from_name("secp256r1");
            const auto ecdh_256 = std::make_unique<Botan::ECDH_PrivateKey>(rng, group_256);
            policy.check_peer_key_acceptable(*ecdh_256);
            result.test_success("Correctly accepting 256 bit EC keys");
         }
   #endif
         return result;
      }

      static Test::Result test_peer_key_acceptable_ecdsa([[maybe_unused]] Botan::RandomNumberGenerator& rng) {
         Test::Result result("TLS Policy ECDSA key verification");
   #if defined(BOTAN_HAS_ECDSA)
         const Botan::TLS::Policy policy;

         if(Botan::EC_Group::supports_named_group("secp192r1")) {
            const auto group_192 = Botan::EC_Group::from_name("secp192r1");
            const auto ecdsa_192 = std::make_unique<Botan::ECDSA_PrivateKey>(rng, group_192);

            try {
               policy.check_peer_key_acceptable(*ecdsa_192);
               result.test_failure("Incorrectly accepting 192 bit EC keys");
            } catch(Botan::TLS::TLS_Exception&) {
               result.test_success("Correctly rejecting 192 bit EC keys");
            }
         }

         if(Botan::EC_Group::supports_named_group("secp256r1")) {
            const auto group_256 = Botan::EC_Group::from_name("secp256r1");
            const auto ecdsa_256 = std::make_unique<Botan::ECDSA_PrivateKey>(rng, group_256);
            policy.check_peer_key_acceptable(*ecdsa_256);
            result.test_success("Correctly accepting 256 bit EC keys");
         }
   #endif
         return result;
      }

      static Test::Result test_peer_key_acceptable_dh() {
         Test::Result result("TLS Policy DH key verification");
   #if defined(BOTAN_HAS_DIFFIE_HELLMAN)
         const BigInt g("2");
         const BigInt p("58458002095536094658683755258523362961421200751439456159756164191494576279467");
         const Botan::DL_Group grp(p, g);
         const Botan::BigInt x("46205663093589612668746163860870963912226379131190812163519349848291472898748");
         const auto dhkey = std::make_unique<Botan::DH_PrivateKey>(grp, x);

         const Botan::TLS::Policy policy;
         try {
            policy.check_peer_key_acceptable(*dhkey);
            result.test_failure("Incorrectly accepting short bit DH keys");
         } catch(Botan::TLS::TLS_Exception&) {
            result.test_success("Correctly rejecting short bit DH keys");
         }
   #endif
         return result;
      }

      static Test::Result test_cert_chain_validation() {
         Test::Result result("TLS Policy certificate chain validation");

   #if defined(BOTAN_HAS_ECDSA) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
         class Fixed_Time_Callbacks final : public Botan::TLS::Callbacks {
            public:
               void tls_emit_data(std::span<const uint8_t> /*data*/) override {}

               void tls_record_received(uint64_t /*seq_no*/, std::span<const uint8_t> /*data*/) override {}

               void tls_alert(Botan::TLS::Alert /*alert*/) override {}

               explicit Fixed_Time_Callbacks(std::chrono::system_clock::time_point now) : m_now(now) {}

               std::chrono::system_clock::time_point tls_current_timestamp() override { return m_now; }

            private:
               std::chrono::system_clock::time_point m_now;
         };

         // The CA has a P-256 key and signs with SHA-256
         const Botan::X509_Certificate ca(Test::data_file("x509/crl_hash/ca.pem"));
         const Botan::X509_Certificate leaf(Test::data_file("x509/crl_hash/leaf.pem"));
         const Botan::X509_CRL crl_sha256(Test::data_file("x509/crl_hash/crl_sha256.pem"));
         const Botan::X509_CRL crl_sha1(Test::data_file("x509/crl_hash/crl_sha1.pem"));

         using TP = Botan::TLS::Text_Policy;

         const auto chain_is_accepted = [&](const std::optional<Botan::X509_CRL>& crl, const TP& policy) {
            Botan::Certificate_Store_In_Memory trusted;
            trusted.add_certificate(ca);
            if(crl.has_value()) {
               trusted.add_crl(crl.value());
            }

            Fixed_Time_Callbacks callbacks(Botan::calendar_point(2027, 1, 1, 0, 0, 0).to_std_timepoint());
            try {
               callbacks.tls_verify_cert_chain({leaf}, {}, {&trusted}, Botan::Usage_Type::UNSPECIFIED, "", policy);
               return true;
            } catch(Botan::TLS::TLS_Exception&) {
               return false;
            }
         };

         result.test_is_true("Chain accepted by default policy", chain_is_accepted(crl_sha256, TP("")));

         result.test_is_false("Chain rejected without revocation information", chain_is_accepted(std::nullopt, TP("")));
         result.test_is_true("Chain accepted without revocation information if not required",
                             chain_is_accepted(std::nullopt, TP("require_cert_revocation_info = false")));

         result.test_is_true("Chain accepted at the strength of the issuer key",
                             chain_is_accepted(crl_sha256, TP("minimum_signature_strength = 128")));
         result.test_is_false("Chain rejected above the strength of the issuer key",
                              chain_is_accepted(crl_sha256, TP("minimum_signature_strength = 129")));

         result.test_is_false("SHA-1 signed CRL not used by default", chain_is_accepted(crl_sha1, TP("")));
         result.test_is_false("SHA-1 signed CRL not used at 80 bit strength",
                              chain_is_accepted(crl_sha1, TP("minimum_signature_strength = 80")));
         result.test_is_true("SHA-256 signed CRL used at 80 bit strength",
                             chain_is_accepted(crl_sha256, TP("minimum_signature_strength = 80")));

         result.test_is_true("Chain accepted at the size of the ECDSA issuer key",
                             chain_is_accepted(crl_sha256, TP("minimum_ecdsa_group_size = 256")));
         result.test_is_false("Chain rejected above the size of the ECDSA issuer key",
                              chain_is_accepted(crl_sha256, TP("minimum_ecdsa_group_size = 257")));
         result.test_is_false(
            "Minimum ECDSA size applies whatever the minimum strength",
            chain_is_accepted(crl_sha256, TP("minimum_signature_strength = 80\nminimum_ecdsa_group_size = 384")));
         result.test_is_true("Minimum RSA size does not apply to ECDSA keys",
                             chain_is_accepted(crl_sha256, TP("minimum_rsa_bits = 4096")));

      #if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EMSA_PKCS1)
         // Here both the intermediate and the root have 2048 bit RSA keys
         const Botan::X509_Certificate rsa_leaf(Test::data_file("x509/ocsp/bdr.pem"));
         const Botan::X509_Certificate rsa_int(Test::data_file("x509/ocsp/bdr-int.pem"));
         const Botan::X509_Certificate rsa_root(Test::data_file("x509/ocsp/bdr-root.pem"));

         const auto rsa_chain_is_accepted = [&](const std::string& policy_text) {
            Botan::Certificate_Store_In_Memory trusted;
            trusted.add_certificate(rsa_root);

            const TP policy("require_cert_revocation_info = false\n" + policy_text);

            Fixed_Time_Callbacks callbacks(Botan::calendar_point(2022, 9, 19, 16, 30, 0).to_std_timepoint());
            try {
               callbacks.tls_verify_cert_chain(
                  {rsa_leaf, rsa_int}, {}, {&trusted}, Botan::Usage_Type::UNSPECIFIED, "", policy);
               return true;
            } catch(Botan::TLS::TLS_Exception&) {
               return false;
            }
         };

         result.test_is_true("RSA chain accepted by default sizes", rsa_chain_is_accepted(""));
         result.test_is_true("RSA chain accepted at the size of the issuer keys",
                             rsa_chain_is_accepted("minimum_rsa_bits = 2048"));
         result.test_is_false("RSA chain rejected above the size of the issuer keys",
                              rsa_chain_is_accepted("minimum_rsa_bits = 2049"));
         result.test_is_false("Minimum RSA size applies whatever the minimum strength",
                              rsa_chain_is_accepted("minimum_signature_strength = 80\nminimum_rsa_bits = 3072"));
         result.test_is_false("Minimum strength applies whatever the minimum RSA size",
                              rsa_chain_is_accepted("minimum_signature_strength = 128\nminimum_rsa_bits = 1024"));
         result.test_is_true("Minimum ECDSA size does not apply to RSA keys",
                             rsa_chain_is_accepted("minimum_ecdsa_group_size = 521"));
      #endif
   #endif

         return result;
      }

      static Test::Result test_key_exchange_groups_to_offer() {
         Test::Result result("TLS Policy key share offering");

         const Botan::TLS::Policy default_policy;
         result.test_sz_eq(
            "default TLS Policy offers exactly one", default_policy.key_exchange_groups_to_offer().size(), 1);
         result.test_is_true(
            "default TLS Policy offers preferred group",
            default_policy.key_exchange_groups().front() == default_policy.key_exchange_groups_to_offer().front());

         using TP = Botan::TLS::Text_Policy;

         result.test_sz_eq(
            "default behaviour from text policy (size)", TP("").key_exchange_groups_to_offer().size(), 1);
         result.test_is_true("default behaviour from text policy (preferred)",
                             TP("").key_exchange_groups().front() == TP("").key_exchange_groups_to_offer().front());

         result.test_is_true("no offerings",
                             TP("key_exchange_groups_to_offer = none").key_exchange_groups_to_offer().empty());

         const std::string two_groups = "key_exchange_groups_to_offer = secp256r1 ffdhe/ietf/4096";
         result.test_sz_eq("list of offerings (size)", TP(two_groups).key_exchange_groups_to_offer().size(), 2);
         result.test_is_true("list of offerings (0)",
                             TP(two_groups).key_exchange_groups_to_offer()[0] == Botan::TLS::Group_Params::SECP256R1);
         result.test_is_true("list of offerings (1)",
                             TP(two_groups).key_exchange_groups_to_offer()[1] == Botan::TLS::Group_Params::FFDHE_4096);

         return result;
      }
};

BOTAN_REGISTER_TEST("tls", "tls_policy", TLS_Policy_Unit_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
