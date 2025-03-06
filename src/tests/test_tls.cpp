/*
* (C) 2014,2015,2017,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <fstream>
#include <memory>

#if defined(BOTAN_HAS_TLS)
   #include "test_rng.h"

   #include <botan/tls_alert.h>
   #include <botan/tls_policy.h>
   #include <botan/tls_session.h>
   #include <botan/tls_version.h>
   #include <botan/internal/fmt.h>

   #if defined(BOTAN_HAS_TLS_CBC)
      #include <botan/internal/tls_cbc.h>
   #endif

#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_TLS)

class TLS_Session_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("TLS::Session");

         Botan::TLS::Session session(Botan::secure_vector<uint8_t>{0xCC, 0xDD},
                                     Botan::TLS::Protocol_Version::TLS_V12,
                                     0xC02F,
                                     Botan::TLS::Connection_Side::Client,
                                     true,
                                     false,
                                     std::vector<Botan::X509_Certificate>(),
                                     Botan::TLS::Server_Information("server"),
                                     0x0000,
                                     std::chrono::system_clock::now());

         const std::string pem = session.PEM_encode();
         Botan::TLS::Session session_from_pem(pem);
         result.test_eq("Roundtrip from pem", session.DER_encode(), session_from_pem.DER_encode());

         const auto der = session.DER_encode();
         Botan::TLS::Session session_from_der(der);
         result.test_eq("Roundtrip from der", session.DER_encode(), session_from_der.DER_encode());

         const Botan::SymmetricKey key("ABCDEF");
         const std::vector<uint8_t> ctext1 = session.encrypt(key, this->rng());
         const std::vector<uint8_t> ctext2 = session.encrypt(key, this->rng());

         result.test_ne(
            "TLS session encryption is non-determinsitic", ctext1.data(), ctext1.size(), ctext2.data(), ctext2.size());

         const std::vector<uint8_t> expected_hdr = Botan::hex_decode("068B5A9D396C0000F2322CAE");

         result.test_eq("tls", "TLS session encryption same header", ctext1.data(), 12, expected_hdr.data(), 12);
         result.test_eq("tls", "TLS session encryption same header", ctext2.data(), 12, expected_hdr.data(), 12);

         Botan::TLS::Session dsession = Botan::TLS::Session::decrypt(ctext1.data(), ctext1.size(), key);

         Fixed_Output_RNG frng1("00112233445566778899AABBCCDDEEFF802802802802802802802802");
         const std::vector<uint8_t> ctextf1 = session.encrypt(key, frng1);
         Fixed_Output_RNG frng2("00112233445566778899AABBCCDDEEFF802802802802802802802802");
         const std::vector<uint8_t> ctextf2 = session.encrypt(key, frng2);

         result.test_eq("Only randomness comes from RNG", ctextf1, ctextf2);

         Botan::TLS::Session session2(Botan::secure_vector<uint8_t>{0xCC, 0xEE},
                                      Botan::TLS::Protocol_Version::TLS_V12,
                                      0xBAAD,  // cipher suite does not exist
                                      Botan::TLS::Connection_Side::Client,
                                      true,
                                      false,
                                      std::vector<Botan::X509_Certificate>(),
                                      Botan::TLS::Server_Information("server"),
                                      0x0000,
                                      std::chrono::system_clock::now());
         const std::string pem_with_unknown_ciphersuite = session2.PEM_encode();

         result.test_throws("unknown ciphersuite during session parsing",
                            "Serialized TLS session contains unknown cipher suite (47789)",
                            [&] { Botan::TLS::Session{pem_with_unknown_ciphersuite}; });

         return {result};
      }
};

BOTAN_REGISTER_TEST("tls", "tls_session", TLS_Session_Tests);

   #if defined(BOTAN_HAS_TLS_CBC)

class TLS_CBC_Padding_Tests final : public Text_Based_Test {
   public:
      TLS_CBC_Padding_Tests() : Text_Based_Test("tls_cbc_padding.vec", "Record,Output") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         const std::vector<uint8_t> record = vars.get_req_bin("Record");
         const size_t output = vars.get_req_sz("Output");

         uint16_t res = Botan::TLS::check_tls_cbc_padding(record.data(), record.size());

         Test::Result result("TLS CBC padding check");
         result.test_eq("Expected", res, output);
         return result;
      }
};

BOTAN_REGISTER_TEST("tls", "tls_cbc_padding", TLS_CBC_Padding_Tests);

class TLS_CBC_Tests final : public Text_Based_Test {
   public:
      class ZeroMac : public Botan::MessageAuthenticationCode {
         public:
            explicit ZeroMac(size_t mac_len) : m_mac_len(mac_len) {}

            void clear() override {}

            std::string name() const override { return "ZeroMac"; }

            size_t output_length() const override { return m_mac_len; }

            void add_data(std::span<const uint8_t> /*input*/) override {}

            void final_result(std::span<uint8_t> out) override {
               for(size_t i = 0; i != m_mac_len; ++i) {
                  out[i] = 0;
               }
            }

            bool has_keying_material() const override { return true; }

            Botan::Key_Length_Specification key_spec() const override {
               return Botan::Key_Length_Specification(0, 0, 1);
            }

            std::unique_ptr<MessageAuthenticationCode> new_object() const override {
               return std::make_unique<ZeroMac>(m_mac_len);
            }

         private:
            void key_schedule(std::span<const uint8_t> /* key */) override {}

            size_t m_mac_len;
      };

      class Noop_Block_Cipher : public Botan::BlockCipher {
         public:
            explicit Noop_Block_Cipher(size_t bs) : m_bs(bs) {}

            void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override {
               Botan::copy_mem(out, in, blocks * m_bs);
            }

            void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override {
               Botan::copy_mem(out, in, blocks * m_bs);
            }

            size_t block_size() const override { return m_bs; }

            void clear() override {}

            std::string name() const override { return "noop"; }

            bool has_keying_material() const override { return true; }

            Botan::Key_Length_Specification key_spec() const override {
               return Botan::Key_Length_Specification(0, 0, 1);
            }

            std::unique_ptr<BlockCipher> new_object() const override {
               return std::make_unique<Noop_Block_Cipher>(m_bs);
            }

         private:
            void key_schedule(std::span<const uint8_t> /*key*/) override {}

            size_t m_bs;
      };

      TLS_CBC_Tests() : Text_Based_Test("tls_cbc.vec", "Blocksize,MACsize,Record,Valid") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("TLS CBC");

         const size_t block_size = vars.get_req_sz("Blocksize");
         const size_t mac_len = vars.get_req_sz("MACsize");
         const std::vector<uint8_t> record = vars.get_req_bin("Record");
         const bool is_valid = vars.get_req_sz("Valid") == 1;

         // todo test permutations
         bool encrypt_then_mac = false;

         Botan::TLS::TLS_CBC_HMAC_AEAD_Decryption tls_cbc(std::make_unique<Noop_Block_Cipher>(block_size),
                                                          std::make_unique<ZeroMac>(mac_len),
                                                          0,
                                                          0,
                                                          Botan::TLS::Protocol_Version::TLS_V12,
                                                          encrypt_then_mac);

         tls_cbc.set_key(std::vector<uint8_t>(0));
         std::vector<uint8_t> ad(13);
         tls_cbc.set_associated_data(ad.data(), ad.size());

         Botan::secure_vector<uint8_t> vec(record.begin(), record.end());

         try {
            tls_cbc.finish(vec, 0);
            if(is_valid) {
               result.test_success("Accepted valid TLS-CBC ciphertext");
            } else {
               result.test_failure("Accepted invalid TLS-CBC ciphertext");
            }
         } catch(std::exception&) {
            if(is_valid) {
               result.test_failure("Rejected valid TLS-CBC ciphertext");
            } else {
               result.test_success("Accepted invalid TLS-CBC ciphertext");
            }
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("tls", "tls_cbc", TLS_CBC_Tests);

   #endif

class Test_TLS_Alert_Strings : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("TLS::Alert::type_string");

         const std::vector<Botan::TLS::Alert::Type> alert_types = {
            Botan::TLS::Alert::CloseNotify,
            Botan::TLS::Alert::UnexpectedMessage,
            Botan::TLS::Alert::BadRecordMac,
            Botan::TLS::Alert::DecryptionFailed,
            Botan::TLS::Alert::RecordOverflow,
            Botan::TLS::Alert::DecompressionFailure,
            Botan::TLS::Alert::HandshakeFailure,
            Botan::TLS::Alert::NoCertificate,
            Botan::TLS::Alert::BadCertificate,
            Botan::TLS::Alert::UnsupportedCertificate,
            Botan::TLS::Alert::CertificateRevoked,
            Botan::TLS::Alert::CertificateExpired,
            Botan::TLS::Alert::CertificateUnknown,
            Botan::TLS::Alert::IllegalParameter,
            Botan::TLS::Alert::UnknownCA,
            Botan::TLS::Alert::AccessDenied,
            Botan::TLS::Alert::DecodeError,
            Botan::TLS::Alert::DecryptError,
            Botan::TLS::Alert::ExportRestriction,
            Botan::TLS::Alert::ProtocolVersion,
            Botan::TLS::Alert::InsufficientSecurity,
            Botan::TLS::Alert::InternalError,
            Botan::TLS::Alert::InappropriateFallback,
            Botan::TLS::Alert::UserCanceled,
            Botan::TLS::Alert::NoRenegotiation,
            Botan::TLS::Alert::MissingExtension,
            Botan::TLS::Alert::UnsupportedExtension,
            Botan::TLS::Alert::CertificateUnobtainable,
            Botan::TLS::Alert::UnrecognizedName,
            Botan::TLS::Alert::BadCertificateStatusResponse,
            Botan::TLS::Alert::BadCertificateHashValue,
            Botan::TLS::Alert::UnknownPSKIdentity,
            Botan::TLS::Alert::NoApplicationProtocol,
         };

         std::set<std::string> seen;

         for(auto alert : alert_types) {
            const std::string str = Botan::TLS::Alert(alert).type_string();
            result.test_eq("No duplicate strings", seen.count(str), 0);
            seen.insert(str);
         }

         Botan::TLS::Alert unknown_alert = Botan::TLS::Alert({01, 66});

         result.test_eq("Unknown alert str", unknown_alert.type_string(), "unrecognized_alert_66");

         return {result};
      }
};

BOTAN_REGISTER_TEST("tls", "tls_alert_strings", Test_TLS_Alert_Strings);

   #if defined(BOTAN_HAS_TLS_13) && defined(BOTAN_HAS_TLS_13_PQC) && defined(BOTAN_HAS_X25519) && \
      defined(BOTAN_HAS_X448)

class Test_TLS_Policy_Text : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("TLS Policy");

         const std::vector<std::string> policies = {"default", "suiteb_128", "suiteb_192", "strict", "datagram", "bsi"};

         for(const std::string& policy : policies) {
            const std::string from_policy_obj = tls_policy_string(policy);

            const std::string policy_file = policy + (policy == "default" || policy == "strict" ? "_tls13" : "");

            const std::string from_file = read_tls_policy(policy_file);

            if(from_policy_obj != from_file) {
               std::string d = diff(from_policy_obj, from_file);
               result.test_failure(Botan::fmt("Values for TLS policy from {} don't match (diff {})", policy_file, d));
            } else {
               result.test_success("Values from TLS policy from " + policy_file + " match");
            }
         }

         return {result};
      }

   private:
      static std::string diff(const std::string& a_str, const std::string& b_str) {
         std::istringstream a_ss(a_str);
         std::istringstream b_ss(b_str);

         std::ostringstream diff;

         for(;;) {
            if(!a_ss && !b_ss) {
               break;  // done
            }

            std::string a_line;
            std::getline(a_ss, a_line, '\n');

            std::string b_line;
            std::getline(b_ss, b_line, '\n');

            if(a_line != b_line) {
               diff << "- " << a_line << "\n"
                    << "+ " << b_line << "\n";
            }
         }

         return diff.str();
      }

      static std::string read_tls_policy(const std::string& policy_str) {
         const std::string fspath = Test::data_file("tls-policy/" + policy_str + ".txt");

         std::ifstream is(fspath.c_str());
         if(!is.good()) {
            throw Test_Error("Missing policy file " + fspath);
         }

         Botan::TLS::Text_Policy policy(is);
         return policy.to_string();
      }

      static std::string tls_policy_string(const std::string& policy_str) {
         std::unique_ptr<Botan::TLS::Policy> policy;
         if(policy_str == "default") {
            policy = std::make_unique<Botan::TLS::Policy>();
         } else if(policy_str == "suiteb_128") {
            policy = std::make_unique<Botan::TLS::NSA_Suite_B_128>();
         } else if(policy_str == "suiteb_192") {
            policy = std::make_unique<Botan::TLS::NSA_Suite_B_192>();
         } else if(policy_str == "bsi") {
            policy = std::make_unique<Botan::TLS::BSI_TR_02102_2>();
         } else if(policy_str == "strict") {
            policy = std::make_unique<Botan::TLS::Strict_Policy>();
         } else if(policy_str == "datagram") {
            policy = std::make_unique<Botan::TLS::Datagram_Policy>();
         } else {
            throw Test_Error("Unknown TLS policy type '" + policy_str + "'");
         }

         return policy->to_string();
      }
};

BOTAN_REGISTER_TEST("tls", "tls_policy_text", Test_TLS_Policy_Text);
   #endif

class Test_TLS_Ciphersuites : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("TLS::Ciphersuite");

         for(size_t csuite_id = 0; csuite_id <= 0xFFFF; ++csuite_id) {
            const uint16_t csuite_id16 = static_cast<uint16_t>(csuite_id);
            auto ciphersuite = Botan::TLS::Ciphersuite::by_id(csuite_id16);

            if(ciphersuite && ciphersuite->valid()) {
               result.test_eq("Valid Ciphersuite is not SCSV", Botan::TLS::Ciphersuite::is_scsv(csuite_id16), false);

               if(ciphersuite->cbc_ciphersuite() == false) {
                  result.test_eq("Expected AEAD ciphersuite", ciphersuite->aead_ciphersuite(), true);
                  result.test_eq("Expected MAC name for AEAD ciphersuites", ciphersuite->mac_algo(), "AEAD");
               } else {
                  result.test_eq("Did not expect AEAD ciphersuite", ciphersuite->aead_ciphersuite(), false);
                  result.test_eq(
                     "MAC algo and PRF algo same for CBC suites", ciphersuite->prf_algo(), ciphersuite->mac_algo());
               }

               // TODO more tests here
            }
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("tls", "tls_ciphersuites", Test_TLS_Ciphersuites);

class Test_TLS_Algo_Strings : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_auth_method_strings());
         results.push_back(test_kex_algo_strings());
         results.push_back(test_tls_sig_method_strings());

         return results;
      }

   private:
      static Test::Result test_tls_sig_method_strings() {
         Test::Result result("TLS::Signature_Scheme");

         std::vector<Botan::TLS::Signature_Scheme> schemes = Botan::TLS::Signature_Scheme::all_available_schemes();

         std::set<std::string> scheme_strs;
         for(auto scheme : schemes) {
            std::string scheme_str = scheme.to_string();

            result.test_eq("Scheme strings unique", scheme_strs.count(scheme_str), 0);

            scheme_strs.insert(scheme_str);
         }

         return result;
      }

      static Test::Result test_auth_method_strings() {
         Test::Result result("TLS::Auth_Method");

         const std::vector<Botan::TLS::Auth_Method> auth_methods({
            Botan::TLS::Auth_Method::RSA,
            Botan::TLS::Auth_Method::ECDSA,
            Botan::TLS::Auth_Method::IMPLICIT,
         });

         for(Botan::TLS::Auth_Method meth : auth_methods) {
            std::string meth_str = Botan::TLS::auth_method_to_string(meth);
            result.test_ne("Method string is not empty", meth_str, "");
            Botan::TLS::Auth_Method meth2 = Botan::TLS::auth_method_from_string(meth_str);
            result.confirm("Decoded method matches", meth == meth2);
         }

         return result;
      }

      static Test::Result test_kex_algo_strings() {
         Test::Result result("TLS::Kex_Algo");

         const std::vector<Botan::TLS::Kex_Algo> kex_algos({Botan::TLS::Kex_Algo::STATIC_RSA,
                                                            Botan::TLS::Kex_Algo::DH,
                                                            Botan::TLS::Kex_Algo::ECDH,
                                                            Botan::TLS::Kex_Algo::PSK,
                                                            Botan::TLS::Kex_Algo::ECDHE_PSK});

         for(Botan::TLS::Kex_Algo meth : kex_algos) {
            std::string meth_str = Botan::TLS::kex_method_to_string(meth);
            result.test_ne("Method string is not empty", meth_str, "");
            Botan::TLS::Kex_Algo meth2 = Botan::TLS::kex_method_from_string(meth_str);
            result.confirm("Decoded method matches", meth == meth2);
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("tls", "tls_algo_strings", Test_TLS_Algo_Strings);

#endif

}  // namespace Botan_Tests
