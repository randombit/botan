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

  #if defined(BOTAN_HAS_TLS_CBC)
     #include <botan/internal/tls_cbc.h>
  #endif

#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_TLS)

class TLS_Session_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("TLS::Session");

         Botan::TLS::Session default_session;

         Botan::secure_vector<uint8_t> default_der = default_session.DER_encode();

         result.test_gte("Encoded default session has size", default_der.size(), 0);

         Botan::TLS::Session decoded_default(default_der.data(), default_der.size());

         Botan::TLS::Session session(std::vector<uint8_t>{0xAA, 0xBB},
                                     Botan::secure_vector<uint8_t>{0xCC, 0xDD},
                                     Botan::TLS::Protocol_Version::TLS_V12,
                                     0xFE0F,
                                     Botan::TLS::CLIENT,
                                     true,
                                     false,
                                     std::vector<Botan::X509_Certificate>(),
                                     std::vector<uint8_t>(),
                                     Botan::TLS::Server_Information("server"),
                                     "SRP username",
                                     0x0000);

         const std::string pem = session.PEM_encode();
         Botan::TLS::Session session_from_pem(pem);
         result.test_eq("Roundtrip from pem", session.DER_encode(), session_from_pem.DER_encode());

         const Botan::SymmetricKey key("ABCDEF");
         const std::vector<uint8_t> ctext1 = session.encrypt(key, Test::rng());
         const std::vector<uint8_t> ctext2 = session.encrypt(key, Test::rng());

         result.test_ne("TLS session encryption is non-determinsitic",
                        ctext1.data(), ctext1.size(),
                        ctext2.data(), ctext2.size());

         const std::vector<uint8_t> expected_hdr = Botan::hex_decode("068B5A9D396C0000F2322CAE");

         result.test_eq("tls", "TLS session encryption same header",
                        ctext1.data(), 12, expected_hdr.data(), 12);
         result.test_eq("tls", "TLS session encryption same header",
                        ctext2.data(), 12, expected_hdr.data(), 12);

         Botan::TLS::Session dsession = Botan::TLS::Session::decrypt(ctext1.data(), ctext1.size(), key);
         result.test_eq("Decrypted session access works", dsession.srp_identifier(), "SRP username");

         Fixed_Output_RNG frng1("00112233445566778899AABBCCDDEEFF802802802802802802802802");
         const std::vector<uint8_t> ctextf1 = session.encrypt(key, frng1);
         Fixed_Output_RNG frng2("00112233445566778899AABBCCDDEEFF802802802802802802802802");
         const std::vector<uint8_t> ctextf2 = session.encrypt(key, frng2);

         result.test_eq("Only randomness comes from RNG", ctextf1, ctextf2);

         return {result};
         }
   };

BOTAN_REGISTER_TEST("tls", "tls_session", TLS_Session_Tests);

#if defined(BOTAN_HAS_TLS_CBC)

class TLS_CBC_Padding_Tests final : public Text_Based_Test
   {
   public:
      TLS_CBC_Padding_Tests() : Text_Based_Test("tls_cbc_padding.vec", "Record,Output") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         const std::vector<uint8_t> record    = vars.get_req_bin("Record");
         const size_t output = vars.get_req_sz("Output");

         uint16_t res = Botan::TLS::check_tls_cbc_padding(record.data(), record.size());

         Test::Result result("TLS CBC padding check");
         result.test_eq("Expected", res, output);
         return result;
         }
   };

BOTAN_REGISTER_TEST("tls", "tls_cbc_padding", TLS_CBC_Padding_Tests);

class TLS_CBC_Tests final : public Text_Based_Test
   {
   public:

      class ZeroMac : public Botan::MessageAuthenticationCode
         {
         public:
            ZeroMac(size_t mac_len) : m_mac_len(mac_len) {}

            void clear() override {}

            std::string name() const override { return "ZeroMac"; }
            size_t output_length() const override { return m_mac_len; }

            void add_data(const uint8_t[], size_t) override {}

            void final_result(uint8_t out[]) override
               {
               for(size_t i = 0; i != m_mac_len; ++i)
                  out[i] = 0;
               }

            Botan::Key_Length_Specification key_spec() const override
               {
               return Botan::Key_Length_Specification(0, 0, 1);
               }

            virtual MessageAuthenticationCode* clone() const override { return new ZeroMac(m_mac_len); }

         private:
            void key_schedule(const uint8_t[], size_t) override {}

            size_t m_mac_len;
         };

      class Noop_Block_Cipher : public Botan::BlockCipher
         {
         public:
            Noop_Block_Cipher(size_t bs) : m_bs(bs) {}

            void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override
               {
               Botan::copy_mem(out, in, blocks * m_bs);
               }

            void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override
               {
               Botan::copy_mem(out, in, blocks * m_bs);
               }

            size_t block_size() const override { return m_bs; }
            void clear() override { }
            std::string name() const override { return "noop"; }

            Botan::Key_Length_Specification key_spec() const override
               {
               return Botan::Key_Length_Specification(0, 0, 1);
               }

            virtual BlockCipher* clone() const override { return new Noop_Block_Cipher(m_bs); }
         private:
            void key_schedule(const uint8_t[], size_t) override {}

            size_t m_bs;
         };

      TLS_CBC_Tests() : Text_Based_Test("tls_cbc.vec", "Blocksize,MACsize,Record,Valid") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         Test::Result result("TLS CBC");

         const size_t block_size = vars.get_req_sz("Blocksize");
         const size_t mac_len = vars.get_req_sz("MACsize");
         const std::vector<uint8_t> record = vars.get_req_bin("Record");
         const bool is_valid = vars.get_req_sz("Valid") == 1;

         // todo test permutations
         bool encrypt_then_mac = false;

         Botan::TLS::TLS_CBC_HMAC_AEAD_Decryption tls_cbc(
            std::unique_ptr<Botan::BlockCipher>(new Noop_Block_Cipher(block_size)),
            std::unique_ptr<Botan::MessageAuthenticationCode>(new ZeroMac(mac_len)),
            0, 0, Botan::TLS::Protocol_Version::TLS_V11, encrypt_then_mac);

         tls_cbc.set_key(std::vector<uint8_t>(0));
         std::vector<uint8_t> ad(13);
         tls_cbc.set_associated_data(ad.data(), ad.size());

         Botan::secure_vector<uint8_t> vec(record.begin(), record.end());

         try
            {
            tls_cbc.finish(vec, 0);
            if(is_valid)
               result.test_success("Accepted valid TLS-CBC ciphertext");
            else
               result.test_failure("Accepted invalid TLS-CBC ciphertext");
            }
         catch(std::exception&)
            {
            if(is_valid)
               result.test_failure("Rejected valid TLS-CBC ciphertext");
            else
               result.test_success("Accepted invalid TLS-CBC ciphertext");
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("tls", "tls_cbc", TLS_CBC_Tests);

#endif

class Test_TLS_Alert_Strings : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("TLS::Alert::type_string");

         const std::vector<Botan::TLS::Alert::Type> alert_types =
            {
               Botan::TLS::Alert::CLOSE_NOTIFY,
               Botan::TLS::Alert::UNEXPECTED_MESSAGE,
               Botan::TLS::Alert::BAD_RECORD_MAC,
               Botan::TLS::Alert::DECRYPTION_FAILED,
               Botan::TLS::Alert::RECORD_OVERFLOW,
               Botan::TLS::Alert::DECOMPRESSION_FAILURE,
               Botan::TLS::Alert::HANDSHAKE_FAILURE,
               Botan::TLS::Alert::NO_CERTIFICATE,
               Botan::TLS::Alert::BAD_CERTIFICATE,
               Botan::TLS::Alert::UNSUPPORTED_CERTIFICATE,
               Botan::TLS::Alert::CERTIFICATE_REVOKED,
               Botan::TLS::Alert::CERTIFICATE_EXPIRED,
               Botan::TLS::Alert::CERTIFICATE_UNKNOWN,
               Botan::TLS::Alert::ILLEGAL_PARAMETER,
               Botan::TLS::Alert::UNKNOWN_CA,
               Botan::TLS::Alert::ACCESS_DENIED,
               Botan::TLS::Alert::DECODE_ERROR,
               Botan::TLS::Alert::DECRYPT_ERROR,
               Botan::TLS::Alert::EXPORT_RESTRICTION,
               Botan::TLS::Alert::PROTOCOL_VERSION,
               Botan::TLS::Alert::INSUFFICIENT_SECURITY,
               Botan::TLS::Alert::INTERNAL_ERROR,
               Botan::TLS::Alert::INAPPROPRIATE_FALLBACK,
               Botan::TLS::Alert::USER_CANCELED,
               Botan::TLS::Alert::NO_RENEGOTIATION,
               Botan::TLS::Alert::UNSUPPORTED_EXTENSION,
               Botan::TLS::Alert::CERTIFICATE_UNOBTAINABLE,
               Botan::TLS::Alert::UNRECOGNIZED_NAME,
               Botan::TLS::Alert::BAD_CERTIFICATE_STATUS_RESPONSE,
               Botan::TLS::Alert::BAD_CERTIFICATE_HASH_VALUE,
               Botan::TLS::Alert::UNKNOWN_PSK_IDENTITY,
               Botan::TLS::Alert:: NO_APPLICATION_PROTOCOL,
            };

         std::set<std::string> seen;

         for(auto alert : alert_types)
            {
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

class Test_TLS_Policy_Text : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("TLS Policy");

         const std::vector<std::string> policies = { "default", "suiteb_128", "suiteb_192", "strict", "datagram", "bsi" };

         for(std::string policy : policies)
            {
            const std::string from_policy_obj = tls_policy_string(policy);
            std::string from_file = read_tls_policy(policy);

#if !defined(BOTAN_HAS_CURVE_25519)
            auto pos = from_file.find("x25519 ");
            if(pos != std::string::npos)
               from_file = from_file.replace(pos, 7, "");
#endif

            result.test_eq("Values for TLS " + policy + " policy", from_file, from_policy_obj);
            }

         return {result};
         }

   private:
      std::string read_tls_policy(const std::string& policy_str)
         {
         const std::string fspath = Test::data_file("tls-policy/" + policy_str + ".txt");

         std::ifstream is(fspath.c_str());
         if(!is.good())
            {
            throw Test_Error("Missing policy file " + fspath);
            }

         Botan::TLS::Text_Policy policy(is);
         return policy.to_string();
         }

      std::string tls_policy_string(const std::string& policy_str)
         {
         std::unique_ptr<Botan::TLS::Policy> policy;
         if(policy_str == "default")
            {
            policy.reset(new Botan::TLS::Policy);
            }
         else if(policy_str == "suiteb_128")
            {
            policy.reset(new Botan::TLS::NSA_Suite_B_128);
            }
         else if(policy_str == "suiteb_192")
            {
            policy.reset(new Botan::TLS::NSA_Suite_B_192);
            }
         else if(policy_str == "bsi")
            {
            policy.reset(new Botan::TLS::BSI_TR_02102_2);
            }
         else if(policy_str == "strict")
            {
            policy.reset(new Botan::TLS::Strict_Policy);
            }
         else if(policy_str == "datagram")
            {
            policy.reset(new Botan::TLS::Datagram_Policy);
            }
         else
            {
            throw Test_Error("Unknown TLS policy type '" + policy_str + "'");
            }

         return policy->to_string();
         }
   };

BOTAN_REGISTER_TEST("tls", "tls_policy_text", Test_TLS_Policy_Text);

class Test_TLS_Ciphersuites : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("TLS::Ciphersuite");

         for(size_t csuite_id = 0; csuite_id <= 0xFFFF; ++csuite_id)
            {
            const uint16_t csuite_id16 = static_cast<uint16_t>(csuite_id);
            Botan::TLS::Ciphersuite ciphersuite = Botan::TLS::Ciphersuite::by_id(csuite_id16);

            if(ciphersuite.valid())
               {
               result.test_eq("Valid Ciphersuite is not SCSV", Botan::TLS::Ciphersuite::is_scsv(csuite_id16), false);

               if(ciphersuite.cbc_ciphersuite() == false)
                  {
                  result.test_eq("Expected MAC name for AEAD ciphersuites", ciphersuite.mac_algo(), "AEAD");
                  }
               else
                  {
                  result.test_eq("MAC algo and PRF algo same for CBC suites", ciphersuite.prf_algo(), ciphersuite.mac_algo());
                  }

               // TODO more tests here
               }
            }

         return {result};
         }
   };

BOTAN_REGISTER_TEST("tls", "tls_ciphersuites", Test_TLS_Ciphersuites);

class Test_TLS_Algo_Strings : public Test
   {
   public:

      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_auth_method_strings());
         results.push_back(test_kex_algo_strings());
         results.push_back(test_tls_sig_method_strings());

         return results;
         }

   private:
      Test::Result test_tls_sig_method_strings()
         {
         Test::Result result("TLS::Signature_Scheme");

         std::vector<Botan::TLS::Signature_Scheme> schemes = Botan::TLS::all_signature_schemes();

         std::set<std::string> scheme_strs;
         for(auto scheme : schemes)
            {
            std::string scheme_str = Botan::TLS::sig_scheme_to_string(scheme);

            result.test_eq("Scheme strings unique", scheme_strs.count(scheme_str), 0);

            scheme_strs.insert(scheme_str);
            }

         return result;
         }

      Test::Result test_auth_method_strings()
         {
         Test::Result result("TLS::Auth_Method");

         const std::vector<Botan::TLS::Auth_Method> auth_methods({
            Botan::TLS::Auth_Method::RSA,
            Botan::TLS::Auth_Method::DSA,
            Botan::TLS::Auth_Method::ECDSA,
            Botan::TLS::Auth_Method::IMPLICIT,
            Botan::TLS::Auth_Method::ANONYMOUS
            });

         for(Botan::TLS::Auth_Method meth : auth_methods)
            {
            std::string meth_str = Botan::TLS::auth_method_to_string(meth);
            result.test_ne("Method string is not empty", meth_str, "");
            Botan::TLS::Auth_Method meth2 = Botan::TLS::auth_method_from_string(meth_str);
            result.confirm("Decoded method matches", meth == meth2);
            }

         return result;
         }

      Test::Result test_kex_algo_strings()
         {
         Test::Result result("TLS::Kex_Algo");

         const std::vector<Botan::TLS::Kex_Algo> kex_algos({
            Botan::TLS::Kex_Algo::STATIC_RSA,
            Botan::TLS::Kex_Algo::DH,
            Botan::TLS::Kex_Algo::ECDH,
            Botan::TLS::Kex_Algo::CECPQ1,
            Botan::TLS::Kex_Algo::SRP_SHA,
            Botan::TLS::Kex_Algo::PSK,
            Botan::TLS::Kex_Algo::DHE_PSK,
            Botan::TLS::Kex_Algo::ECDHE_PSK
            });

         for(Botan::TLS::Kex_Algo meth : kex_algos)
            {
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

}
