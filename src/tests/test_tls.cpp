/*
* (C) 2014,2015,2017,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <fstream>
#include <memory>

#if defined(BOTAN_HAS_TLS)
  #include <botan/tls_alert.h>
  #include <botan/tls_policy.h>

  #if defined(BOTAN_HAS_TLS_CBC)
     #include <botan/internal/tls_cbc.h>
  #endif

#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_TLS)

#if defined(BOTAN_HAS_TLS_CBC)

class TLS_CBC_Padding_Tests final : public Text_Based_Test
   {
   public:
      TLS_CBC_Padding_Tests() : Text_Based_Test("tls_cbc.vec", "Record,Output") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) override
         {
         const std::vector<uint8_t> record    = get_req_bin(vars, "Record");
         const size_t output = get_req_sz(vars, "Output");

         uint16_t res = Botan::TLS::check_tls_cbc_padding(record.data(), record.size());

         Test::Result result("TLS CBC padding check");
         result.test_eq("Expected", res, output);
         return result;
         }
   };

BOTAN_REGISTER_TEST("tls_cbc_padding", TLS_CBC_Padding_Tests);

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

BOTAN_REGISTER_TEST("tls_alert_strings", Test_TLS_Alert_Strings);

class Test_TLS_Policy_Text : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("TLS Policy");

         const std::vector<std::string> policies = { "default", "suiteb", "strict", "datagram", "bsi" };

         for(std::string policy : policies)
            {
            const std::string from_policy_obj = tls_policy_string(policy);
            const std::string from_file = read_tls_policy(policy);

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
         else if(policy_str == "suiteb")
            {
            policy.reset(new Botan::TLS::NSA_Suite_B_128);
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

BOTAN_REGISTER_TEST("tls_policy_text", Test_TLS_Policy_Text);

class Test_TLS_Ciphersuites : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         Test::Result result("TLS::Ciphersuite");

         for(size_t csuite_id = 0; csuite_id <= 0xFFFF; ++csuite_id)
            {
            Botan::TLS::Ciphersuite ciphersuite = Botan::TLS::Ciphersuite::by_id(csuite_id);

            if(ciphersuite.valid())
               {
               result.test_eq("Valid Ciphersuite is not SCSV", Botan::TLS::Ciphersuite::is_scsv(csuite_id), false);

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

BOTAN_REGISTER_TEST("tls_ciphersuites", Test_TLS_Ciphersuites);

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

BOTAN_REGISTER_TEST("tls_algo_strings", Test_TLS_Algo_Strings);

#endif

}
