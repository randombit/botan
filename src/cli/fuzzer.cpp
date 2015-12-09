/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"
#include <fstream>
#include <botan/auto_rng.h>

#if defined(BOTAN_HAS_X509_CERTIFICATES)
#include <botan/x509cert.h>
#include <botan/x509_crl.h>
#include <botan/pkcs8.h>
#endif

#if defined(BOTAN_HAS_TLS)
#include <botan/tls_client.h>
#endif

namespace {

#if defined(BOTAN_HAS_TLS)

class Fuzzer_Creds : public Credentials_Manager
   {
   public:
      void verify_certificate_chain(const std::string& type,
                                    const std::string& purported_hostname,
                                    const std::vector<X509_Certificate>& cert_chain) override
         {
         try
            {
            Credentials_Manager::verify_certificate_chain(type,
                                                          purported_hostname,
                                                          cert_chain);
            }
         catch(std::exception& e) {}
         }

      std::string psk_identity_hint(const std::string&, const std::string&) override { return "psk_hint"; }
      std::string psk_identity(const std::string&, const std::string&, const std::string&) override { return "psk_id"; }
      SymmetricKey psk(const std::string&, const std::string&, const std::string&) override
         {
         return SymmetricKey("AABBCCDDEEFF00112233445566778899");
         }
   };

#endif

int fuzzer(const std::vector<std::string> &args)
   {
   if(args.size() != 3)
      {
      std::cout << "Usage: " << args[0] << " [type] [input_file]\n"
                << "Hook for fuzzers such as afl (produces no output)\n"
                << "Types: cert crl privkey tls_client" << std::endl;
      return 1;
      }

   const std::string type = args[1];
   const std::string input = args[2];

   AutoSeeded_RNG rng;

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   if(type == "cert")
      {
      X509_Certificate cert(input);
      return 0;
      }

   if(type == "crl")
      {
      X509_CRL crl(input);
      return 0;
      }

   if(type == "privkey")
      {
      std::unique_ptr<Private_Key>(PKCS8::load_key(input, rng));
      return 0;
      }

#endif

#if defined(BOTAN_HAS_TLS)
   if(type == "tls_client")
      {
      auto dev_null = [](const byte[], size_t) {};

      auto ignore_alerts = [](TLS::Alert, const byte[], size_t) {};
      auto ignore_hs = [](const TLS::Session&) { return true; };

      TLS::Session_Manager_In_Memory session_manager(rng);
      TLS::Policy policy;
      TLS::Protocol_Version client_offer = TLS::Protocol_Version::TLS_V12;
      TLS::Server_Information info("server.name", 443);
      const std::vector<std::string> protocols_to_offer = { "fuzz/1.0", "http/1.1", "bunny/1.21.3" };
      Fuzzer_Creds creds;

      TLS::Client client(dev_null,
                         dev_null,
                         ignore_alerts,
                         ignore_hs,
                         session_manager,
                         creds,
                         policy,
                         rng,
                         info,
                         client_offer,
                         protocols_to_offer);

      std::ifstream in(input.c_str());

      std::vector<byte> buf(1024);

      try
         {
         while(in.good())
            {
            in.read((char*)&buf[0], buf.size());
            size_t got = in.gcount();
            client.received_data(&buf[0], got);
            }
         }
      catch(std::exception& e)
         {
         return 0;
         }
      return 0;
      }
#endif

   std::cout << "Unknown type '" << type << "'" << std::endl;
   return 1;
   }

REGISTER_APP(fuzzer);

}
