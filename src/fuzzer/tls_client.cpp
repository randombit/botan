/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"
#include <botan/tls_client.h>

class Fuzzer_TLS_Client_Creds : public Botan::Credentials_Manager
   {
   public:
      std::string psk_identity_hint(const std::string&, const std::string&) override { return "psk_hint"; }
      std::string psk_identity(const std::string&, const std::string&, const std::string&) override { return "psk_id"; }
      Botan::SymmetricKey psk(const std::string&, const std::string&, const std::string&) override
         {
         return Botan::SymmetricKey("AABBCCDDEEFF00112233445566778899");
         }
   };

void fuzz(const uint8_t in[], size_t len)
   {
   if(len == 0)
      return;

   auto dev_null = [](const uint8_t[], size_t) {};

   auto ignore_alerts = [](Botan::TLS::Alert, const uint8_t[], size_t) {};
   auto ignore_hs = [](const Botan::TLS::Session&) { abort(); return true; };

   Botan::TLS::Session_Manager_Noop session_manager;
   Botan::TLS::Policy policy;
   Botan::TLS::Protocol_Version client_offer = Botan::TLS::Protocol_Version::TLS_V12;
   Botan::TLS::Server_Information info("server.name", 443);
   Fuzzer_TLS_Client_Creds creds;

   Botan::TLS::Client client(dev_null,
                      dev_null,
                      ignore_alerts,
                      ignore_hs,
                      session_manager,
                      creds,
                      policy,
                      fuzzer_rng(),
                      info,
                      client_offer);

   try
      {
      client.received_data(in, len);
      }
   catch(std::exception& e)
      {
      }

   }

