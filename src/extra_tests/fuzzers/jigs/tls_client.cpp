/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "driver.h"
#include <botan/tls_client.h>

class Fuzzer_TLS_Client_Creds : public Credentials_Manager
   {
   public:
      std::string psk_identity_hint(const std::string&, const std::string&) override { return "psk_hint"; }
      std::string psk_identity(const std::string&, const std::string&, const std::string&) override { return "psk_id"; }
      SymmetricKey psk(const std::string&, const std::string&, const std::string&) override
         {
         return SymmetricKey("AABBCCDDEEFF00112233445566778899");
         }
   };

void fuzz(const uint8_t in[], size_t len)
   {
   if(len == 0)
      return;

   auto dev_null = [](const byte[], size_t) {};

   auto ignore_alerts = [](TLS::Alert, const byte[], size_t) {};
   auto ignore_hs = [](const TLS::Session&) { abort(); return true; };

   TLS::Session_Manager_Noop session_manager;
   TLS::Policy policy;
   TLS::Protocol_Version client_offer = TLS::Protocol_Version::TLS_V12;
   TLS::Server_Information info("server.name", 443);
   Fuzzer_TLS_Client_Creds creds;

   TLS::Client client(dev_null,
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

