/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "driver.h"
#include <botan/tls_client.h>
#include <botan/system_rng.h>

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

   Botan::System_RNG rng;
   TLS::Session_Manager_Noop session_manager;
   TLS::Policy policy;
   TLS::Protocol_Version client_offer = TLS::Protocol_Version::TLS_V12;
   TLS::Server_Information info("server.name", 443);
   const std::vector<std::string> protocols_to_offer = { "fuzz/1.0", "http/1.1", "bunny/1.21.3" };
   Fuzzer_TLS_Client_Creds creds;

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

   try
      {
      while(len > 0)
         {
         const size_t write_len = in[0];
         const size_t left = len - 1;

         const size_t consumed = std::min(left, write_len);

         client.received_data(in + 1, consumed);

         in += consumed + 1;
         len -= consumed + 1;
         }
      }
   catch(std::exception& e)
      {
      }

   }

