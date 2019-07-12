/*
* TLS Server Hello and Server Hello Done
* (C) 2004-2011,2015,2016,2019 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/tls_extensions.h>
#include <botan/tls_callbacks.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace TLS {

namespace {

const uint64_t DOWNGRADE_TLS11 = 0x444F574E47524400;
//const uint64_t DOWNGRADE_TLS12 = 0x444F574E47524401;

std::vector<uint8_t>
make_server_hello_random(RandomNumberGenerator& rng,
                         Protocol_Version offered_version,
                         const Policy& policy)
   {
   auto random = make_hello_random(rng, policy);

   if((offered_version == Protocol_Version::TLS_V10 ||
       offered_version == Protocol_Version::TLS_V11) &&
      policy.allow_tls12())
      {
      store_be(DOWNGRADE_TLS11, &random[24]);
      }

   if(offered_version == Protocol_Version::DTLS_V10 && policy.allow_dtls12())
      {
      store_be(DOWNGRADE_TLS11, &random[24]);
      }

   return random;
   }

}

// New session case
Server_Hello::Server_Hello(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           Callbacks& cb,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& reneg_info,
                           const Client_Hello& client_hello,
                           const Server_Hello::Settings& server_settings,
                           const std::string next_protocol) :
   m_version(server_settings.protocol_version()),
   m_session_id(server_settings.session_id()),
   m_random(make_server_hello_random(rng, m_version, policy)),
   m_ciphersuite(server_settings.ciphersuite()),
   m_comp_method(0)
   {
   if(client_hello.supports_extended_master_secret())
      m_extensions.add(new Extended_Master_Secret);

   // Sending the extension back does not commit us to sending a stapled response
   if(client_hello.supports_cert_status_message() && policy.support_cert_status_message())
      m_extensions.add(new Certificate_Status_Request);

   Ciphersuite c = Ciphersuite::by_id(m_ciphersuite);

   if(c.cbc_ciphersuite() && client_hello.supports_encrypt_then_mac() && policy.negotiate_encrypt_then_mac())
      {
      m_extensions.add(new Encrypt_then_MAC);
      }

   if(c.ecc_ciphersuite() && client_hello.extension_types().count(TLSEXT_EC_POINT_FORMATS))
      {
      m_extensions.add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
      }

   if(client_hello.secure_renegotiation())
      m_extensions.add(new Renegotiation_Extension(reneg_info));

   if(client_hello.supports_session_ticket() && server_settings.offer_session_ticket())
      m_extensions.add(new Session_Ticket());

   if(!next_protocol.empty() && client_hello.supports_alpn())
      m_extensions.add(new Application_Layer_Protocol_Notification(next_protocol));

   if(m_version.is_datagram_protocol())
      {
      const std::vector<uint16_t> server_srtp = policy.srtp_profiles();
      const std::vector<uint16_t> client_srtp = client_hello.srtp_profiles();

      if(!server_srtp.empty() && !client_srtp.empty())
         {
         uint16_t shared = 0;
         // always using server preferences for now
         for(auto s_srtp : server_srtp)
            for(auto c_srtp : client_srtp)
               {
               if(shared == 0 && s_srtp == c_srtp)
                  shared = s_srtp;
               }

         if(shared)
            m_extensions.add(new SRTP_Protection_Profiles(shared));
         }
      }

   cb.tls_modify_extensions(m_extensions, SERVER);

   hash.update(io.send(*this));
   }

// Resuming
Server_Hello::Server_Hello(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           Callbacks& cb,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& reneg_info,
                           const Client_Hello& client_hello,
                           Session& resumed_session,
                           bool offer_session_ticket,
                           const std::string& next_protocol) :
   m_version(resumed_session.version()),
   m_session_id(client_hello.session_id()),
   m_random(make_hello_random(rng, policy)),
   m_ciphersuite(resumed_session.ciphersuite_code()),
   m_comp_method(0)
   {
   if(client_hello.supports_extended_master_secret())
      m_extensions.add(new Extended_Master_Secret);

   if(client_hello.supports_encrypt_then_mac() && policy.negotiate_encrypt_then_mac())
      {
      Ciphersuite c = resumed_session.ciphersuite();
      if(c.cbc_ciphersuite())
         m_extensions.add(new Encrypt_then_MAC);
      }

   if(resumed_session.ciphersuite().ecc_ciphersuite() && client_hello.extension_types().count(TLSEXT_EC_POINT_FORMATS))
      {
      m_extensions.add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
      }

   if(client_hello.secure_renegotiation())
      m_extensions.add(new Renegotiation_Extension(reneg_info));

   if(client_hello.supports_session_ticket() && offer_session_ticket)
      m_extensions.add(new Session_Ticket());

   if(!next_protocol.empty() && client_hello.supports_alpn())
      m_extensions.add(new Application_Layer_Protocol_Notification(next_protocol));

   cb.tls_modify_extensions(m_extensions, SERVER);

   hash.update(io.send(*this));
   }

/*
* Deserialize a Server Hello message
*/
Server_Hello::Server_Hello(const std::vector<uint8_t>& buf)
   {
   if(buf.size() < 38)
      throw Decoding_Error("Server_Hello: Packet corrupted");

   TLS_Data_Reader reader("ServerHello", buf);

   const uint8_t major_version = reader.get_byte();
   const uint8_t minor_version = reader.get_byte();

   m_version = Protocol_Version(major_version, minor_version);

   m_random = reader.get_fixed<uint8_t>(32);

   m_session_id = reader.get_range<uint8_t>(1, 0, 32);

   m_ciphersuite = reader.get_uint16_t();

   m_comp_method = reader.get_byte();

   m_extensions.deserialize(reader, Connection_Side::SERVER);
   }

/*
* Serialize a Server Hello message
*/
std::vector<uint8_t> Server_Hello::serialize() const
   {
   std::vector<uint8_t> buf;

   buf.push_back(m_version.major_version());
   buf.push_back(m_version.minor_version());
   buf += m_random;

   append_tls_length_value(buf, m_session_id, 1);

   buf.push_back(get_byte(0, m_ciphersuite));
   buf.push_back(get_byte(1, m_ciphersuite));

   buf.push_back(m_comp_method);

   buf += m_extensions.serialize(Connection_Side::SERVER);

   return buf;
   }

bool Server_Hello::random_signals_downgrade() const
   {
   const uint64_t last8 = load_be<uint64_t>(m_random.data(), 3);
   return (last8 == DOWNGRADE_TLS11);
   }

/*
* Create a new Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(Handshake_IO& io,
                                     Handshake_Hash& hash)
   {
   hash.update(io.send(*this));
   }

/*
* Deserialize a Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(const std::vector<uint8_t>& buf)
   {
   if(buf.size())
      throw Decoding_Error("Server_Hello_Done: Must be empty, and is not");
   }

/*
* Serialize a Server Hello Done message
*/
std::vector<uint8_t> Server_Hello_Done::serialize() const
   {
   return std::vector<uint8_t>();
   }

}

}
