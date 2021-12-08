/*
* TLS Server Hello Impl
* (C) 2004-2011,2015,2016,2019 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/msg_server_hello_impl.h>
#include <botan/internal/tls_reader.h>


namespace Botan {

namespace TLS {

namespace {

const uint64_t DOWNGRADE_TLS11 = 0x444F574E47524400;
//const uint64_t DOWNGRADE_TLS12 = 0x444F574E47524401;

}


class Client_Hello;

namespace {

std::vector<uint8_t>
make_server_hello_random(RandomNumberGenerator& rng,
                         Protocol_Version offered_version,
                         const Policy& policy)
   {
   BOTAN_UNUSED(offered_version);
   auto random = make_hello_random(rng, policy);
   return random;
   }

}

Server_Hello_Impl::Server_Hello_Impl() = default;

// New session case
Server_Hello_Impl::Server_Hello_Impl(const Policy& policy,
                                     RandomNumberGenerator& rng,
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
      {
      m_extensions.add(new Extended_Master_Secret);
      }

   // Sending the extension back does not commit us to sending a stapled response
   if(client_hello.supports_cert_status_message() && policy.support_cert_status_message())
      {
      m_extensions.add(new Certificate_Status_Request);
      }

   if(!next_protocol.empty() && client_hello.supports_alpn())
      {
      m_extensions.add(new Application_Layer_Protocol_Notification(next_protocol));
      }
   }

// Resuming
Server_Hello_Impl::Server_Hello_Impl(const Policy& policy,
                                     RandomNumberGenerator& rng,
                                     const Client_Hello& client_hello,
                                     Session& resumed_session,
                                     const std::string next_protocol) :
   m_version(resumed_session.version()),
   m_session_id(client_hello.session_id()),
   m_random(make_hello_random(rng, policy)),
   m_ciphersuite(resumed_session.ciphersuite_code()),
   m_comp_method(0)
   {
   if(client_hello.supports_extended_master_secret())
      {
      m_extensions.add(new Extended_Master_Secret);
      }

   if(!next_protocol.empty() && client_hello.supports_alpn())
      {
      m_extensions.add(new Application_Layer_Protocol_Notification(next_protocol));
      }
   }

Server_Hello_Impl::Server_Hello_Impl(const std::vector<uint8_t>& buf)
   {
   if(buf.size() < 38)
      {
      throw Decoding_Error("Server_Hello: Packet corrupted");
      }

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

Handshake_Type Server_Hello_Impl::type() const
   {
   return SERVER_HELLO;
   }

Protocol_Version Server_Hello_Impl::version() const
   {
   return m_version;
   }

const std::vector<uint8_t>& Server_Hello_Impl::random() const
   {
   return m_random;
   }

const std::vector<uint8_t>& Server_Hello_Impl::session_id() const
   {
   return m_session_id;
   }

uint16_t Server_Hello_Impl::ciphersuite() const
   {
   return m_ciphersuite;
   }

uint8_t Server_Hello_Impl::compression_method() const
   {
   return m_comp_method;
   }

bool Server_Hello_Impl::secure_renegotiation() const
   {
   return m_extensions.has<Renegotiation_Extension>();
   }

std::vector<uint8_t> Server_Hello_Impl::renegotiation_info() const
   {
   if(Renegotiation_Extension* reneg = m_extensions.get<Renegotiation_Extension>())
      return reneg->renegotiation_info();
   return std::vector<uint8_t>();
   }

bool Server_Hello_Impl::supports_extended_master_secret() const
   {
   return m_extensions.has<Extended_Master_Secret>();
   }

bool Server_Hello_Impl::supports_encrypt_then_mac() const
   {
   return m_extensions.has<Encrypt_then_MAC>();
   }


bool Server_Hello_Impl::supports_certificate_status_message() const
   {
   return m_extensions.has<Certificate_Status_Request>();
   }

bool Server_Hello_Impl::supports_session_ticket() const
   {
   return m_extensions.has<Session_Ticket>();
   }

uint16_t Server_Hello_Impl::srtp_profile() const
   {
   if(auto srtp = m_extensions.get<SRTP_Protection_Profiles>())
      {
      auto prof = srtp->profiles();
      if(prof.size() != 1 || prof[0] == 0)
         throw Decoding_Error("Server sent malformed DTLS-SRTP extension");
      return prof[0];
      }

   return 0;
   }

std::string Server_Hello_Impl::next_protocol() const
   {
   if(auto alpn = m_extensions.get<Application_Layer_Protocol_Notification>())
      {
      return alpn->single_protocol();
      }
   return "";
   }

std::set<Handshake_Extension_Type> Server_Hello_Impl::extension_types() const
   {
   return m_extensions.extension_types();
   }

const Extensions& Server_Hello_Impl::extensions() const
   {
   return m_extensions;
   }

bool Server_Hello_Impl::prefers_compressed_ec_points() const
   {
   if(auto ecc_formats = m_extensions.get<Supported_Point_Formats>())
      {
      return ecc_formats->prefers_compressed();
      }
   return false;
   }

bool Server_Hello_Impl::random_signals_downgrade() const
   {
   const uint64_t last8 = load_be<uint64_t>(m_random.data(), 3);
   return (last8 == DOWNGRADE_TLS11);
   }

/*
* Serialize a Server Hello message
*/
std::vector<uint8_t> Server_Hello_Impl::serialize() const
   {
   std::vector<uint8_t> buf;

   buf.push_back(m_version.major_version());
   buf.push_back(m_version.minor_version());
   buf += m_random;

   append_tls_length_value(buf, m_session_id, 1);

   buf.push_back(get_byte<0>(m_ciphersuite));
   buf.push_back(get_byte<1>(m_ciphersuite));

   buf.push_back(m_comp_method);

   buf += m_extensions.serialize(Connection_Side::SERVER);

   return buf;
   }

std::vector<Protocol_Version> Server_Hello_Impl::supported_versions() const
   {
   if(Supported_Versions* versions = m_extensions.get<Supported_Versions>())
      return versions->versions();
   return {};
   }

}

}
