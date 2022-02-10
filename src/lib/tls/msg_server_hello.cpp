/*
* TLS Server Hello and Server Hello Done
* (C) 2004-2011,2015,2016,2019 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2021 Elektrobit Automotive GmbH
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

#include <array>

namespace Botan::TLS {

namespace {

const uint64_t DOWNGRADE_TLS11 = 0x444F574E47524400;
const uint64_t DOWNGRADE_TLS12 = 0x444F574E47524401;

#if defined(BOTAN_HAS_TLS_13)

// SHA-256("HelloRetryRequest")
const std::array<uint8_t, 32> HELLO_RETRY_REQUEST_MARKER =
   {
   0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02,
   0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
   0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
   };

#endif

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

// New session case
Server_Hello_12::Server_Hello_12(Handshake_IO& io,
                                 Handshake_Hash& hash,
                                 const Policy& policy,
                                 Callbacks& cb,
                                 RandomNumberGenerator& rng,
                                 const std::vector<uint8_t>& reneg_info,
                                 const Client_Hello_12& client_hello,
                                 const Server_Hello_12::Settings& server_settings,
                                 const std::string next_protocol) :
   Server_Hello(server_settings.protocol_version(),
                server_settings.session_id(),
                make_server_hello_random(rng, server_settings.protocol_version(), policy),
                server_settings.ciphersuite(),
                0)
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

   const auto c = Ciphersuite::by_id(m_ciphersuite);

   if(c && c->cbc_ciphersuite() && client_hello.supports_encrypt_then_mac() && policy.negotiate_encrypt_then_mac())
      {
      m_extensions.add(new Encrypt_then_MAC);
      }

   if(c && c->ecc_ciphersuite() && client_hello.extension_types().count(TLSEXT_EC_POINT_FORMATS))
      {
      m_extensions.add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
      }

   if(client_hello.secure_renegotiation())
      {
      m_extensions.add(new Renegotiation_Extension(reneg_info));
      }

   if(client_hello.supports_session_ticket() && server_settings.offer_session_ticket())
      {
      m_extensions.add(new Session_Ticket());
      }

   if(m_legacy_version.is_datagram_protocol())
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
                  { shared = s_srtp; }
               }

         if(shared)
            {
            m_extensions.add(new SRTP_Protection_Profiles(shared));
            }
         }
      }

   cb.tls_modify_extensions(m_extensions, SERVER);

   hash.update(io.send(*this));
   }

// Resuming
Server_Hello_12::Server_Hello_12(Handshake_IO& io,
                                 Handshake_Hash& hash,
                                 const Policy& policy,
                                 Callbacks& cb,
                                 RandomNumberGenerator& rng,
                                 const std::vector<uint8_t>& reneg_info,
                                 const Client_Hello_12& client_hello,
                                 Session& resumed_session,
                                 bool offer_session_ticket,
                                 const std::string& next_protocol) :
   Server_Hello(resumed_session.version(),
                client_hello.session_id(),
                make_hello_random(rng, policy),
                resumed_session.ciphersuite_code(),
                0)
   {
   if(client_hello.supports_extended_master_secret())
      {
      m_extensions.add(new Extended_Master_Secret);
      }

   if(!next_protocol.empty() && client_hello.supports_alpn())
      {
      m_extensions.add(new Application_Layer_Protocol_Notification(next_protocol));
      }

   if(client_hello.supports_encrypt_then_mac() && policy.negotiate_encrypt_then_mac())
      {
      Ciphersuite c = resumed_session.ciphersuite();
      if(c.cbc_ciphersuite())
         {
         m_extensions.add(new Encrypt_then_MAC);
         }
      }

   if(resumed_session.ciphersuite().ecc_ciphersuite() && client_hello.extension_types().count(TLSEXT_EC_POINT_FORMATS))
      {
      m_extensions.add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
      }

   if(client_hello.secure_renegotiation())
      {
      m_extensions.add(new Renegotiation_Extension(reneg_info));
      }

   if(client_hello.supports_session_ticket() && offer_session_ticket)
      {
      m_extensions.add(new Session_Ticket());
      }

   cb.tls_modify_extensions(m_extensions, SERVER);

   hash.update(io.send(*this));
   }

/*
* Deserialize a Server Hello message
*/
Server_Hello::Server_Hello(const std::vector<uint8_t>& buf)
   {
   if(buf.size() < 38)
      {
      throw Decoding_Error("Server_Hello: Packet corrupted");
      }

   TLS_Data_Reader reader("ServerHello", buf);

   const uint8_t major_version = reader.get_byte();
   const uint8_t minor_version = reader.get_byte();

   m_legacy_version = Protocol_Version(major_version, minor_version);

   m_random = reader.get_fixed<uint8_t>(32);

   m_session_id = reader.get_range<uint8_t>(1, 0, 32);

   m_ciphersuite = reader.get_uint16_t();

   m_comp_method = reader.get_byte();

   m_extensions.deserialize(reader, Connection_Side::SERVER);
   }

Handshake_Type Server_Hello::type() const
   {
   return SERVER_HELLO;
   }

Protocol_Version Server_Hello::legacy_version() const
   {
   return m_legacy_version;
   }

const std::vector<uint8_t>& Server_Hello::random() const
   {
   return m_random;
   }

uint8_t Server_Hello::compression_method() const
   {
   return m_comp_method;
   }

const std::vector<uint8_t>& Server_Hello::session_id() const
   {
   return m_session_id;
   }

uint16_t Server_Hello::ciphersuite() const
   {
   return m_ciphersuite;
   }

bool Server_Hello_12::secure_renegotiation() const
   {
   return m_extensions.has<Renegotiation_Extension>();
   }

std::vector<uint8_t> Server_Hello_12::renegotiation_info() const
   {
   if(Renegotiation_Extension* reneg = m_extensions.get<Renegotiation_Extension>())
      { return reneg->renegotiation_info(); }
   return std::vector<uint8_t>();
   }

bool Server_Hello_12::supports_extended_master_secret() const
   {
   return m_extensions.has<Extended_Master_Secret>();
   }

bool Server_Hello_12::supports_encrypt_then_mac() const
   {
   return m_extensions.has<Encrypt_then_MAC>();
   }

bool Server_Hello_12::supports_certificate_status_message() const
   {
   return m_extensions.has<Certificate_Status_Request>();
   }

bool Server_Hello_12::supports_session_ticket() const
   {
   return m_extensions.has<Session_Ticket>();
   }

uint16_t Server_Hello_12::srtp_profile() const
   {
   if(auto srtp = m_extensions.get<SRTP_Protection_Profiles>())
      {
      auto prof = srtp->profiles();
      if(prof.size() != 1 || prof[0] == 0)
         { throw Decoding_Error("Server sent malformed DTLS-SRTP extension"); }
      return prof[0];
      }

   return 0;
   }

std::string Server_Hello_12::next_protocol() const
   {
   if(auto alpn = m_extensions.get<Application_Layer_Protocol_Notification>())
      {
      return alpn->single_protocol();
      }
   return "";
   }

std::set<Handshake_Extension_Type> Server_Hello::extension_types() const
   {
   return m_extensions.extension_types();
   }

const Extensions& Server_Hello::extensions() const
   {
   return m_extensions;
   }

bool Server_Hello_12::prefers_compressed_ec_points() const
   {
   if(auto ecc_formats = m_extensions.get<Supported_Point_Formats>())
      {
      return ecc_formats->prefers_compressed();
      }
   return false;
   }

// TODO: this should have a specific implementation for 1.2/1.3
std::optional<Protocol_Version> Server_Hello_12::random_signals_downgrade() const
   {
   const uint64_t last8 = load_be<uint64_t>(m_random.data(), 3);
   if(last8 == DOWNGRADE_TLS11)
      { return Protocol_Version::TLS_V11; }
   if(last8 == DOWNGRADE_TLS12)
      { return Protocol_Version::TLS_V12; }

   return std::nullopt;
   }

/*
* Serialize a Server Hello message
*/
std::vector<uint8_t> Server_Hello::serialize() const
   {
   std::vector<uint8_t> buf;

   buf.push_back(m_legacy_version.major_version());
   buf.push_back(m_legacy_version.minor_version());
   buf += m_random;

   append_tls_length_value(buf, m_session_id, 1);

   buf.push_back(get_byte<0>(m_ciphersuite));
   buf.push_back(get_byte<1>(m_ciphersuite));

   buf.push_back(m_comp_method);

   buf += m_extensions.serialize(Connection_Side::SERVER);

   return buf;
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
      { throw Decoding_Error("Server_Hello_Done: Must be empty, and is not"); }
   }

/*
* Serialize a Server Hello Done message
*/
std::vector<uint8_t> Server_Hello_Done::serialize() const
   {
   return std::vector<uint8_t>();
   }

#if defined(BOTAN_HAS_TLS_13)

// TODO: this should have a specific implementation for 1.2/1.3
std::optional<Protocol_Version> Server_Hello_13::random_signals_downgrade() const
   {
   const uint64_t last8 = load_be<uint64_t>(m_random.data(), 3);
   if(last8 == DOWNGRADE_TLS11)
      { return Protocol_Version::TLS_V11; }
   if(last8 == DOWNGRADE_TLS12)
      { return Protocol_Version::TLS_V12; }

   return std::nullopt;
   }

// TODO: this should have a specific implementation for 1.2/1.3
bool Server_Hello_13::random_signals_hello_retry_request() const
   {
   return (m_random.data() == HELLO_RETRY_REQUEST_MARKER.data());
   }

std::vector<Protocol_Version> Server_Hello_13::supported_versions() const
   {
   if(Supported_Versions* versions = m_extensions.get<Supported_Versions>())
      { return versions->versions(); }
   return {};
   }

#endif // BOTAN_HAS_TLS_13

}
