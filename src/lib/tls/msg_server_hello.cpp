/*
* TLS Server Hello and Server Hello Done
* (C) 2004-2011,2015,2016,2019 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>

#include <botan/tls_extensions.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_callbacks.h>
#include <botan/internal/tls_reader.h>
#include <botan/mem_ops.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>

#include <array>

namespace Botan::TLS {

namespace {

const uint64_t DOWNGRADE_TLS11 = 0x444F574E47524400;
const uint64_t DOWNGRADE_TLS12 = 0x444F574E47524401;

std::vector<uint8_t>
make_server_hello_random(RandomNumberGenerator& rng,
                         Protocol_Version offered_version,
                         Callbacks& cb,
                         const Policy& policy)
   {
   BOTAN_UNUSED(offered_version);
   auto random = make_hello_random(rng, cb, policy);
   return random;
   }

}

/*
* Deserialize a Server Hello message
*/
Server_Hello::Internal::Internal(const std::vector<uint8_t>& buf)
   {
   if(buf.size() < 38)
      {
      throw Decoding_Error("Server_Hello: Packet corrupted");
      }

   TLS_Data_Reader reader("ServerHello", buf);

   const uint8_t major_version = reader.get_byte();
   const uint8_t minor_version = reader.get_byte();

   legacy_version = Protocol_Version(major_version, minor_version);

   random = reader.get_fixed<uint8_t>(32);

   session_id = reader.get_range<uint8_t>(1, 0, 32);
   ciphersuite = reader.get_uint16_t();
   comp_method = reader.get_byte();

   extensions.deserialize(reader, Connection_Side::SERVER,
                          Handshake_Type::SERVER_HELLO);
   }


Server_Hello::Internal::Internal(Protocol_Version lv,
                                 std::vector<uint8_t> sid,
                                 std::vector<uint8_t> r,
                                 const uint16_t cs,
                                 const uint8_t cm)
   : legacy_version(lv)
   , session_id(std::move(sid))
   , random(std::move(r))
   , ciphersuite(cs)
   , comp_method(cm) {}


Protocol_Version Server_Hello::Internal::version() const
   {
   return legacy_version;
   }


/*
* Serialize a Server Hello message
*/
std::vector<uint8_t> Server_Hello::serialize() const
   {
   std::vector<uint8_t> buf;

   buf.push_back(m_data->legacy_version.major_version());
   buf.push_back(m_data->legacy_version.minor_version());
   buf += m_data->random;

   append_tls_length_value(buf, m_data->session_id, 1);

   buf.push_back(get_byte<0>(m_data->ciphersuite));
   buf.push_back(get_byte<1>(m_data->ciphersuite));

   buf.push_back(m_data->comp_method);

   buf += m_data->extensions.serialize(Connection_Side::SERVER);

   return buf;
   }


Handshake_Type Server_Hello::type() const
   {
   return SERVER_HELLO;
   }

Protocol_Version Server_Hello::legacy_version() const
   {
   return m_data->legacy_version;
   }

const std::vector<uint8_t>& Server_Hello::random() const
   {
   return m_data->random;
   }

uint8_t Server_Hello::compression_method() const
   {
   return m_data->comp_method;
   }

const std::vector<uint8_t>& Server_Hello::session_id() const
   {
   return m_data->session_id;
   }

uint16_t Server_Hello::ciphersuite() const
   {
   return m_data->ciphersuite;
   }

std::set<Handshake_Extension_Type> Server_Hello::extension_types() const
   {
   return m_data->extensions.extension_types();
   }

const Extensions& Server_Hello::extensions() const
   {
   return m_data->extensions;
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
                                 const std::string& next_protocol) :
   Server_Hello(std::make_unique<Server_Hello::Internal>(
                   server_settings.protocol_version(),
                   server_settings.session_id(),
                   make_server_hello_random(rng, server_settings.protocol_version(), cb, policy),
                   server_settings.ciphersuite(),
                   uint8_t(0)))
   {
   if(client_hello.supports_extended_master_secret())
      {
      m_data->extensions.add(new Extended_Master_Secret);
      }

   // Sending the extension back does not commit us to sending a stapled response
   if(client_hello.supports_cert_status_message() && policy.support_cert_status_message())
      {
      m_data->extensions.add(new Certificate_Status_Request);
      }

   if(!next_protocol.empty() && client_hello.supports_alpn())
      {
      m_data->extensions.add(new Application_Layer_Protocol_Notification(next_protocol));
      }

   const auto c = Ciphersuite::by_id(m_data->ciphersuite);

   if(c && c->cbc_ciphersuite() && client_hello.supports_encrypt_then_mac() && policy.negotiate_encrypt_then_mac())
      {
      m_data->extensions.add(new Encrypt_then_MAC);
      }

   if(c && c->ecc_ciphersuite() && client_hello.extension_types().count(TLSEXT_EC_POINT_FORMATS))
      {
      m_data->extensions.add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
      }

   if(client_hello.secure_renegotiation())
      {
      m_data->extensions.add(new Renegotiation_Extension(reneg_info));
      }

   if(client_hello.supports_session_ticket() && server_settings.offer_session_ticket())
      {
      m_data->extensions.add(new Session_Ticket());
      }

   if(m_data->legacy_version.is_datagram_protocol())
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
            m_data->extensions.add(new SRTP_Protection_Profiles(shared));
            }
         }
      }

   cb.tls_modify_extensions(m_data->extensions, SERVER);

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
   Server_Hello(std::make_unique<Server_Hello::Internal>(
                   resumed_session.version(),
                   client_hello.session_id(),
                   make_hello_random(rng, cb, policy),
                   resumed_session.ciphersuite_code(),
                   uint8_t(0)))
   {
   if(client_hello.supports_extended_master_secret())
      {
      m_data->extensions.add(new Extended_Master_Secret);
      }

   if(!next_protocol.empty() && client_hello.supports_alpn())
      {
      m_data->extensions.add(new Application_Layer_Protocol_Notification(next_protocol));
      }

   if(client_hello.supports_encrypt_then_mac() && policy.negotiate_encrypt_then_mac())
      {
      Ciphersuite c = resumed_session.ciphersuite();
      if(c.cbc_ciphersuite())
         {
         m_data->extensions.add(new Encrypt_then_MAC);
         }
      }

   if(resumed_session.ciphersuite().ecc_ciphersuite() && client_hello.extension_types().count(TLSEXT_EC_POINT_FORMATS))
      {
      m_data->extensions.add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
      }

   if(client_hello.secure_renegotiation())
      {
      m_data->extensions.add(new Renegotiation_Extension(reneg_info));
      }

   if(client_hello.supports_session_ticket() && offer_session_ticket)
      {
      m_data->extensions.add(new Session_Ticket());
      }

   cb.tls_modify_extensions(m_data->extensions, SERVER);

   hash.update(io.send(*this));
   }


Server_Hello_12::Server_Hello_12(const std::vector<uint8_t>& buf)
   : Server_Hello_12(std::make_unique<Server_Hello::Internal>(buf))
   {}

Server_Hello_12::Server_Hello_12(std::unique_ptr<Server_Hello::Internal> data)
   : Server_Hello(std::move(data))
   {
   }

Protocol_Version Server_Hello_12::selected_version() const
   {
   return legacy_version();
   }

bool Server_Hello_12::secure_renegotiation() const
   {
   return m_data->extensions.has<Renegotiation_Extension>();
   }

std::vector<uint8_t> Server_Hello_12::renegotiation_info() const
   {
   if(Renegotiation_Extension* reneg = m_data->extensions.get<Renegotiation_Extension>())
      { return reneg->renegotiation_info(); }
   return std::vector<uint8_t>();
   }

bool Server_Hello_12::supports_extended_master_secret() const
   {
   return m_data->extensions.has<Extended_Master_Secret>();
   }

bool Server_Hello_12::supports_encrypt_then_mac() const
   {
   return m_data->extensions.has<Encrypt_then_MAC>();
   }

bool Server_Hello_12::supports_certificate_status_message() const
   {
   return m_data->extensions.has<Certificate_Status_Request>();
   }

bool Server_Hello_12::supports_session_ticket() const
   {
   return m_data->extensions.has<Session_Ticket>();
   }

uint16_t Server_Hello_12::srtp_profile() const
   {
   if(auto srtp = m_data->extensions.get<SRTP_Protection_Profiles>())
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
   if(auto alpn = m_data->extensions.get<Application_Layer_Protocol_Notification>())
      {
      return alpn->single_protocol();
      }
   return "";
   }

bool Server_Hello_12::prefers_compressed_ec_points() const
   {
   if(auto ecc_formats = m_data->extensions.get<Supported_Point_Formats>())
      {
      return ecc_formats->prefers_compressed();
      }
   return false;
   }

std::optional<Protocol_Version> Server_Hello_12::random_signals_downgrade() const
   {
   const uint64_t last8 = load_be<uint64_t>(m_data->random.data(), 3);
   if(last8 == DOWNGRADE_TLS11)
      { return Protocol_Version::TLS_V11; }
   if(last8 == DOWNGRADE_TLS12)
      { return Protocol_Version::TLS_V12; }

   return std::nullopt;
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
   if(!buf.empty())
      { throw Decoding_Error("Server_Hello_Done: Must be empty, and is not"); }
   }

/*
* Serialize a Server Hello Done message
*/
std::vector<uint8_t> Server_Hello_Done::serialize() const
   {
   return std::vector<uint8_t>();
   }

}
