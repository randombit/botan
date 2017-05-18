/*
* TLS Hello Request and Client Hello Messages
* (C) 2004-2011,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages.h>
#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/stl_util.h>
#include <chrono>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace Botan {

namespace TLS {

enum {
   TLS_EMPTY_RENEGOTIATION_INFO_SCSV        = 0x00FF,
   TLS_FALLBACK_SCSV                        = 0x5600
};

std::vector<uint8_t> make_hello_random(RandomNumberGenerator& rng,
                                    const Policy& policy)
   {
   std::vector<uint8_t> buf(32);
   rng.randomize(buf.data(), buf.size());

   if(policy.include_time_in_hello_random())
      {
      const uint32_t time32 = static_cast<uint32_t>(
         std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

      store_be(time32, buf.data());
      }

   return buf;
   }

/*
* Create a new Hello Request message
*/
Hello_Request::Hello_Request(Handshake_IO& io)
   {
   io.send(*this);
   }

/*
* Deserialize a Hello Request message
*/
Hello_Request::Hello_Request(const std::vector<uint8_t>& buf)
   {
   if(buf.size())
      throw Decoding_Error("Bad Hello_Request, has non-zero size");
   }

/*
* Serialize a Hello Request message
*/
std::vector<uint8_t> Hello_Request::serialize() const
   {
   return std::vector<uint8_t>();
   }

/*
* Create a new Client Hello message
*/
Client_Hello::Client_Hello(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& reneg_info,
                           const Client_Hello::Settings& client_settings,
                           const std::vector<std::string>& next_protocols) :
   m_version(client_settings.protocol_version()),
   m_random(make_hello_random(rng, policy)),
   m_suites(policy.ciphersuite_list(m_version, !client_settings.srp_identifier().empty())),
   m_comp_methods(policy.compression())
   {
   BOTAN_ASSERT(policy.acceptable_protocol_version(client_settings.protocol_version()),
                "Our policy accepts the version we are offering");

   /*
   * Place all empty extensions in front to avoid a bug in some systems
   * which reject hellos when the last extension in the list is empty.
   */
   m_extensions.add(new Extended_Master_Secret);
   m_extensions.add(new Session_Ticket());
   m_extensions.add(new Certificate_Status_Request);

   if(policy.negotiate_encrypt_then_mac())
      m_extensions.add(new Encrypt_then_MAC);

   m_extensions.add(new Renegotiation_Extension(reneg_info));

   /* IP address is not allowed in SNI */
   struct sockaddr_storage addrbuf;
   if(!client_settings.hostname().empty() &&
      inet_pton(AF_INET, client_settings.hostname().c_str(), &addrbuf) != 1 &&
      inet_pton(AF_INET6, client_settings.hostname().c_str(), &addrbuf) != 1)
      {
      m_extensions.add(new Server_Name_Indicator(client_settings.hostname()));
      }

   m_extensions.add(new Certificate_Status_Request({}, {}));

   if(reneg_info.empty() && !next_protocols.empty())
      m_extensions.add(new Application_Layer_Protocol_Notification(next_protocols));

   if(m_version.supports_negotiable_signature_algorithms())
      m_extensions.add(new Signature_Algorithms(policy.allowed_signature_hashes(),
                                                policy.allowed_signature_methods()));

   if(m_version.is_datagram_protocol())
      m_extensions.add(new SRTP_Protection_Profiles(policy.srtp_profiles()));

#if defined(BOTAN_HAS_SRP6)
   m_extensions.add(new SRP_Identifier(client_settings.srp_identifier()));
#else
   if(!client_settings.srp_identifier().empty())
      {
      throw Invalid_State("Attempting to initiate SRP session but TLS-SRP support disabled");
      }
#endif

   m_extensions.add(new Supported_Elliptic_Curves(policy.allowed_ecc_curves()));

   if(!policy.allowed_ecc_curves().empty())
      {
      m_extensions.add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
      }

   if(m_version.supports_negotiable_signature_algorithms())
      m_extensions.add(new Signature_Algorithms(policy.allowed_signature_hashes(),
                                                policy.allowed_signature_methods()));

   if(policy.send_fallback_scsv(client_settings.protocol_version()))
      m_suites.push_back(TLS_FALLBACK_SCSV);

   hash.update(io.send(*this));
   }

/*
* Create a new Client Hello message (session resumption case)
*/
Client_Hello::Client_Hello(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& reneg_info,
                           const Session& session,
                           const std::vector<std::string>& next_protocols) :
   m_version(session.version()),
   m_session_id(session.session_id()),
   m_random(make_hello_random(rng, policy)),
   m_suites(policy.ciphersuite_list(m_version, (session.srp_identifier() != ""))),
   m_comp_methods(policy.compression())
   {
   if(!value_exists(m_suites, session.ciphersuite_code()))
      m_suites.push_back(session.ciphersuite_code());

   if(!value_exists(m_comp_methods, session.compression_method()))
      m_comp_methods.push_back(session.compression_method());

   /*
   We always add the EMS extension, even if not used in the original session.
   If the server understands it and follows the RFC it should reject our resume
   attempt and upgrade us to a new session with the EMS protection.
   */
   m_extensions.add(new Extended_Master_Secret);
   m_extensions.add(new Certificate_Status_Request);

   m_extensions.add(new Renegotiation_Extension(reneg_info));
   m_extensions.add(new Server_Name_Indicator(session.server_info().hostname()));
   m_extensions.add(new Session_Ticket(session.session_ticket()));
   m_extensions.add(new Supported_Elliptic_Curves(policy.allowed_ecc_curves()));

   if(!policy.allowed_ecc_curves().empty())
      {
      m_extensions.add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
      }

   if(session.supports_encrypt_then_mac())
      m_extensions.add(new Encrypt_then_MAC);

#if defined(BOTAN_HAS_SRP6)
   m_extensions.add(new SRP_Identifier(session.srp_identifier()));
#else
   if(!session.srp_identifier().empty())
      {
      throw Invalid_State("Attempting to resume SRP session but TLS-SRP support disabled");
      }
#endif

   if(m_version.supports_negotiable_signature_algorithms())
      m_extensions.add(new Signature_Algorithms(policy.allowed_signature_hashes(),
                                                policy.allowed_signature_methods()));

   if(reneg_info.empty() && !next_protocols.empty())
      m_extensions.add(new Application_Layer_Protocol_Notification(next_protocols));

   hash.update(io.send(*this));
   }

void Client_Hello::update_hello_cookie(const Hello_Verify_Request& hello_verify)
   {
   if(!m_version.is_datagram_protocol())
      throw Exception("Cannot use hello cookie with stream protocol");

   m_hello_cookie = hello_verify.cookie();
   }

/*
* Serialize a Client Hello message
*/
std::vector<uint8_t> Client_Hello::serialize() const
   {
   std::vector<uint8_t> buf;

   buf.push_back(m_version.major_version());
   buf.push_back(m_version.minor_version());
   buf += m_random;

   append_tls_length_value(buf, m_session_id, 1);

   if(m_version.is_datagram_protocol())
      append_tls_length_value(buf, m_hello_cookie, 1);

   append_tls_length_value(buf, m_suites, 2);
   append_tls_length_value(buf, m_comp_methods, 1);

   /*
   * May not want to send extensions at all in some cases. If so,
   * should include SCSV value (if reneg info is empty, if not we are
   * renegotiating with a modern server)
   */

   buf += m_extensions.serialize();

   return buf;
   }

/*
* Read a counterparty client hello
*/
Client_Hello::Client_Hello(const std::vector<uint8_t>& buf)
   {
   if(buf.size() < 41)
      throw Decoding_Error("Client_Hello: Packet corrupted");

   TLS_Data_Reader reader("ClientHello", buf);

   const uint8_t major_version = reader.get_byte();
   const uint8_t minor_version = reader.get_byte();

   m_version = Protocol_Version(major_version, minor_version);

   m_random = reader.get_fixed<uint8_t>(32);

   m_session_id = reader.get_range<uint8_t>(1, 0, 32);

   if(m_version.is_datagram_protocol())
      m_hello_cookie = reader.get_range<uint8_t>(1, 0, 255);

   m_suites = reader.get_range_vector<uint16_t>(2, 1, 32767);

   m_comp_methods = reader.get_range_vector<uint8_t>(1, 1, 255);

   m_extensions.deserialize(reader);

   if(offered_suite(static_cast<uint16_t>(TLS_EMPTY_RENEGOTIATION_INFO_SCSV)))
      {
      if(Renegotiation_Extension* reneg = m_extensions.get<Renegotiation_Extension>())
         {
         if(!reneg->renegotiation_info().empty())
            throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                                "Client sent renegotiation SCSV and non-empty extension");
         }
      else
         {
         // add fake extension
         m_extensions.add(new Renegotiation_Extension());
         }
      }

   // Parsing complete, now any additional decoding checks

   if(m_version.supports_negotiable_signature_algorithms() == false)
      {
      if(m_extensions.has<Signature_Algorithms>())
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE,
                             "Client sent signature_algorithms extension in version that doesn't support it");
      }
   }

bool Client_Hello::sent_fallback_scsv() const
   {
   return offered_suite(static_cast<uint16_t>(TLS_FALLBACK_SCSV));
   }

/*
* Check if we offered this ciphersuite
*/
bool Client_Hello::offered_suite(uint16_t ciphersuite) const
   {
   for(size_t i = 0; i != m_suites.size(); ++i)
      if(m_suites[i] == ciphersuite)
         return true;
   return false;
   }

}

}
