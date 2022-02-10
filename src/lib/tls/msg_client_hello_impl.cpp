/*
* TLS Hello Request and Client Hello Messages
* (C) 2004-2011,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/msg_client_hello_impl.h>
#include <botan/tls_policy.h>
#include <botan/tls_magic.h>
#include <botan/tls_session.h>


////////////
#include <botan/tls_messages.h>
#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_policy.h>
#include <botan/tls_session.h>
#include <botan/rng.h>
#include <botan/hash.h>

#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/stl_util.h>
#include <chrono>
////////////

namespace Botan {

namespace TLS {

enum {
   TLS_EMPTY_RENEGOTIATION_INFO_SCSV        = 0x00FF,
};

std::vector<uint8_t> make_hello_random(RandomNumberGenerator& rng,
                                       const Policy& policy)
   {
   std::vector<uint8_t> buf(32);
   rng.randomize(buf.data(), buf.size());

   // TODO: We use a fixed output RNG in test_tls_rfc8448 to produce
   //       the expected client_hello. Disable this on demand only.
   // auto sha256 = HashFunction::create_or_throw("SHA-256");
   // sha256->update(buf);
   // sha256->final(buf);

   if(policy.include_time_in_hello_random())
      {
      const uint32_t time32 = static_cast<uint32_t>(
         std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

      store_be(time32, buf.data());
      }

   return buf;
   }

/*
* Create a new Client Hello message
*/
Client_Hello_Impl::Client_Hello_Impl(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           Callbacks& cb,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& reneg_info,
                           const Client_Hello::Settings& client_settings,
                           const std::vector<std::string>& next_protocols) :
   m_legacy_version(client_settings.protocol_version()),
   m_random(make_hello_random(rng, policy)),
   m_suites(policy.ciphersuite_list(m_legacy_version)),
   m_comp_methods(1)
   {
   BOTAN_UNUSED(io, hash, cb, reneg_info, next_protocols);

   if(!policy.acceptable_protocol_version(m_legacy_version))
      throw Internal_Error("Offering " + m_legacy_version.to_string() +
                           " but our own policy does not accept it");

   /*
   * Place all empty extensions in front to avoid a bug in some systems
   * which reject hellos when the last extension in the list is empty.
   */

   if (policy.use_extended_master_secret() || policy.allow_tls12() || policy.allow_dtls12())
      {
      // EMS must always be used for TLS 1.2 but is optional for TLS 1.3
      m_extensions.add(new Extended_Master_Secret);
      }
   }

/*
* Create a new Client Hello message (session resumption case)
*/
Client_Hello_Impl::Client_Hello_Impl(Handshake_IO& io,
                           Handshake_Hash& hash,
                           const Policy& policy,
                           Callbacks& cb,
                           RandomNumberGenerator& rng,
                           const std::vector<uint8_t>& reneg_info,
                           const Session& session,
                           const std::vector<std::string>& next_protocols) :
   m_legacy_version(session.version()),
   m_session_id(session.session_id()),
   m_random(make_hello_random(rng, policy)),
   m_suites(policy.ciphersuite_list(m_legacy_version)),
   m_comp_methods(1)
   {
   BOTAN_UNUSED(io, hash, cb, reneg_info, next_protocols);

   if(!policy.acceptable_protocol_version(m_legacy_version))
      throw Internal_Error("Offering " + m_legacy_version.to_string() +
                           " but our own policy does not accept it");

   if (policy.use_extended_master_secret() || policy.allow_tls12() || policy.allow_dtls12())
      {
      /*
      * As EMS must always be used with TLS 1.2, add it even if it wasn't used
      * in the original session. If the server understands it and follows the
      * RFC it should reject our resume attempt and upgrade us to a new session
      * with the EMS protection.
      */
      m_extensions.add(new Extended_Master_Secret);
      }
   }

/*
* Read a counterparty client hello
*/
Client_Hello_Impl::Client_Hello_Impl(const std::vector<uint8_t>& buf)
   {
   if(buf.size() < 41)
      throw Decoding_Error("Client_Hello_Impl: Packet corrupted");

   TLS_Data_Reader reader("ClientHello", buf);

   const uint8_t major_version = reader.get_byte();
   const uint8_t minor_version = reader.get_byte();

   m_legacy_version = Protocol_Version(major_version, minor_version);
   m_random = reader.get_fixed<uint8_t>(32);
   m_session_id = reader.get_range<uint8_t>(1, 0, 32);

   if(m_legacy_version.is_datagram_protocol())
      {
      auto sha256 = HashFunction::create_or_throw("SHA-256");
      sha256->update(reader.get_data_read_so_far());

      m_hello_cookie = reader.get_range<uint8_t>(1, 0, 255);

      sha256->update(reader.get_remaining());
      m_cookie_input_bits.resize(sha256->output_length());
      sha256->final(m_cookie_input_bits.data());
      }

   m_suites = reader.get_range_vector<uint16_t>(2, 1, 32767);

   m_comp_methods = reader.get_range_vector<uint8_t>(1, 1, 255);

   m_extensions.deserialize(reader, Connection_Side::CLIENT);

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
   }

Handshake_Type Client_Hello_Impl::type() const
   {
   return CLIENT_HELLO;
   }

Protocol_Version Client_Hello_Impl::legacy_version() const
   {
   return m_legacy_version;
   }

const std::vector<uint8_t>& Client_Hello_Impl::random() const
   {
   return m_random;
   }

const std::vector<uint8_t>& Client_Hello_Impl::session_id() const
   {
   return m_session_id;
   }

const std::vector<uint8_t>& Client_Hello_Impl::compression_methods() const
   {
   return m_comp_methods;
   }

const std::vector<uint16_t>& Client_Hello_Impl::ciphersuites() const
   {
   return m_suites;
   }

std::set<Handshake_Extension_Type> Client_Hello_Impl::extension_types() const
   {
   return m_extensions.extension_types();
   }

const Extensions& Client_Hello_Impl::extensions() const
   {
   return m_extensions;
   }

void Client_Hello_Impl::update_hello_cookie(const Hello_Verify_Request& hello_verify)
   {
   if(!m_legacy_version.is_datagram_protocol())
      throw Invalid_State("Cannot use hello cookie with stream protocol");

   m_hello_cookie = hello_verify.cookie();
   }

/*
* Serialize a Client Hello message
*/
std::vector<uint8_t> Client_Hello_Impl::serialize() const
   {
   std::vector<uint8_t> buf;

   buf.push_back(m_legacy_version.major_version());
   buf.push_back(m_legacy_version.minor_version());
   buf += m_random;

   append_tls_length_value(buf, m_session_id, 1);

   if(m_legacy_version.is_datagram_protocol())
      append_tls_length_value(buf, m_hello_cookie, 1);

   append_tls_length_value(buf, m_suites, 2);
   append_tls_length_value(buf, m_comp_methods, 1);

   /*
   * May not want to send extensions at all in some cases. If so,
   * should include SCSV value (if reneg info is empty, if not we are
   * renegotiating with a modern server)
   */

   buf += m_extensions.serialize(Connection_Side::CLIENT);

   return buf;
   }

std::vector<uint8_t> Client_Hello_Impl::cookie_input_data() const
   {
   if(m_cookie_input_bits.empty())
      throw Invalid_State("Client_Hello_Impl::cookie_input_data called but was not computed");

   return m_cookie_input_bits;
   }

/*
* Check if we offered this ciphersuite
*/
bool Client_Hello_Impl::offered_suite(uint16_t ciphersuite) const
   {
   return std::find(m_suites.cbegin(), m_suites.cend(), ciphersuite) != m_suites.cend();
   }

std::vector<Signature_Scheme> Client_Hello_Impl::signature_schemes() const
   {
   std::vector<Signature_Scheme> schemes;

   if(Signature_Algorithms* sigs = m_extensions.get<Signature_Algorithms>())
      {
      schemes = sigs->supported_schemes();
      }

   return schemes;
   }

std::vector<Group_Params> Client_Hello_Impl::supported_ecc_curves() const
   {
   if(Supported_Groups* groups = m_extensions.get<Supported_Groups>())
      return groups->ec_groups();
   return std::vector<Group_Params>();
   }

std::vector<Group_Params> Client_Hello_Impl::supported_dh_groups() const
   {
   if(Supported_Groups* groups = m_extensions.get<Supported_Groups>())
      return groups->dh_groups();
   return std::vector<Group_Params>();
   }

bool Client_Hello_Impl::prefers_compressed_ec_points() const
   {
   if(Supported_Point_Formats* ecc_formats = m_extensions.get<Supported_Point_Formats>())
      {
      return ecc_formats->prefers_compressed();
      }
   return false;
   }

std::string Client_Hello_Impl::sni_hostname() const
   {
   if(Server_Name_Indicator* sni = m_extensions.get<Server_Name_Indicator>())
      return sni->host_name();
   return "";
   }

bool Client_Hello_Impl::secure_renegotiation() const
   {
   return m_extensions.has<Renegotiation_Extension>();
   }

std::vector<uint8_t> Client_Hello_Impl::renegotiation_info() const
   {
   if(Renegotiation_Extension* reneg = m_extensions.get<Renegotiation_Extension>())
      return reneg->renegotiation_info();
   return std::vector<uint8_t>();
   }

std::vector<Protocol_Version> Client_Hello_Impl::supported_versions() const
   {
   if(Supported_Versions* versions = m_extensions.get<Supported_Versions>())
      return versions->versions();
   return {};
   }

bool Client_Hello_Impl::supports_session_ticket() const
   {
   return m_extensions.has<Session_Ticket>();
   }

std::vector<uint8_t> Client_Hello_Impl::session_ticket() const
   {
   if(Session_Ticket* ticket = m_extensions.get<Session_Ticket>())
      return ticket->contents();
   return std::vector<uint8_t>();
   }

bool Client_Hello_Impl::supports_alpn() const
   {
   return m_extensions.has<Application_Layer_Protocol_Notification>();
   }

bool Client_Hello_Impl::supports_extended_master_secret() const
   {
   return m_extensions.has<Extended_Master_Secret>();
   }

bool Client_Hello_Impl::supports_cert_status_message() const
   {
   return m_extensions.has<Certificate_Status_Request>();
   }

bool Client_Hello_Impl::supports_encrypt_then_mac() const
   {
   return m_extensions.has<Encrypt_then_MAC>();
   }

bool Client_Hello_Impl::sent_signature_algorithms() const
   {
   return m_extensions.has<Signature_Algorithms>();
   }

std::vector<std::string> Client_Hello_Impl::next_protocols() const
   {
   if(auto alpn = m_extensions.get<Application_Layer_Protocol_Notification>())
      return alpn->protocols();
   return std::vector<std::string>();
   }

std::vector<uint16_t> Client_Hello_Impl::srtp_profiles() const
   {
   if(SRTP_Protection_Profiles* srtp = m_extensions.get<SRTP_Protection_Profiles>())
      return srtp->profiles();
   return std::vector<uint16_t>();
   }

const std::vector<uint8_t>& Client_Hello_Impl::cookie() const
{
return m_hello_cookie;
}

}

}
