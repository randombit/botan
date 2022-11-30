/*
* TLS Hello Request and Client Hello Messages
* (C) 2004-2011,2015,2016 Jack Lloyd
*     2016 Matthias Gierlings
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#include <botan/tls_exceptn.h>
#include <botan/tls_messages.h>
#include <botan/tls_callbacks.h>
#include <botan/rng.h>
#include <botan/hash.h>
#include <botan/tls_version.h>

#include <botan/internal/stl_util.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_handshake_hash.h>

#ifdef BOTAN_HAS_TLS_13
  #include <botan/internal/tls_transcript_hash_13.h>
  #include <botan/internal/tls_handshake_layer_13.h>
#endif

#include <chrono>

namespace Botan::TLS {

enum
   {
   TLS_EMPTY_RENEGOTIATION_INFO_SCSV        = 0x00FF,
   };

std::vector<uint8_t> make_hello_random(RandomNumberGenerator& rng,
                                       Callbacks& cb,
                                       const Policy& policy)
   {
   std::vector<uint8_t> buf(32);
   rng.randomize(buf.data(), buf.size());

   if(policy.hash_hello_random())
      {
      auto sha256 = HashFunction::create_or_throw("SHA-256");
      sha256->update(buf);
      sha256->final(buf);
      }

   // TLS 1.3 does not require the insertion of a timestamp in the client hello
   // random. When offering both TLS 1.2 and 1.3 we nevertheless comply with the
   // legacy specification.
   if(policy.include_time_in_hello_random() && (policy.allow_tls12() || policy.allow_dtls12()))
      {
      const uint32_t time32 = static_cast<uint32_t>(
                                 std::chrono::system_clock::to_time_t(cb.tls_current_timestamp()));

      store_be(time32, buf.data());
      }

   return buf;
   }

/*
* Read a counterparty client hello
*/
Client_Hello::Client_Hello(const std::vector<uint8_t>& buf)
   {
   if(buf.size() < 41)
      { throw Decoding_Error("Client_Hello: Packet corrupted"); }

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

   m_extensions.deserialize(reader, Connection_Side::CLIENT, type());

   // TODO: Reject oid_filters extension if found (which is the only known extension that
   //       must not occur in the TLS 1.3 client hello.
   // RFC 8446 4.2.5
   //    [The oid_filters extension] MUST only be sent in the CertificateRequest message.
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

Handshake_Type Client_Hello::type() const
   {
   return CLIENT_HELLO;
   }

Protocol_Version Client_Hello::legacy_version() const
   {
   return m_legacy_version;
   }

const std::vector<uint8_t>& Client_Hello::random() const
   {
   return m_random;
   }

const std::vector<uint8_t>& Client_Hello::session_id() const
   {
   return m_session_id;
   }

const std::vector<uint8_t>& Client_Hello::compression_methods() const
   {
   return m_comp_methods;
   }

const std::vector<uint16_t>& Client_Hello::ciphersuites() const
   {
   return m_suites;
   }

std::set<Handshake_Extension_Type> Client_Hello::extension_types() const
   {
   return m_extensions.extension_types();
   }

const Extensions& Client_Hello::extensions() const
   {
   return m_extensions;
   }

void Client_Hello_12::update_hello_cookie(const Hello_Verify_Request& hello_verify)
   {
   if(!m_legacy_version.is_datagram_protocol())
      { throw Invalid_State("Cannot use hello cookie with stream protocol"); }

   m_hello_cookie = hello_verify.cookie();
   }

/*
* Serialize a Client Hello message
*/
std::vector<uint8_t> Client_Hello::serialize() const
   {
   std::vector<uint8_t> buf;
   buf.reserve(1024); // working around GCC warning

   buf.push_back(m_legacy_version.major_version());
   buf.push_back(m_legacy_version.minor_version());
   buf += m_random;

   append_tls_length_value(buf, m_session_id, 1);

   if(m_legacy_version.is_datagram_protocol())
      { append_tls_length_value(buf, m_hello_cookie, 1); }

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

std::vector<uint8_t> Client_Hello::cookie_input_data() const
   {
   if(m_cookie_input_bits.empty())
      { throw Invalid_State("Client_Hello::cookie_input_data called but was not computed"); }

   return m_cookie_input_bits;
   }

/*
* Check if we offered this ciphersuite
*/
bool Client_Hello::offered_suite(uint16_t ciphersuite) const
   {
   return std::find(m_suites.cbegin(), m_suites.cend(), ciphersuite) != m_suites.cend();
   }

std::vector<Signature_Scheme> Client_Hello::signature_schemes() const
   {
   std::vector<Signature_Scheme> schemes;

   if(Signature_Algorithms* sigs = m_extensions.get<Signature_Algorithms>())
      {
      schemes = sigs->supported_schemes();
      }

   return schemes;
   }

std::vector<Group_Params> Client_Hello::supported_ecc_curves() const
   {
   if(Supported_Groups* groups = m_extensions.get<Supported_Groups>())
      { return groups->ec_groups(); }
   return std::vector<Group_Params>();
   }

std::vector<Group_Params> Client_Hello::supported_dh_groups() const
   {
   if(Supported_Groups* groups = m_extensions.get<Supported_Groups>())
      { return groups->dh_groups(); }
   return std::vector<Group_Params>();
   }

bool Client_Hello_12::prefers_compressed_ec_points() const
   {
   if(Supported_Point_Formats* ecc_formats = m_extensions.get<Supported_Point_Formats>())
      {
      return ecc_formats->prefers_compressed();
      }
   return false;
   }

std::string Client_Hello::sni_hostname() const
   {
   if(Server_Name_Indicator* sni = m_extensions.get<Server_Name_Indicator>())
      { return sni->host_name(); }
   return "";
   }

bool Client_Hello_12::secure_renegotiation() const
   {
   return m_extensions.has<Renegotiation_Extension>();
   }

std::vector<uint8_t> Client_Hello_12::renegotiation_info() const
   {
   if(Renegotiation_Extension* reneg = m_extensions.get<Renegotiation_Extension>())
      { return reneg->renegotiation_info(); }
   return std::vector<uint8_t>();
   }

std::vector<Protocol_Version> Client_Hello::supported_versions() const
   {
   if(Supported_Versions* versions = m_extensions.get<Supported_Versions>())
      { return versions->versions(); }
   return {};
   }

bool Client_Hello_12::supports_session_ticket() const
   {
   return m_extensions.has<Session_Ticket>();
   }

std::vector<uint8_t> Client_Hello_12::session_ticket() const
   {
   if(Session_Ticket* ticket = m_extensions.get<Session_Ticket>())
      { return ticket->contents(); }
   return std::vector<uint8_t>();
   }

bool Client_Hello::supports_alpn() const
   {
   return m_extensions.has<Application_Layer_Protocol_Notification>();
   }

bool Client_Hello_12::supports_extended_master_secret() const
   {
   return m_extensions.has<Extended_Master_Secret>();
   }

bool Client_Hello_12::supports_cert_status_message() const
   {
   return m_extensions.has<Certificate_Status_Request>();
   }

bool Client_Hello_12::supports_encrypt_then_mac() const
   {
   return m_extensions.has<Encrypt_then_MAC>();
   }

bool Client_Hello::sent_signature_algorithms() const
   {
   return m_extensions.has<Signature_Algorithms>();
   }

std::vector<std::string> Client_Hello::next_protocols() const
   {
   if(auto alpn = m_extensions.get<Application_Layer_Protocol_Notification>())
      { return alpn->protocols(); }
   return std::vector<std::string>();
   }

std::vector<uint16_t> Client_Hello::srtp_profiles() const
   {
   if(SRTP_Protection_Profiles* srtp = m_extensions.get<SRTP_Protection_Profiles>())
      { return srtp->profiles(); }
   return std::vector<uint16_t>();
   }

const std::vector<uint8_t>& Client_Hello::cookie() const
   {
   return m_hello_cookie;
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
   if(!buf.empty())
      { throw Decoding_Error("Bad Hello_Request, has non-zero size"); }
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
Client_Hello_12::Client_Hello_12(Handshake_IO& io,
                                 Handshake_Hash& hash,
                                 const Policy& policy,
                                 Callbacks& cb,
                                 RandomNumberGenerator& rng,
                                 const std::vector<uint8_t>& reneg_info,
                                 const Client_Hello_12::Settings& client_settings,
                                 const std::vector<std::string>& next_protocols)
   {
   m_legacy_version = client_settings.protocol_version();
   m_random = make_hello_random(rng, cb, policy);
   m_suites = policy.ciphersuite_list(client_settings.protocol_version());

   if(!policy.acceptable_protocol_version(m_legacy_version))
      throw Internal_Error("Offering " + m_legacy_version.to_string() +
                           " but our own policy does not accept it");

   /*
   * Place all empty extensions in front to avoid a bug in some systems
   * which reject hellos when the last extension in the list is empty.
   */

   // EMS must always be used with TLS 1.2, regardless of the policy used.
   m_extensions.add(new Extended_Master_Secret);

   if(policy.negotiate_encrypt_then_mac())
      { m_extensions.add(new Encrypt_then_MAC); }

   m_extensions.add(new Session_Ticket());

   m_extensions.add(new Renegotiation_Extension(reneg_info));

   m_extensions.add(new Supported_Versions(m_legacy_version, policy));

   if(!client_settings.hostname().empty())
      { m_extensions.add(new Server_Name_Indicator(client_settings.hostname())); }

   if(policy.support_cert_status_message())
      m_extensions.add(new Certificate_Status_Request({}, {}));

   auto supported_groups = std::make_unique<Supported_Groups>(policy.key_exchange_groups());
   if(!supported_groups->ec_groups().empty())
      {
      m_extensions.add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
      }
   m_extensions.add(supported_groups.release());

   m_extensions.add(new Signature_Algorithms(policy.acceptable_signature_schemes()));

   if(reneg_info.empty() && !next_protocols.empty())
      { m_extensions.add(new Application_Layer_Protocol_Notification(next_protocols)); }

   if(m_legacy_version.is_datagram_protocol())
      { m_extensions.add(new SRTP_Protection_Profiles(policy.srtp_profiles())); }

   cb.tls_modify_extensions(m_extensions, CLIENT);

   hash.update(io.send(*this));
   }

/*
* Create a new Client Hello message (session resumption case)
*/
Client_Hello_12::Client_Hello_12(Handshake_IO& io,
                                 Handshake_Hash& hash,
                                 const Policy& policy,
                                 Callbacks& cb,
                                 RandomNumberGenerator& rng,
                                 const std::vector<uint8_t>& reneg_info,
                                 const Session& session,
                                 const std::vector<std::string>& next_protocols)
   {
   m_legacy_version = session.version();
   m_random = make_hello_random(rng, cb, policy);
   m_session_id = session.session_id();
   m_suites = policy.ciphersuite_list(m_legacy_version);

   if(!policy.acceptable_protocol_version(session.version()))
      throw Internal_Error("Offering " + m_legacy_version.to_string() +
                           " but our own policy does not accept it");

   if(!value_exists(m_suites, session.ciphersuite_code()))
      { m_suites.push_back(session.ciphersuite_code()); }

   /*
   * As EMS must always be used with TLS 1.2, add it even if it wasn't used
   * in the original session. If the server understands it and follows the
   * RFC it should reject our resume attempt and upgrade us to a new session
   * with the EMS protection.
   */
   m_extensions.add(new Extended_Master_Secret);

   if(session.supports_encrypt_then_mac())
      { m_extensions.add(new Encrypt_then_MAC); }

   m_extensions.add(new Session_Ticket(session.session_ticket()));

   m_extensions.add(new Renegotiation_Extension(reneg_info));

   m_extensions.add(new Server_Name_Indicator(session.server_info().hostname()));

   if(policy.support_cert_status_message())
      m_extensions.add(new Certificate_Status_Request({}, {}));

   auto supported_groups = std::make_unique<Supported_Groups>(policy.key_exchange_groups());

   if(!supported_groups->ec_groups().empty())
      {
      m_extensions.add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
      }

   m_extensions.add(supported_groups.release());

   m_extensions.add(new Signature_Algorithms(policy.acceptable_signature_schemes()));

   if(reneg_info.empty() && !next_protocols.empty())
      { m_extensions.add(new Application_Layer_Protocol_Notification(next_protocols)); }

   cb.tls_modify_extensions(m_extensions, CLIENT);

   hash.update(io.send(*this));
   }

#if defined(BOTAN_HAS_TLS_13)

/*
* Create a new Client Hello message
*/
Client_Hello_13::Client_Hello_13(const Policy& policy,
                                 Callbacks& cb,
                                 RandomNumberGenerator& rng,
                                 const std::string& hostname,
                                 const std::vector<std::string>& next_protocols,
                                 const std::optional<Session>& session)
   {
   // RFC 8446 4.1.2
   //    In TLS 1.3, the client indicates its version preferences in the
   //    "supported_versions" extension (Section 4.2.1) and the
   //    legacy_version field MUST be set to 0x0303, which is the version
   //    number for TLS 1.2.
   m_legacy_version = Protocol_Version::TLS_V12;
   m_random = make_hello_random(rng, cb, policy);
   m_suites = policy.ciphersuite_list(Protocol_Version::TLS_V13);

   if(policy.allow_tls12())  // Note: DTLS 1.3 is NYI, hence dtls_12 is not checked
      {
      const auto legacy_suites = policy.ciphersuite_list(Protocol_Version::TLS_V12);
      m_suites.insert(m_suites.end(), legacy_suites.cbegin(), legacy_suites.cend());
      }

   if(policy.tls_13_middlebox_compatibility_mode())
      {
      // RFC 8446 4.1.2
      //    In compatibility mode (see Appendix D.4), this field MUST be non-empty,
      //    so a client not offering a pre-TLS 1.3 session MUST generate a new
      //    32-byte value.
      rng.random_vec(m_session_id, 32);
      }

   if(!hostname.empty())
      m_extensions.add(new Server_Name_Indicator(hostname));

   m_extensions.add(new Supported_Groups(policy.key_exchange_groups()));

   m_extensions.add(new Key_Share(policy, cb, rng));

   m_extensions.add(new Supported_Versions(Protocol_Version::TLS_V13, policy));

   m_extensions.add(new Signature_Algorithms(policy.acceptable_signature_schemes()));

   // TODO: Support for PSK-only mode without a key exchange.
   //       This should be configurable in TLS::Policy and should allow no PSK
   //       support at all (e.g. to disable support for session resumption).
   m_extensions.add(new PSK_Key_Exchange_Modes({PSK_Key_Exchange_Mode::PSK_DHE_KE}));

   // TODO: Add a signature_algorithms_cert extension negotiating the acceptable
   //       signature algorithms in a server certificate chain's certificates.

   if(policy.support_cert_status_message())
      m_extensions.add(new Certificate_Status_Request({}, {}));

   // We currently support "record_size_limit" for TLS 1.3 exclusively. Hence,
   // when TLS 1.2 is advertised as a supported protocol, we must not offer this
   // extension.
   if(policy.record_size_limit().has_value() && !policy.allow_tls12())
      m_extensions.add(new Record_Size_Limit(policy.record_size_limit().value()));

   if(!next_protocols.empty())
      m_extensions.add(new Application_Layer_Protocol_Notification(next_protocols));

   if(policy.allow_tls12())
      {
      m_extensions.add(new Renegotiation_Extension());
      m_extensions.add(new Session_Ticket());

      // EMS must always be used with TLS 1.2, regardless of the policy
      m_extensions.add(new Extended_Master_Secret);

      if(policy.negotiate_encrypt_then_mac())
         m_extensions.add(new Encrypt_then_MAC);

      if(m_extensions.has<Supported_Groups>() && !m_extensions.get<Supported_Groups>()->ec_groups().empty())
         m_extensions.add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
      }

   // TODO: Some extensions require a certain order or pose other assumptions.
   //       We should check those after the user was allowed to make changes to
   //       the extensions.
   cb.tls_modify_extensions(m_extensions, CLIENT);

   // RFC 8446 4.2.11
   //    The "pre_shared_key" extension MUST be the last extension in the
   //    ClientHello (this facilitates implementation [...]).
   //
   // The PSK extension takes the partial transcript hash into account. Passing
   // into Callbacks::tls_modify_extensions() does not make sense therefore.
   if(session.has_value())
      {
      m_extensions.add(new PSK(session.value(), cb));
      calculate_psk_binders({});
      }
   }

void Client_Hello_13::retry(const Hello_Retry_Request& hrr,
                            const Transcript_Hash_State& transcript_hash_state,
                            Callbacks& cb,
                            RandomNumberGenerator& rng)
   {
   BOTAN_STATE_CHECK(m_extensions.has<Supported_Groups>());
   BOTAN_STATE_CHECK(m_extensions.has<Key_Share>());

   auto hrr_ks = hrr.extensions().get<Key_Share>();
   const auto& supported_groups = m_extensions.get<Supported_Groups>()->groups();

   if(hrr.extensions().has<Key_Share>())
      m_extensions.get<Key_Share>()->retry_offer(*hrr_ks, supported_groups, cb, rng);

   // RFC 8446 4.2.2
   //    When sending the new ClientHello, the client MUST copy
   //    the contents of the extension received in the HelloRetryRequest into
   //    a "cookie" extension in the new ClientHello.
   //
   // RFC 8446 4.2.2
   //    Clients MUST NOT use cookies in their initial ClientHello in subsequent
   //    connections.
   if(hrr.extensions().has<Cookie>())
      {
      BOTAN_STATE_CHECK(!m_extensions.has<Cookie>());
      m_extensions.add(new Cookie(hrr.extensions().get<Cookie>()->get_cookie()));
      }

   // TODO: the consumer of the TLS implementation won't be able to distinguish
   //       invocations to this callback due to the first Client_Hello or the
   //       retried Client_Hello after receiving a Hello_Retry_Request.
   cb.tls_modify_extensions(m_extensions, CLIENT);

   auto psk = m_extensions.get<PSK>();
   if(psk)
      {
      // Cipher suite should always be a known suite as this is checked upstream
      const auto cipher = Ciphersuite::by_id(hrr.ciphersuite());
      BOTAN_ASSERT_NOMSG(cipher.has_value());

      // RFC 8446 4.1.4
      //    In [...] its updated ClientHello, the client SHOULD NOT offer
      //    any pre-shared keys associated with a hash other than that of the
      //    selected cipher suite.
      psk->filter(cipher.value());

      // RFC 8446 4.2.11.2
      //    If the server responds with a HelloRetryRequest and the client
      //    then sends ClientHello2, its binder will be computed over: [...].
      calculate_psk_binders(transcript_hash_state.clone());
      }
   }

void Client_Hello_13::calculate_psk_binders(Transcript_Hash_State ths)
   {
   auto psk = m_extensions.get<PSK>();
   if(!psk || psk->empty())
      return;

   // RFC 8446 4.2.11.2
   //    Each entry in the binders list is computed as an HMAC over a
   //    transcript hash (see Section 4.4.1) containing a partial ClientHello
   //    [...].
   //
   // Therefore we marshal the entire message prematurely to obtain the
   // (truncated) transcript hash, calculate the PSK binders with it, update
   // the Client Hello thus finalizing the message. Down the road, it will be
   // re-marshalled with the correct binders and sent over the wire.
   Handshake_Layer::prepare_message(*this, ths);
   psk->calculate_binders(ths);
   }

#endif // BOTAN_HAS_TLS_13

}
