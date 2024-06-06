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

#include <botan/tls_messages.h>

#include <botan/credentials_manager.h>
#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_version.h>

#include <botan/internal/parsing.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_session_key.h>

#ifdef BOTAN_HAS_TLS_13
   #include <botan/internal/tls_handshake_layer_13.h>
   #include <botan/internal/tls_transcript_hash_13.h>
#endif

#include <chrono>
#include <iterator>

namespace Botan::TLS {

std::vector<uint8_t> make_hello_random(RandomNumberGenerator& rng, Callbacks& cb, const Policy& policy) {
   auto buf = rng.random_vec<std::vector<uint8_t>>(32);

   if(policy.hash_hello_random()) {
      auto sha256 = HashFunction::create_or_throw("SHA-256");
      sha256->update(buf);
      sha256->final(buf);
   }

   // TLS 1.3 does not require the insertion of a timestamp in the client hello
   // random. When offering both TLS 1.2 and 1.3 we nevertheless comply with the
   // legacy specification.
   if(policy.include_time_in_hello_random() && (policy.allow_tls12() || policy.allow_dtls12())) {
      const uint32_t time32 = static_cast<uint32_t>(std::chrono::system_clock::to_time_t(cb.tls_current_timestamp()));

      store_be(time32, buf.data());
   }

   return buf;
}

/**
 * Version-agnostic internal client hello data container that allows
 * parsing Client_Hello messages without prior knowledge of the contained
 * protocol version.
 */
class Client_Hello_Internal {
   public:
      Client_Hello_Internal() : m_comp_methods({0}) {}

      Client_Hello_Internal(const std::vector<uint8_t>& buf) {
         if(buf.size() < 41) {
            throw Decoding_Error("Client_Hello: Packet corrupted");
         }

         TLS_Data_Reader reader("ClientHello", buf);

         const uint8_t major_version = reader.get_byte();
         const uint8_t minor_version = reader.get_byte();

         m_legacy_version = Protocol_Version(major_version, minor_version);
         m_random = reader.get_fixed<uint8_t>(32);
         m_session_id = Session_ID(reader.get_range<uint8_t>(1, 0, 32));

         if(m_legacy_version.is_datagram_protocol()) {
            auto sha256 = HashFunction::create_or_throw("SHA-256");
            sha256->update(reader.get_data_read_so_far());

            m_hello_cookie = reader.get_range<uint8_t>(1, 0, 255);

            sha256->update(reader.get_remaining());
            m_cookie_input_bits = sha256->final_stdvec();
         }

         m_suites = reader.get_range_vector<uint16_t>(2, 1, 32767);
         m_comp_methods = reader.get_range_vector<uint8_t>(1, 1, 255);

         m_extensions.deserialize(reader, Connection_Side::Client, Handshake_Type::ClientHello);
      }

      /**
       * This distinguishes between a TLS 1.3 compliant Client Hello (containing
       * the "supported_version" extension) and legacy Client Hello messages.
       *
       * @return TLS 1.3 if the Client Hello contains "supported_versions", or
       *         the content of the "legacy_version" version field if it
       *         indicates (D)TLS 1.2 or older, or
       *         (D)TLS 1.2 if the "legacy_version" was some other odd value.
       */
      Protocol_Version version() const {
         // RFC 8446 4.2.1
         //    If [the "supported_versions"] extension is not present, servers
         //    which are compliant with this specification and which also support
         //    TLS 1.2 MUST negotiate TLS 1.2 or prior as specified in [RFC5246],
         //    even if ClientHello.legacy_version is 0x0304 or later.
         //
         // RFC 8446 4.2.1
         //    Servers MUST be prepared to receive ClientHellos that include
         //    [the supported_versions] extension but do not include 0x0304 in
         //    the list of versions.
         //
         // RFC 8446 4.1.2
         //    TLS 1.3 ClientHellos are identified as having a legacy_version of
         //    0x0303 and a supported_versions extension present with 0x0304 as
         //    the highest version indicated therein.
         if(!extensions().has<Supported_Versions>() ||
            !extensions().get<Supported_Versions>()->supports(Protocol_Version::TLS_V13)) {
            // The exact legacy_version is ignored we just inspect it to
            // distinguish TLS and DTLS.
            return (m_legacy_version.is_datagram_protocol()) ? Protocol_Version::DTLS_V12 : Protocol_Version::TLS_V12;
         }

         // Note: The Client_Hello_13 class will make sure that legacy_version
         //       is exactly 0x0303 (aka ossified TLS 1.2)
         return Protocol_Version::TLS_V13;
      }

      Protocol_Version legacy_version() const { return m_legacy_version; }

      const Session_ID& session_id() const { return m_session_id; }

      const std::vector<uint8_t>& random() const { return m_random; }

      const std::vector<uint16_t>& ciphersuites() const { return m_suites; }

      const std::vector<uint8_t>& comp_methods() const { return m_comp_methods; }

      const std::vector<uint8_t>& hello_cookie() const { return m_hello_cookie; }

      const std::vector<uint8_t>& hello_cookie_input_bits() const { return m_cookie_input_bits; }

      const Extensions& extensions() const { return m_extensions; }

      Extensions& extensions() { return m_extensions; }

   public:
      Protocol_Version m_legacy_version;    // NOLINT(*-non-private-member-variables-in-classes)
      Session_ID m_session_id;              // NOLINT(*-non-private-member-variables-in-classes)
      std::vector<uint8_t> m_random;        // NOLINT(*-non-private-member-variables-in-classes)
      std::vector<uint16_t> m_suites;       // NOLINT(*-non-private-member-variables-in-classes)
      std::vector<uint8_t> m_comp_methods;  // NOLINT(*-non-private-member-variables-in-classes)
      Extensions m_extensions;              // NOLINT(*-non-private-member-variables-in-classes)

      // These fields are only for DTLS:
      std::vector<uint8_t> m_hello_cookie;       // NOLINT(*-non-private-member-variables-in-classes)
      std::vector<uint8_t> m_cookie_input_bits;  // NOLINT(*-non-private-member-variables-in-classes)
};

Client_Hello::Client_Hello(Client_Hello&&) noexcept = default;
Client_Hello& Client_Hello::operator=(Client_Hello&&) noexcept = default;

Client_Hello::~Client_Hello() = default;

Client_Hello::Client_Hello() : m_data(std::make_unique<Client_Hello_Internal>()) {}

/*
* Read a counterparty client hello
*/
Client_Hello::Client_Hello(std::unique_ptr<Client_Hello_Internal> data) : m_data(std::move(data)) {
   BOTAN_ASSERT_NONNULL(m_data);
}

Handshake_Type Client_Hello::type() const {
   return Handshake_Type::ClientHello;
}

Protocol_Version Client_Hello::legacy_version() const {
   return m_data->legacy_version();
}

const std::vector<uint8_t>& Client_Hello::random() const {
   return m_data->random();
}

const Session_ID& Client_Hello::session_id() const {
   return m_data->session_id();
}

const std::vector<uint8_t>& Client_Hello::compression_methods() const {
   return m_data->comp_methods();
}

const std::vector<uint16_t>& Client_Hello::ciphersuites() const {
   return m_data->ciphersuites();
}

std::set<Extension_Code> Client_Hello::extension_types() const {
   return m_data->extensions().extension_types();
}

const Extensions& Client_Hello::extensions() const {
   return m_data->extensions();
}

void Client_Hello_12::update_hello_cookie(const Hello_Verify_Request& hello_verify) {
   BOTAN_STATE_CHECK(m_data->legacy_version().is_datagram_protocol());

   m_data->m_hello_cookie = hello_verify.cookie();
}

/*
* Serialize a Client Hello message
*/
std::vector<uint8_t> Client_Hello::serialize() const {
   std::vector<uint8_t> buf;
   buf.reserve(1024);  // working around GCC warning

   buf.push_back(m_data->legacy_version().major_version());
   buf.push_back(m_data->legacy_version().minor_version());
   buf += m_data->random();

   append_tls_length_value(buf, m_data->session_id().get(), 1);

   if(m_data->legacy_version().is_datagram_protocol()) {
      append_tls_length_value(buf, m_data->hello_cookie(), 1);
   }

   append_tls_length_value(buf, m_data->ciphersuites(), 2);
   append_tls_length_value(buf, m_data->comp_methods(), 1);

   /*
   * May not want to send extensions at all in some cases. If so,
   * should include SCSV value (if reneg info is empty, if not we are
   * renegotiating with a modern server)
   */

   buf += m_data->extensions().serialize(Connection_Side::Client);

   return buf;
}

std::vector<uint8_t> Client_Hello::cookie_input_data() const {
   BOTAN_STATE_CHECK(!m_data->hello_cookie_input_bits().empty());

   return m_data->hello_cookie_input_bits();
}

/*
* Check if we offered this ciphersuite
*/
bool Client_Hello::offered_suite(uint16_t ciphersuite) const {
   return std::find(m_data->ciphersuites().cbegin(), m_data->ciphersuites().cend(), ciphersuite) !=
          m_data->ciphersuites().cend();
}

std::vector<Signature_Scheme> Client_Hello::signature_schemes() const {
   if(Signature_Algorithms* sigs = m_data->extensions().get<Signature_Algorithms>()) {
      return sigs->supported_schemes();
   }
   return {};
}

std::vector<Signature_Scheme> Client_Hello::certificate_signature_schemes() const {
   // RFC 8446 4.2.3
   //   If no "signature_algorithms_cert" extension is present, then the
   //   "signature_algorithms" extension also applies to signatures appearing
   //   in certificates.
   if(Signature_Algorithms_Cert* sigs = m_data->extensions().get<Signature_Algorithms_Cert>()) {
      return sigs->supported_schemes();
   } else {
      return signature_schemes();
   }
}

std::vector<Group_Params> Client_Hello::supported_ecc_curves() const {
   if(Supported_Groups* groups = m_data->extensions().get<Supported_Groups>()) {
      return groups->ec_groups();
   }
   return {};
}

std::vector<Group_Params> Client_Hello::supported_dh_groups() const {
   if(Supported_Groups* groups = m_data->extensions().get<Supported_Groups>()) {
      return groups->dh_groups();
   }
   return std::vector<Group_Params>();
}

bool Client_Hello_12::prefers_compressed_ec_points() const {
   if(Supported_Point_Formats* ecc_formats = m_data->extensions().get<Supported_Point_Formats>()) {
      return ecc_formats->prefers_compressed();
   }
   return false;
}

std::string Client_Hello::sni_hostname() const {
   if(Server_Name_Indicator* sni = m_data->extensions().get<Server_Name_Indicator>()) {
      return sni->host_name();
   }
   return "";
}

bool Client_Hello_12::secure_renegotiation() const {
   return m_data->extensions().has<Renegotiation_Extension>();
}

std::vector<uint8_t> Client_Hello_12::renegotiation_info() const {
   if(Renegotiation_Extension* reneg = m_data->extensions().get<Renegotiation_Extension>()) {
      return reneg->renegotiation_info();
   }
   return {};
}

std::vector<Protocol_Version> Client_Hello::supported_versions() const {
   if(Supported_Versions* versions = m_data->extensions().get<Supported_Versions>()) {
      return versions->versions();
   }
   return {};
}

bool Client_Hello_12::supports_session_ticket() const {
   return m_data->extensions().has<Session_Ticket_Extension>();
}

Session_Ticket Client_Hello_12::session_ticket() const {
   if(auto* ticket = m_data->extensions().get<Session_Ticket_Extension>()) {
      return ticket->contents();
   }
   return {};
}

std::optional<Session_Handle> Client_Hello_12::session_handle() const {
   // RFC 5077 3.4
   //    If a ticket is presented by the client, the server MUST NOT attempt
   //    to use the Session ID in the ClientHello for stateful session
   //    resumption.
   if(auto ticket = session_ticket(); !ticket.empty()) {
      return ticket;
   } else if(const auto& id = session_id(); !id.empty()) {
      return id;
   } else {
      return std::nullopt;
   }
}

bool Client_Hello::supports_alpn() const {
   return m_data->extensions().has<Application_Layer_Protocol_Notification>();
}

bool Client_Hello_12::supports_extended_master_secret() const {
   return m_data->extensions().has<Extended_Master_Secret>();
}

bool Client_Hello_12::supports_cert_status_message() const {
   return m_data->extensions().has<Certificate_Status_Request>();
}

bool Client_Hello_12::supports_encrypt_then_mac() const {
   return m_data->extensions().has<Encrypt_then_MAC>();
}

bool Client_Hello::sent_signature_algorithms() const {
   return m_data->extensions().has<Signature_Algorithms>();
}

std::vector<std::string> Client_Hello::next_protocols() const {
   if(auto alpn = m_data->extensions().get<Application_Layer_Protocol_Notification>()) {
      return alpn->protocols();
   }
   return {};
}

std::vector<uint16_t> Client_Hello::srtp_profiles() const {
   if(SRTP_Protection_Profiles* srtp = m_data->extensions().get<SRTP_Protection_Profiles>()) {
      return srtp->profiles();
   }
   return {};
}

const std::vector<uint8_t>& Client_Hello::cookie() const {
   return m_data->hello_cookie();
}

/*
* Create a new Hello Request message
*/
Hello_Request::Hello_Request(Handshake_IO& io) {
   io.send(*this);
}

/*
* Deserialize a Hello Request message
*/
Hello_Request::Hello_Request(const std::vector<uint8_t>& buf) {
   if(!buf.empty()) {
      throw Decoding_Error("Bad Hello_Request, has non-zero size");
   }
}

/*
* Serialize a Hello Request message
*/
std::vector<uint8_t> Hello_Request::serialize() const {
   return std::vector<uint8_t>();
}

void Client_Hello_12::add_tls12_supported_groups_extensions(const Policy& policy) {
   // RFC 7919 3.
   //    A client that offers a group MUST be able and willing to perform a DH
   //    key exchange using that group.
   //
   // We don't support hybrid key exchange in TLS 1.2
   const std::vector<Group_Params> kex_groups = policy.key_exchange_groups();
   std::vector<Group_Params> compatible_kex_groups;
   std::copy_if(kex_groups.begin(), kex_groups.end(), std::back_inserter(compatible_kex_groups), [](const auto group) {
      return !group.is_post_quantum();
   });

   auto supported_groups = std::make_unique<Supported_Groups>(std::move(compatible_kex_groups));

   if(!supported_groups->ec_groups().empty()) {
      m_data->extensions().add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
   }

   m_data->extensions().add(std::move(supported_groups));
}

Client_Hello_12::Client_Hello_12(std::unique_ptr<Client_Hello_Internal> data) : Client_Hello(std::move(data)) {
   const uint16_t TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF;

   if(offered_suite(static_cast<uint16_t>(TLS_EMPTY_RENEGOTIATION_INFO_SCSV))) {
      if(Renegotiation_Extension* reneg = m_data->extensions().get<Renegotiation_Extension>()) {
         if(!reneg->renegotiation_info().empty()) {
            throw TLS_Exception(Alert::HandshakeFailure, "Client sent renegotiation SCSV and non-empty extension");
         }
      } else {
         // add fake extension
         m_data->extensions().add(new Renegotiation_Extension());
      }
   }
}

namespace {

// Avoid sending an IPv4/IPv6 address in SNI as this is prohibitied
bool hostname_acceptable_for_sni(std::string_view hostname) {
   if(hostname.empty()) {
      return false;
   }

   if(string_to_ipv4(hostname).has_value()) {
      return false;
   }

   // IPv6? Anyway ':' is not valid in DNS
   if(hostname.find(':') != std::string_view::npos) {
      return false;
   }

   return true;
}

}  // namespace

// Note: This delegates to the Client_Hello_12 constructor to take advantage
//       of the sanity checks there.
Client_Hello_12::Client_Hello_12(const std::vector<uint8_t>& buf) :
      Client_Hello_12(std::make_unique<Client_Hello_Internal>(buf)) {}

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
                                 const std::vector<std::string>& next_protocols) {
   m_data->m_legacy_version = client_settings.protocol_version();
   m_data->m_random = make_hello_random(rng, cb, policy);
   m_data->m_suites = policy.ciphersuite_list(client_settings.protocol_version());

   if(!policy.acceptable_protocol_version(m_data->legacy_version())) {
      throw Internal_Error("Offering " + m_data->legacy_version().to_string() +
                           " but our own policy does not accept it");
   }

   /*
   * Place all empty extensions in front to avoid a bug in some systems
   * which reject hellos when the last extension in the list is empty.
   */

   // EMS must always be used with TLS 1.2, regardless of the policy used.
   m_data->extensions().add(new Extended_Master_Secret);

   if(policy.negotiate_encrypt_then_mac()) {
      m_data->extensions().add(new Encrypt_then_MAC);
   }

   m_data->extensions().add(new Session_Ticket_Extension());

   m_data->extensions().add(new Renegotiation_Extension(reneg_info));

   m_data->extensions().add(new Supported_Versions(m_data->legacy_version(), policy));

   if(hostname_acceptable_for_sni(client_settings.hostname())) {
      m_data->extensions().add(new Server_Name_Indicator(client_settings.hostname()));
   }

   if(policy.support_cert_status_message()) {
      m_data->extensions().add(new Certificate_Status_Request({}, {}));
   }

   add_tls12_supported_groups_extensions(policy);

   m_data->extensions().add(new Signature_Algorithms(policy.acceptable_signature_schemes()));
   if(auto cert_signing_prefs = policy.acceptable_certificate_signature_schemes()) {
      // RFC 8446 4.2.3
      //    TLS 1.2 implementations SHOULD also process this extension.
      //    Implementations which have the same policy in both cases MAY omit
      //    the "signature_algorithms_cert" extension.
      m_data->extensions().add(new Signature_Algorithms_Cert(std::move(cert_signing_prefs.value())));
   }

   if(reneg_info.empty() && !next_protocols.empty()) {
      m_data->extensions().add(new Application_Layer_Protocol_Notification(next_protocols));
   }

   if(m_data->legacy_version().is_datagram_protocol()) {
      m_data->extensions().add(new SRTP_Protection_Profiles(policy.srtp_profiles()));
   }

   cb.tls_modify_extensions(m_data->extensions(), Connection_Side::Client, type());

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
                                 const Session_with_Handle& session,
                                 const std::vector<std::string>& next_protocols) {
   m_data->m_legacy_version = session.session.version();
   m_data->m_random = make_hello_random(rng, cb, policy);

   // RFC 5077 3.4
   //    When presenting a ticket, the client MAY generate and include a
   //    Session ID in the TLS ClientHello. [...] If a ticket is presented by
   //    the client, the server MUST NOT attempt to use the Session ID in the
   //    ClientHello for stateful session resumption.
   m_data->m_session_id = session.handle.id().value_or(Session_ID(make_hello_random(rng, cb, policy)));
   m_data->m_suites = policy.ciphersuite_list(m_data->legacy_version());

   if(!policy.acceptable_protocol_version(session.session.version())) {
      throw Internal_Error("Offering " + m_data->legacy_version().to_string() +
                           " but our own policy does not accept it");
   }

   if(!value_exists(m_data->ciphersuites(), session.session.ciphersuite_code())) {
      m_data->m_suites.push_back(session.session.ciphersuite_code());
   }

   /*
   * As EMS must always be used with TLS 1.2, add it even if it wasn't used
   * in the original session. If the server understands it and follows the
   * RFC it should reject our resume attempt and upgrade us to a new session
   * with the EMS protection.
   */
   m_data->extensions().add(new Extended_Master_Secret);

   if(session.session.supports_encrypt_then_mac()) {
      m_data->extensions().add(new Encrypt_then_MAC);
   }

   if(session.handle.is_ticket()) {
      m_data->extensions().add(new Session_Ticket_Extension(session.handle.ticket().value()));
   }

   m_data->extensions().add(new Renegotiation_Extension(reneg_info));

   const std::string hostname = session.session.server_info().hostname();

   if(hostname_acceptable_for_sni(hostname)) {
      m_data->extensions().add(new Server_Name_Indicator(hostname));
   }

   if(policy.support_cert_status_message()) {
      m_data->extensions().add(new Certificate_Status_Request({}, {}));
   }

   add_tls12_supported_groups_extensions(policy);

   m_data->extensions().add(new Signature_Algorithms(policy.acceptable_signature_schemes()));
   if(auto cert_signing_prefs = policy.acceptable_certificate_signature_schemes()) {
      // RFC 8446 4.2.3
      //    TLS 1.2 implementations SHOULD also process this extension.
      //    Implementations which have the same policy in both cases MAY omit
      //    the "signature_algorithms_cert" extension.
      m_data->extensions().add(new Signature_Algorithms_Cert(std::move(cert_signing_prefs.value())));
   }

   if(reneg_info.empty() && !next_protocols.empty()) {
      m_data->extensions().add(new Application_Layer_Protocol_Notification(next_protocols));
   }

   cb.tls_modify_extensions(m_data->extensions(), Connection_Side::Client, type());

   hash.update(io.send(*this));
}

#if defined(BOTAN_HAS_TLS_13)

Client_Hello_13::Client_Hello_13(std::unique_ptr<Client_Hello_Internal> data) : Client_Hello(std::move(data)) {
   const auto& exts = m_data->extensions();

   // RFC 8446 4.1.2
   //    TLS 1.3 ClientHellos are identified as having a legacy_version of
   //    0x0303 and a "supported_versions" extension present with 0x0304 as the
   //    highest version indicated therein.
   //
   // Note that we already checked for "supported_versions" before entering this
   // c'tor in `Client_Hello_13::parse()`. This is just to be doubly sure.
   BOTAN_ASSERT_NOMSG(exts.has<Supported_Versions>());

   // RFC 8446 4.2.1
   //    Servers MAY abort the handshake upon receiving a ClientHello with
   //    legacy_version 0x0304 or later.
   if(m_data->legacy_version().is_tls_13_or_later()) {
      throw TLS_Exception(Alert::DecodeError, "TLS 1.3 Client Hello has invalid legacy_version");
   }

   // RFC 8446 4.1.2
   //    For every TLS 1.3 ClientHello, [the compression method] MUST contain
   //    exactly one byte, set to zero, [...].  If a TLS 1.3 ClientHello is
   //    received with any other value in this field, the server MUST abort the
   //    handshake with an "illegal_parameter" alert.
   if(m_data->comp_methods().size() != 1 || m_data->comp_methods().front() != 0) {
      throw TLS_Exception(Alert::IllegalParameter, "Client did not offer NULL compression");
   }

   // RFC 8446 4.2.9
   //    A client MUST provide a "psk_key_exchange_modes" extension if it
   //    offers a "pre_shared_key" extension. If clients offer "pre_shared_key"
   //    without a "psk_key_exchange_modes" extension, servers MUST abort
   //    the handshake.
   if(exts.has<PSK>()) {
      if(!exts.has<PSK_Key_Exchange_Modes>()) {
         throw TLS_Exception(Alert::MissingExtension,
                             "Client Hello offered a PSK without a psk_key_exchange_modes extension");
      }

      // RFC 8446 4.2.11
      //     The "pre_shared_key" extension MUST be the last extension in the
      //     ClientHello [...]. Servers MUST check that it is the last extension
      //     and otherwise fail the handshake with an "illegal_parameter" alert.
      if(exts.all().back()->type() != Extension_Code::PresharedKey) {
         throw TLS_Exception(Alert::IllegalParameter, "PSK extension was not at the very end of the Client Hello");
      }
   }

   // RFC 8446 9.2
   //    [A TLS 1.3 ClientHello] message MUST meet the following requirements:
   //
   //     -  If not containing a "pre_shared_key" extension, it MUST contain
   //        both a "signature_algorithms" extension and a "supported_groups"
   //        extension.
   //
   //     -  If containing a "supported_groups" extension, it MUST also contain
   //        a "key_share" extension, and vice versa.  An empty
   //        KeyShare.client_shares vector is permitted.
   //
   //    Servers receiving a ClientHello which does not conform to these
   //    requirements MUST abort the handshake with a "missing_extension"
   //    alert.
   if(!exts.has<PSK>()) {
      if(!exts.has<Supported_Groups>() || !exts.has<Signature_Algorithms>()) {
         throw TLS_Exception(
            Alert::MissingExtension,
            "Non-PSK Client Hello did not contain supported_groups and signature_algorithms extensions");
      }
   }
   if(exts.has<Supported_Groups>() != exts.has<Key_Share>()) {
      throw TLS_Exception(Alert::MissingExtension,
                          "Client Hello must either contain both key_share and supported_groups extensions or neither");
   }

   if(exts.has<Key_Share>()) {
      const auto supported_ext = exts.get<Supported_Groups>();
      BOTAN_ASSERT_NONNULL(supported_ext);
      const auto supports = supported_ext->groups();
      const auto offers = exts.get<Key_Share>()->offered_groups();

      // RFC 8446 4.2.8
      //    Each KeyShareEntry value MUST correspond to a group offered in the
      //    "supported_groups" extension and MUST appear in the same order.
      //    [...]
      //    Clients MUST NOT offer any KeyShareEntry values for groups not
      //    listed in the client's "supported_groups" extension.
      //
      // Note: We can assume that both `offers` and `supports` are unique lists
      //       as this is ensured in the parsing code of the extensions.
      auto found_in_supported_groups = [&supports, support_offset = -1](auto group) mutable {
         const auto i = std::find(supports.begin(), supports.end(), group);
         if(i == supports.end()) {
            return false;
         }

         const auto found_at = std::distance(supports.begin(), i);
         if(found_at <= support_offset) {
            return false;  // The order that groups appear in "key_share" and
                           // "supported_groups" must be the same
         }

         support_offset = static_cast<decltype(support_offset)>(found_at);
         return true;
      };

      for(const auto offered : offers) {
         // RFC 8446 4.2.8
         //    Servers MAY check for violations of these rules and abort the
         //    handshake with an "illegal_parameter" alert if one is violated.
         if(!found_in_supported_groups(offered)) {
            throw TLS_Exception(Alert::IllegalParameter,
                                "Offered key exchange groups do not align with claimed supported groups");
         }
      }
   }

   // TODO: Reject oid_filters extension if found (which is the only known extension that
   //       must not occur in the TLS 1.3 client hello.
   // RFC 8446 4.2.5
   //    [The oid_filters extension] MUST only be sent in the CertificateRequest message.
}

/*
* Create a new Client Hello message
*/
Client_Hello_13::Client_Hello_13(const Policy& policy,
                                 Callbacks& cb,
                                 RandomNumberGenerator& rng,
                                 std::string_view hostname,
                                 const std::vector<std::string>& next_protocols,
                                 std::optional<Session_with_Handle>& session,
                                 std::vector<ExternalPSK> psks) {
   // RFC 8446 4.1.2
   //    In TLS 1.3, the client indicates its version preferences in the
   //    "supported_versions" extension (Section 4.2.1) and the
   //    legacy_version field MUST be set to 0x0303, which is the version
   //    number for TLS 1.2.
   m_data->m_legacy_version = Protocol_Version::TLS_V12;
   m_data->m_random = make_hello_random(rng, cb, policy);
   m_data->m_suites = policy.ciphersuite_list(Protocol_Version::TLS_V13);

   if(policy.allow_tls12())  // Note: DTLS 1.3 is NYI, hence dtls_12 is not checked
   {
      const auto legacy_suites = policy.ciphersuite_list(Protocol_Version::TLS_V12);
      m_data->m_suites.insert(m_data->m_suites.end(), legacy_suites.cbegin(), legacy_suites.cend());
   }

   if(policy.tls_13_middlebox_compatibility_mode()) {
      // RFC 8446 4.1.2
      //    In compatibility mode (see Appendix D.4), this field MUST be non-empty,
      //    so a client not offering a pre-TLS 1.3 session MUST generate a new
      //    32-byte value.
      //
      // Note: we won't ever offer a TLS 1.2 session. In such a case we would
      //       have instantiated a TLS 1.2 client in the first place.
      m_data->m_session_id = Session_ID(make_hello_random(rng, cb, policy));
   }

   if(hostname_acceptable_for_sni(hostname)) {
      m_data->extensions().add(new Server_Name_Indicator(hostname));
   }

   m_data->extensions().add(new Supported_Groups(policy.key_exchange_groups()));

   m_data->extensions().add(new Key_Share(policy, cb, rng));

   m_data->extensions().add(new Supported_Versions(Protocol_Version::TLS_V13, policy));

   m_data->extensions().add(new Signature_Algorithms(policy.acceptable_signature_schemes()));
   if(auto cert_signing_prefs = policy.acceptable_certificate_signature_schemes()) {
      // RFC 8446 4.2.3
      //    Implementations which have the same policy in both cases MAY omit
      //    the "signature_algorithms_cert" extension.
      m_data->extensions().add(new Signature_Algorithms_Cert(std::move(cert_signing_prefs.value())));
   }

   // TODO: Support for PSK-only mode without a key exchange.
   //       This should be configurable in TLS::Policy and should allow no PSK
   //       support at all (e.g. to disable support for session resumption).
   m_data->extensions().add(new PSK_Key_Exchange_Modes({PSK_Key_Exchange_Mode::PSK_DHE_KE}));

   if(policy.support_cert_status_message()) {
      m_data->extensions().add(new Certificate_Status_Request({}, {}));
   }

   // We currently support "record_size_limit" for TLS 1.3 exclusively. Hence,
   // when TLS 1.2 is advertised as a supported protocol, we must not offer this
   // extension.
   if(policy.record_size_limit().has_value() && !policy.allow_tls12()) {
      m_data->extensions().add(new Record_Size_Limit(policy.record_size_limit().value()));
   }

   if(!next_protocols.empty()) {
      m_data->extensions().add(new Application_Layer_Protocol_Notification(next_protocols));
   }

   // RFC 7250 4.1
   //    In order to indicate the support of raw public keys, clients include
   //    the client_certificate_type and/or the server_certificate_type
   //    extensions in an extended client hello message.
   m_data->extensions().add(new Client_Certificate_Type(policy.accepted_client_certificate_types()));
   m_data->extensions().add(new Server_Certificate_Type(policy.accepted_server_certificate_types()));

   if(policy.allow_tls12()) {
      m_data->extensions().add(new Renegotiation_Extension());
      m_data->extensions().add(new Session_Ticket_Extension());

      // EMS must always be used with TLS 1.2, regardless of the policy
      m_data->extensions().add(new Extended_Master_Secret);

      if(policy.negotiate_encrypt_then_mac()) {
         m_data->extensions().add(new Encrypt_then_MAC);
      }

      if(m_data->extensions().has<Supported_Groups>() &&
         !m_data->extensions().get<Supported_Groups>()->ec_groups().empty()) {
         m_data->extensions().add(new Supported_Point_Formats(policy.use_ecc_point_compression()));
      }
   }

   if(session.has_value() || !psks.empty()) {
      m_data->extensions().add(new PSK(session, std::move(psks), cb));
   }

   cb.tls_modify_extensions(m_data->extensions(), Connection_Side::Client, type());

   if(m_data->extensions().has<PSK>()) {
      // RFC 8446 4.2.11
      //    The "pre_shared_key" extension MUST be the last extension in the
      //    ClientHello (this facilitates implementation [...]).
      if(m_data->extensions().all().back()->type() != Extension_Code::PresharedKey) {
         throw TLS_Exception(Alert::InternalError,
                             "Application modified extensions of Client Hello, PSK is not last anymore");
      }
      calculate_psk_binders({});
   }
}

std::variant<Client_Hello_13, Client_Hello_12> Client_Hello_13::parse(const std::vector<uint8_t>& buf) {
   auto data = std::make_unique<Client_Hello_Internal>(buf);
   const auto version = data->version();

   if(version.is_pre_tls_13()) {
      return Client_Hello_12(std::move(data));
   } else {
      return Client_Hello_13(std::move(data));
   }
}

void Client_Hello_13::retry(const Hello_Retry_Request& hrr,
                            const Transcript_Hash_State& transcript_hash_state,
                            Callbacks& cb,
                            RandomNumberGenerator& rng) {
   BOTAN_STATE_CHECK(m_data->extensions().has<Supported_Groups>());
   BOTAN_STATE_CHECK(m_data->extensions().has<Key_Share>());

   auto hrr_ks = hrr.extensions().get<Key_Share>();
   const auto& supported_groups = m_data->extensions().get<Supported_Groups>()->groups();

   if(hrr.extensions().has<Key_Share>()) {
      m_data->extensions().get<Key_Share>()->retry_offer(*hrr_ks, supported_groups, cb, rng);
   }

   // RFC 8446 4.2.2
   //    When sending the new ClientHello, the client MUST copy
   //    the contents of the extension received in the HelloRetryRequest into
   //    a "cookie" extension in the new ClientHello.
   //
   // RFC 8446 4.2.2
   //    Clients MUST NOT use cookies in their initial ClientHello in subsequent
   //    connections.
   if(hrr.extensions().has<Cookie>()) {
      BOTAN_STATE_CHECK(!m_data->extensions().has<Cookie>());
      m_data->extensions().add(new Cookie(hrr.extensions().get<Cookie>()->get_cookie()));
   }

   // Note: the consumer of the TLS implementation won't be able to distinguish
   //       invocations to this callback due to the first Client_Hello or the
   //       retried Client_Hello after receiving a Hello_Retry_Request. We assume
   //       that the user keeps and detects this state themselves.
   cb.tls_modify_extensions(m_data->extensions(), Connection_Side::Client, type());

   auto psk = m_data->extensions().get<PSK>();
   if(psk) {
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

void Client_Hello_13::validate_updates(const Client_Hello_13& new_ch) {
   // RFC 8446 4.1.2
   //    The client will also send a ClientHello when the server has responded
   //    to its ClientHello with a HelloRetryRequest. In that case, the client
   //    MUST send the same ClientHello without modification, except as follows:

   if(m_data->session_id() != new_ch.m_data->session_id() || m_data->random() != new_ch.m_data->random() ||
      m_data->ciphersuites() != new_ch.m_data->ciphersuites() ||
      m_data->comp_methods() != new_ch.m_data->comp_methods()) {
      throw TLS_Exception(Alert::IllegalParameter, "Client Hello core values changed after Hello Retry Request");
   }

   const auto oldexts = extension_types();
   const auto newexts = new_ch.extension_types();

   // Check that extension omissions are justified
   for(const auto oldext : oldexts) {
      if(!newexts.contains(oldext)) {
         const auto ext = extensions().get(oldext);

         // We don't make any assumptions about unimplemented extensions.
         if(!ext->is_implemented()) {
            continue;
         }

         // RFC 8446 4.1.2
         //    Removing the "early_data" extension (Section 4.2.10) if one was
         //    present.  Early data is not permitted after a HelloRetryRequest.
         if(oldext == EarlyDataIndication::static_type()) {
            continue;
         }

         // RFC 8446 4.1.2
         //    Optionally adding, removing, or changing the length of the
         //    "padding" extension.
         //
         // TODO: implement the Padding extension
         // if(oldext == Padding::static_type())
         //    continue;

         throw TLS_Exception(Alert::IllegalParameter, "Extension removed in updated Client Hello");
      }
   }

   // Check that extension additions are justified
   for(const auto newext : newexts) {
      if(!oldexts.contains(newext)) {
         const auto ext = new_ch.extensions().get(newext);

         // We don't make any assumptions about unimplemented extensions.
         if(!ext->is_implemented()) {
            continue;
         }

         // RFC 8446 4.1.2
         //    Including a "cookie" extension if one was provided in the
         //    HelloRetryRequest.
         if(newext == Cookie::static_type()) {
            continue;
         }

         // RFC 8446 4.1.2
         //    Optionally adding, removing, or changing the length of the
         //    "padding" extension.
         //
         // TODO: implement the Padding extension
         // if(newext == Padding::static_type())
         //    continue;

         throw TLS_Exception(Alert::UnsupportedExtension, "Added an extension in updated Client Hello");
      }
   }

   // RFC 8446 4.1.2
   //    Removing the "early_data" extension (Section 4.2.10) if one was
   //    present.  Early data is not permitted after a HelloRetryRequest.
   if(new_ch.extensions().has<EarlyDataIndication>()) {
      throw TLS_Exception(Alert::IllegalParameter, "Updated Client Hello indicates early data");
   }

   // TODO: Contents of extensions are not checked for update compatibility, see:
   //
   // RFC 8446 4.1.2
   //    If a "key_share" extension was supplied in the HelloRetryRequest,
   //    replacing the list of shares with a list containing a single
   //    KeyShareEntry from the indicated group.
   //
   //    Updating the "pre_shared_key" extension if present by recomputing
   //    the "obfuscated_ticket_age" and binder values and (optionally)
   //    removing any PSKs which are incompatible with the server's
   //    indicated cipher suite.
   //
   //    Optionally adding, removing, or changing the length of the
   //    "padding" extension.
}

void Client_Hello_13::calculate_psk_binders(Transcript_Hash_State ths) {
   auto psk = m_data->extensions().get<PSK>();
   if(!psk || psk->empty()) {
      return;
   }

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

std::optional<Protocol_Version> Client_Hello_13::highest_supported_version(const Policy& policy) const {
   // RFC 8446 4.2.1
   //    The "supported_versions" extension is used by the client to indicate
   //    which versions of TLS it supports and by the server to indicate which
   //    version it is using. The extension contains a list of supported
   //    versions in preference order, with the most preferred version first.
   const auto supvers = m_data->extensions().get<Supported_Versions>();
   BOTAN_ASSERT_NONNULL(supvers);

   std::optional<Protocol_Version> result;

   for(const auto& v : supvers->versions()) {
      // RFC 8446 4.2.1
      //    Servers MUST only select a version of TLS present in that extension
      //    and MUST ignore any unknown versions that are present in that
      //    extension.
      if(!v.known_version() || !policy.acceptable_protocol_version(v)) {
         continue;
      }

      result = (result.has_value()) ? std::optional(std::max(result.value(), v)) : std::optional(v);
   }

   return result;
}

#endif  // BOTAN_HAS_TLS_13

}  // namespace Botan::TLS
