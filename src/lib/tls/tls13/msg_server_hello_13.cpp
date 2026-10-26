/*
* TLS Server Hello and Server Hello Done
* (C) 2004-2011,2015,2016,2019 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*     2026 René Meusel - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages_13.h>

#include <botan/credentials_manager.h>
#include <botan/tls_alert.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_extensions_13.h>
#include <botan/tls_policy.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_messages_internal.h>

namespace Botan::TLS {

const Server_Hello_13::Server_Hello_Tag Server_Hello_13::as_server_hello;
const Server_Hello_13::Hello_Retry_Request_Tag Server_Hello_13::as_hello_retry_request;
const Server_Hello_13::Hello_Retry_Request_Creation_Tag Server_Hello_13::as_new_hello_retry_request;

std::variant<Hello_Retry_Request, Server_Hello_13> Server_Hello_13::create(const Client_Hello_13& ch,
                                                                           bool hello_retry_request_allowed,
                                                                           Session_Manager& session_mgr,
                                                                           Credentials_Manager& credentials_mgr,
                                                                           RandomNumberGenerator& rng,
                                                                           const Policy& policy,
                                                                           Callbacks& cb,
                                                                           TLS_Flavor flavor) {
   const auto& exts = ch.extensions();

   // RFC 8446 4.2.9
   //    [With PSK with (EC)DHE key establishment], the client and server MUST
   //    supply "key_share" values [...].
   //
   // Note: We currently do not support PSK without (EC)DHE, hence, we can
   //       assume that those extensions are available.
   BOTAN_ASSERT_NOMSG(exts.has<Supported_Groups>() && exts.has<Key_Share>());
   const auto& supported_by_client = exts.get<Supported_Groups>()->groups();
   const auto& offered_by_client = exts.get<Key_Share>()->offered_groups();
   const auto selected_group = policy.choose_key_exchange_group(supported_by_client, offered_by_client);

   // RFC 8446 4.1.1
   //    If there is no overlap between the received "supported_groups" and the
   //    groups supported by the server, then the server MUST abort the
   //    handshake with a "handshake_failure" or an "insufficient_security" alert.
   if(selected_group == Named_Group::NONE) {
      throw TLS_Exception(Alert::HandshakeFailure, "Client did not offer any acceptable group");
   }

   // RFC 8446 4.2.8:
   //    Servers MUST NOT send a KeyShareEntry for any group not indicated in the
   //    client's "supported_groups" extension [...]
   if(!value_exists(supported_by_client, selected_group)) {
      throw TLS_Exception(Alert::InternalError, "Application selected a group that is not supported by the client");
   }

   // RFC 8446 4.1.4
   //    The server will send this message in response to a ClientHello
   //    message if it is able to find an acceptable set of parameters but the
   //    ClientHello does not contain sufficient information to proceed with
   //    the handshake.
   //
   // Hence, we need a HelloRetryRequest if the client did not offer an
   // acceptable key share.
   const bool hrr_for_key_exchange = !value_exists(offered_by_client, selected_group);

   // RFC 9147 5.1
   //    Datagram security protocols are extremely susceptible to a variety of
   //    DoS attacks [...]. In order to counter [two] of these attacks, DTLS
   //    borrows the stateless cookie technique used by Photuris and IKE. [...]
   //    The HelloRetryRequest message contains a stateless cookie [...]. This
   //    mechanism forces the attacker/client to be able to receive the cookie,
   //    which makes DoS attacks with spoofed IP addresses difficult.
   //
   // Hence, we enforce HelloRetryRequest if we're running DTLS and DoS
   // protection is required by the policy.
   const bool hrr_for_cookie = flavor == TLS_Flavor::DTLS &&  //
                               policy.dtls_server_require_cookie_exchange();

   if(hello_retry_request_allowed && (hrr_for_cookie || hrr_for_key_exchange)) {
      return Hello_Retry_Request(ch, selected_group, policy, credentials_mgr, cb, flavor);
   } else {
      return Server_Hello_13(ch, selected_group, session_mgr, credentials_mgr, rng, cb, policy, flavor);
   }
}

std::variant<Hello_Retry_Request, Server_Hello_13, Server_Hello_12_Shim> Server_Hello_13::parse(
   std::span<const uint8_t> buf, TLS_Flavor flavor) {
   auto data = std::make_unique<Server_Hello_Internal>(buf);
   const auto version = data->version();

   // server hello that appears to be pre-TLS 1.3, takes precedence over...
   if(version.is_pre_tls_13()) {
      return Server_Hello_12_Shim(std::move(data));
   }

   // ... the TLS 1.3 "special case" aka. Hello_Retry_Request
   if(version.is_tls_13_or_later()) {
      if(data->is_hello_retry_request()) {
         return Hello_Retry_Request(std::move(data), flavor);
      }

      return Server_Hello_13(std::move(data), flavor);
   }

   throw TLS_Exception(Alert::ProtocolVersion, "unexpected server hello version: " + version.to_string());
}

/**
 * Validation that applies to both Server Hello and Hello Retry Request
 */
void Server_Hello_13::basic_validation(TLS_Flavor flavor) const {
   BOTAN_ASSERT_NOMSG(m_data->version().is_tls_13_or_later());

   // Note: checks that cannot be performed without contextual information
   //       are done in the specific TLS client implementation.
   // Note: The Supported_Version extension makes sure internally that
   //       exactly one entry is provided.

   // Note: Hello Retry Request basic validation is equivalent with the
   //       basic validations required for Server Hello
   //
   // RFC 8446 4.1.4
   //    Upon receipt of a HelloRetryRequest, the client MUST check the
   //    legacy_version, [...], and legacy_compression_method as specified in
   //    Section 4.1.3 and then process the extensions, starting with determining
   //    the version using "supported_versions".

   // RFC 8446 4.1.3
   //    In TLS 1.3, [...] the legacy_version field MUST be set to 0x0303

   // RFC 9147 5.4
   //    [...] the legacy_version field is set to 0xfefd, indicating DTLS 1.2.
   const auto accepted_legacy_version =
      (flavor == TLS_Flavor::DTLS) ? Protocol_Version::DTLS_V12 : Protocol_Version::TLS_V12;
   if(legacy_version() != accepted_legacy_version) {
      throw TLS_Exception(Alert::ProtocolVersion,
                          "legacy_version '" + legacy_version().to_string() + "' is not allowed");
   }

   // RFC 8446 4.1.3
   //    legacy_compression_method:  A single byte which MUST have the value 0.
   if(compression_method() != 0x00) {
      throw TLS_Exception(Alert::DecodeError, "compression is not supported in TLS 1.3");
   }

   // RFC 8446 4.1.3
   //    All TLS 1.3 ServerHello messages MUST contain the "supported_versions" extension.
   if(!extensions().has<Supported_Versions>()) {
      throw TLS_Exception(Alert::MissingExtension, "server hello did not contain 'supported version' extension");
   }

   // RFC 8446 4.2.1
   //    A server which negotiates TLS 1.3 MUST respond by sending
   //    a "supported_versions" extension containing the selected version
   //    value (0x0304).
   //
   // RFC 9147 4.2.1
   //    The "supported_versions" [...] value 0xfefc is used to indicate DTLS 1.3.
   if((flavor == TLS_Flavor::TLS && selected_version() != Protocol_Version::TLS_V13) ||
      (flavor == TLS_Flavor::DTLS && selected_version() != Protocol_Version::DTLS_V13)) {
      throw TLS_Exception(Alert::IllegalParameter, "TLS 1.3 Server Hello selected a different version");
   }
}

Server_Hello_13::Server_Hello_13(std::unique_ptr<Server_Hello_Internal> data,
                                 TLS_Flavor flavor,
                                 Server_Hello_13::Server_Hello_Tag /*tag*/) :
      Server_Hello(std::move(data)) {
   BOTAN_ASSERT_NOMSG(!m_data->is_hello_retry_request());
   basic_validation(flavor);

   const auto& exts = extensions();

   // RFC 8446 4.1.3
   //    The ServerHello MUST only include extensions which are required to
   //    establish the cryptographic context and negotiate the protocol version.
   //    [...]
   //    Other extensions (see Section 4.2) are sent separately in the
   //    EncryptedExtensions message.
   //
   // Note that further validation dependent on the client hello is done in the
   // TLS client implementation.
   const std::set<Extension_Code> allowed = {
      Extension_Code::KeyShare,
      Extension_Code::SupportedVersions,
      Extension_Code::PresharedKey,
   };

   // As the ServerHello shall only contain essential extensions, we don't give
   // any slack for extensions not implemented by Botan here.
   if(exts.contains_other_than(allowed)) {
      throw TLS_Exception(Alert::UnsupportedExtension, "Server Hello contained an extension that is not allowed");
   }

   // RFC 8446 4.1.3
   //    Current ServerHello messages additionally contain
   //    either the "pre_shared_key" extension or the "key_share"
   //    extension, or both [...].
   if(!exts.has<Key_Share>() && !exts.has<PSK>()) {
      throw TLS_Exception(Alert::MissingExtension, "server hello must contain key exchange information");
   }
}

Server_Hello_13::Server_Hello_13(std::unique_ptr<Server_Hello_Internal> data,
                                 TLS_Flavor flavor,
                                 Server_Hello_13::Hello_Retry_Request_Tag /*tag*/) :
      Server_Hello(std::move(data)) {
   BOTAN_ASSERT_NOMSG(m_data->is_hello_retry_request());
   basic_validation(flavor);

   const auto& exts = extensions();

   // RFC 8446 4.1.4
   //     The HelloRetryRequest extensions defined in this specification are:
   //     -  supported_versions (see Section 4.2.1)
   //     -  cookie (see Section 4.2.2)
   //     -  key_share (see Section 4.2.8)
   const std::set<Extension_Code> allowed = {
      Extension_Code::Cookie,
      Extension_Code::SupportedVersions,
      Extension_Code::KeyShare,
   };

   // As the Hello Retry Request shall only contain essential extensions, we
   // don't give any slack for extensions not implemented by Botan here.
   if(exts.contains_other_than(allowed)) {
      throw TLS_Exception(Alert::UnsupportedExtension,
                          "Hello Retry Request contained an extension that is not allowed");
   }

   // RFC 8446 4.1.4
   //    Clients MUST abort the handshake with an "illegal_parameter" alert if
   //    the HelloRetryRequest would not result in any change in the ClientHello.
   if(!exts.has<Key_Share>() && !exts.has<Cookie>()) {
      throw TLS_Exception(Alert::IllegalParameter, "Hello Retry Request does not request any changes to Client Hello");
   }
}

Server_Hello_13::Server_Hello_13(std::unique_ptr<Server_Hello_Internal> data,
                                 Hello_Retry_Request_Creation_Tag /*tag*/) :
      Server_Hello(std::move(data)) {}

namespace {

uint16_t choose_ciphersuite(const Client_Hello_13& ch, const Policy& policy, TLS_Flavor flavor) {
   auto pref_list = ch.ciphersuites();
   const auto version = flavor == TLS_Flavor::DTLS ? Protocol_Version::DTLS_V13 : Protocol_Version::TLS_V13;
   auto other_list = policy.ciphersuite_list(version);

   if(policy.server_uses_own_ciphersuite_preferences()) {
      std::swap(pref_list, other_list);
   }

   for(const auto suite_id : pref_list) {
      // TODO: take potentially available PSKs into account to select a
      //       compatible ciphersuite.
      //
      // Assuming the client sent one or more PSKs, we would first need to find
      // the hash functions they are associated to. For session tickets, that
      // would mean decrypting the ticket and comparing the cipher suite used in
      // those tickets. For (currently not yet supported) pre-assigned PSKs, the
      // hash function needs to be specified along with them.
      //
      // Then we could refine the ciphersuite selection using the required hash
      // function for the PSK(s) we are wishing to use down the road.
      //
      // For now, we just negotiate the cipher suite blindly and hope for the
      // best. As long as PSKs are used for session resumption only, this has a
      // high chance of success. Previous handshakes with this client have very
      // likely selected the same ciphersuite anyway.
      //
      // See also RFC 8446 4.2.11
      //    When session resumption is the primary use case of PSKs, the most
      //    straightforward way to implement the PSK/cipher suite matching
      //    requirements is to negotiate the cipher suite first [...].
      if(value_exists(other_list, suite_id)) {
         return suite_id;
      }
   }

   // RFC 8446 4.1.1
   //     If the server is unable to negotiate a supported set of parameters
   //     [...], it MUST abort the handshake with either a "handshake_failure"
   //     or "insufficient_security" fatal alert [...].
   throw TLS_Exception(Alert::HandshakeFailure, "Can't agree on a ciphersuite with client");
}
}  // namespace

Server_Hello_13::Server_Hello_13(const Client_Hello_13& ch,
                                 std::optional<Named_Group> key_exchange_group,
                                 Session_Manager& session_mgr,
                                 Credentials_Manager& credentials_mgr,
                                 RandomNumberGenerator& rng,
                                 Callbacks& cb,
                                 const Policy& policy,
                                 TLS_Flavor flavor) :
      Server_Hello(std::make_unique<Server_Hello_Internal>(
         flavor == TLS_Flavor::DTLS ? Protocol_Version::DTLS_V12 /* legacy version */
                                    : Protocol_Version::TLS_V12,
         // RFC 9846 4.2.3
         //    legacy_session_id_echo: The contents of the client's
         //                            legacy_session_id field.
         //
         // RFC 9147 5.
         //    DTLS servers MUST NOT echo the "legacy_session_id" value from the
         //    client [...].
         flavor == TLS_Flavor::TLS ? ch.session_id() : Session_ID{},
         make_server_hello_random(rng,
                                  flavor == TLS_Flavor::DTLS ? Protocol_Version::DTLS_V13 : Protocol_Version::TLS_V13,
                                  cb,
                                  policy,
                                  flavor),
         choose_ciphersuite(ch, policy, flavor),
         uint8_t(0) /* compression method */
         )) {
   // RFC 8446 4.2.1
   //    A server which negotiates TLS 1.3 MUST respond by sending a
   //    "supported_versions" extension containing the selected version
   //    value (0x0304). It MUST set the ServerHello.legacy_version field to
   //     0x0303 (TLS 1.2).
   //
   // Note that the legacy version (TLS 1.2) is set in this constructor's
   // initializer list, accordingly.
   const auto version = flavor == TLS_Flavor::DTLS ? Protocol_Version::DTLS_V13 : Protocol_Version::TLS_V13;
   m_data->extensions().add(new Supported_Versions(version));  // NOLINT(*-owning-memory)

   if(key_exchange_group.has_value()) {
      BOTAN_ASSERT_NOMSG(ch.extensions().has<Key_Share>());
      m_data->extensions().add(Key_Share::create_as_encapsulation(
         key_exchange_group.value(), *ch.extensions().get<Key_Share>(), policy, cb, rng));
   }

   const auto& ch_exts = ch.extensions();

   if(ch_exts.has<PSK>()) {
      const auto cs = Ciphersuite::by_id(m_data->ciphersuite());
      BOTAN_ASSERT_NOMSG(cs);

      // RFC 8446 4.2.9
      //    A client MUST provide a "psk_key_exchange_modes" extension if it
      //    offers a "pre_shared_key" extension.
      //
      // Note: Client_Hello_13 constructor already performed a graceful check.
      const auto* const psk_modes = ch_exts.get<PSK_Key_Exchange_Modes>();
      BOTAN_ASSERT_NONNULL(psk_modes);

      // TODO: also support PSK_Key_Exchange_Mode::PSK_KE
      //       (PSK-based handshake without an additional ephemeral key exchange)
      if(value_exists(psk_modes->modes(), PSK_Key_Exchange_Mode::PSK_DHE_KE)) {
         if(auto server_psk = ch_exts.get<PSK>()->select_offered_psk(
               ch.sni_hostname(), cs.value(), session_mgr, credentials_mgr, cb, policy)) {
            // RFC 8446 4.2.11
            //    In order to accept PSK key establishment, the server sends a
            //    "pre_shared_key" extension indicating the selected identity.
            m_data->extensions().add(std::move(server_psk));
         }
      }
   }

   cb.tls_modify_extensions(m_data->extensions(), Connection_Side::Server, type());

   if(!m_data->extensions().has<Key_Share>()) {
      throw TLS_Exception(Alert::InternalError,
                          "Application tls_modify_extensions callback removed Key_Share from the ServerHello");
   }
}

Protocol_Version Server_Hello_13::selected_version() const {
   const auto* const versions_ext = m_data->extensions().get<Supported_Versions>();
   BOTAN_ASSERT_NOMSG(versions_ext);
   const auto& versions = versions_ext->versions();
   BOTAN_ASSERT_NOMSG(versions.size() == 1);
   return versions.front();
}

Hello_Retry_Request::Hello_Retry_Request(std::unique_ptr<Server_Hello_Internal> data, TLS_Flavor flavor) :
      Server_Hello_13(std::move(data), flavor, Server_Hello_13::as_hello_retry_request) {}

Hello_Retry_Request::Hello_Retry_Request(const Client_Hello_13& ch,
                                         Named_Group selected_group,
                                         const Policy& policy,
                                         Credentials_Manager& credentials_manager,
                                         Callbacks& cb,
                                         TLS_Flavor flavor) :
      Server_Hello_13(std::make_unique<Server_Hello_Internal>(
                         flavor == TLS_Flavor::DTLS ? Protocol_Version::DTLS_V12 /* legacy_version */
                                                    : Protocol_Version::TLS_V12,
                         // RFC 9147 5.
                         //    DTLS servers MUST NOT echo the "legacy_session_id" value from the
                         //    client [...].
                         flavor == TLS_Flavor::DTLS ? Session_ID{} : ch.session_id(),
                         std::vector<uint8_t>(HELLO_RETRY_REQUEST_MARKER.begin(), HELLO_RETRY_REQUEST_MARKER.end()),
                         choose_ciphersuite(ch, policy, flavor),
                         uint8_t(0) /* compression method */,
                         true /* is Hello Retry Request */
                         ),
                      as_new_hello_retry_request) {
   // RFC 8446 4.1.4
   //     As with the ServerHello, a HelloRetryRequest MUST NOT contain any
   //     extensions that were not first offered by the client in its
   //     ClientHello, with the exception of optionally the "cookie" [...]
   //     extension.
   BOTAN_STATE_CHECK(ch.extensions().has<Supported_Groups>());
   BOTAN_STATE_CHECK(ch.extensions().has<Key_Share>());

   // RFC 8446 4.1.4
   //    The server's extensions MUST contain "supported_versions".
   //
   // RFC 8446 4.2.1
   //    A server which negotiates TLS 1.3 MUST respond by sending a
   //    "supported_versions" extension containing the selected version
   //    value (0x0304). It MUST set the ServerHello.legacy_version field to
   //    0x0303 (TLS 1.2).
   //
   // Note that the legacy version ((D)TLS 1.2) is set in this constructor's
   // initializer list, accordingly.
   // NOLINTBEGIN(*-owning-memory)
   const auto version = flavor == TLS_Flavor::DTLS ? Protocol_Version::DTLS_V13 : Protocol_Version::TLS_V13;
   m_data->extensions().add(new Supported_Versions(version));

   // RFC 9846 4.2.4
   //    The server's [HelloRetryRequest] extensions SHOULD contain the minimal
   //    set of extensions necessary for the client to generate a correct
   //    ClientHello pair.
   //
   // I.e., if the client already offered a key share for our preferred group,
   // we don't need to request a new key share for this particular group.
   if(!value_exists(ch.extensions().get<Key_Share>()->offered_groups(), selected_group)) {
      m_data->extensions().add(new Key_Share(selected_group));
   }

   // RFC 9846 4.2.4
   //    A HelloRetryRequest MUST NOT contain any extensions that were not first
   //    offered by the client in its ClientHello, with the exception of
   //    optionally the "cookie" [...] extension.
   //
   // RFC 9147 5.1
   //    In order to counter [some DoS attacks], DTLS borrows the stateless
   //    cookie technique used by Photuris and IKE. [...] DTLS 1.3 reuses the
   //    HelloRetryRequest message and conveys the cookie to the client via an
   //    extension.
   if(flavor == TLS_Flavor::DTLS && policy.dtls_server_require_cookie_exchange()) {
      m_data->extensions().add(new Cookie(calculate_cookie(
         ch.cookie_input_data(), cb.tls_peer_network_identity(), credentials_manager.dtls_cookie_secret())));
   }

   // NOLINTEND(*-owning-memory)

   cb.tls_modify_extensions(m_data->extensions(), Connection_Side::Server, type());

   // Note: This error condition could also indicate some other internal
   //       issue, e.g., a faulty use of the Hello_Retry_Request constructor.
   if(!m_data->extensions().has<Key_Share>() && !m_data->extensions().has<Cookie>()) {
      throw TLS_Exception(
         Alert::InternalError,
         "Application tls_modify_extensions callback removed Key_Share or Cookie from the HelloRetryRequest");
   }
}

}  // namespace Botan::TLS
