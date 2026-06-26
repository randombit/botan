/*
* TLS Client Hello Messages
* (C) 2004-2011,2015,2016 Jack Lloyd
*     2021 Elektrobit Automotive GmbH
*     2022 René Meusel, Hannes Rantzsch - neXenio GmbH
*     2026 René Meusel - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_messages_13.h>

#include <botan/assert.h>
#include <botan/tls_alert.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_extensions_13.h>
#include <botan/tls_policy.h>
#include <botan/internal/tls_handshake_layer_13.h>
#include <botan/internal/tls_messages_internal.h>
#include <botan/internal/tls_transcript_hash_13.h>
#include <algorithm>

#if defined(BOTAN_HAS_TLS_12)
   #include <botan/tls_extensions_12.h>
#endif

namespace Botan::TLS {

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

   // RFC 8446 D.5
   //    Any endpoint receiving a Hello message with ClientHello.legacy_version [...]
   //    set to 0x0300 MUST abort the handshake with a "protocol_version" alert.
   if(m_data->legacy_version().major_version() == 3 && m_data->legacy_version().minor_version() == 0) {
      throw TLS_Exception(Alert::ProtocolVersion, "TLS 1.3 Client Hello has invalid legacy_version");
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
      if(exts.last_added() != Extension_Code::PresharedKey) {
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
      auto* const supported_ext = exts.get<Supported_Groups>();
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
      //    Servers MAY check for violations of these rules and abort the
      //    handshake with an "illegal_parameter" alert if one is violated.
      //
      // Note: We can assume that both `offers` and `supports` are unique lists
      //       as this is ensured in the parsing code of the extensions.
      //
      // Since offers must appear in the same order as supports, a single
      // forward sweep of `supports` suffices: after finding each offered group
      // we advance past its position so the next offered group is searched for
      // only in the remaining suffix.
      auto supports_it = supports.begin();
      for(const auto offered : offers) {
         supports_it = std::find(supports_it, supports.end(), offered);
         if(supports_it == supports.end()) {
            throw TLS_Exception(Alert::IllegalParameter,
                                "Offered key exchange groups do not align with claimed supported groups");
         }
         ++supports_it;
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
                                 std::vector<std::string> next_protocols,
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

   if(policy.allow_tls12()) {
      // Note: DTLS 1.3 is NYI, hence dtls_12 is not checked
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

   // NOLINTBEGIN(*-owning-memory)
   if(Server_Name_Indicator::hostname_acceptable_for_sni(hostname)) {
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

   /*
   * Right now raw public key support is not implemented for TLS 1.2, so we only offer
   * certificate_types (which is used to request raw public key) if additionally TLS 1.2
   * support is disabled. Otherwise a peer might reply with a 1.2 server hello + a certificate_type
   * extension indicating it wishes to use RPK, which would lead to errors later.
   */
   if(!policy.allow_tls12()) {
      m_data->extensions().add(new Client_Certificate_Type(policy.accepted_client_certificate_types()));
      m_data->extensions().add(new Server_Certificate_Type(policy.accepted_server_certificate_types()));
   }

   if(!next_protocols.empty()) {
      m_data->extensions().add(new Application_Layer_Protocol_Notification(std::move(next_protocols)));
   }

#if defined(BOTAN_HAS_TLS_12)
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
#endif

   if(session.has_value() || !psks.empty()) {
      m_data->extensions().add(new PSK(session, std::move(psks), cb));
   }
   // NOLINTEND(*-owning-memory)

   cb.tls_modify_extensions(m_data->extensions(), Connection_Side::Client, type());

   // The application's tls_modify_extensions callback could have stripped
   // Supported_Groups or Key_Share, which must be there.
   if(!m_data->extensions().has<Supported_Groups>()) {
      throw TLS_Exception(Alert::InternalError,
                          "Application tls_modify_extensions callback removed Supported_Groups from the ClientHello");
   }
   if(!m_data->extensions().has<Key_Share>()) {
      throw TLS_Exception(Alert::InternalError,
                          "Application tls_modify_extensions callback removed Key_Share from the ClientHello");
   }

   if(m_data->extensions().has<PSK>()) {
      // RFC 8446 4.2.11
      //    The "pre_shared_key" extension MUST be the last extension in the
      //    ClientHello (this facilitates implementation [...]).
      if(m_data->extensions().last_added() != Extension_Code::PresharedKey) {
         throw TLS_Exception(Alert::InternalError,
                             "Application modified extensions of Client Hello, PSK is not last anymore");
      }
      calculate_psk_binders({});
   }
}

std::variant<Client_Hello_13, Client_Hello_12_Shim> Client_Hello_13::parse(std::span<const uint8_t> buf) {
   auto data = std::make_unique<Client_Hello_Internal>(buf);
   const auto version = data->version();

   if(version.is_pre_tls_13()) {
      return Client_Hello_12_Shim(std::move(data));
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

   auto* hrr_ks = hrr.extensions().get<Key_Share>();
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
      m_data->extensions().add(new Cookie(hrr.extensions().get<Cookie>()->get_cookie()));  // NOLINT(*-owning-memory)
   }

   // Note: the consumer of the TLS implementation won't be able to distinguish
   //       invocations to this callback due to the first Client_Hello or the
   //       retried Client_Hello after receiving a Hello_Retry_Request. We assume
   //       that the user keeps and detects this state themselves.
   cb.tls_modify_extensions(m_data->extensions(), Connection_Side::Client, type());

   // Same invariants as in the constructor: the callback must not strip
   // Supported_Groups or Key_Share
   if(!m_data->extensions().has<Supported_Groups>()) {
      throw TLS_Exception(
         Alert::InternalError,
         "Application tls_modify_extensions callback removed Supported_Groups from the retried ClientHello");
   }
   if(!m_data->extensions().has<Key_Share>()) {
      throw TLS_Exception(Alert::InternalError,
                          "Application tls_modify_extensions callback removed Key_Share from the retried ClientHello");
   }

   auto* psk = m_data->extensions().get<PSK>();
   if(psk != nullptr) {
      // RFC 8446 4.2.11
      //    The "pre_shared_key" extension MUST be the last extension in the
      //    ClientHello (this facilitates implementation [...]).
      m_data->extensions().reorder(std::array{Extension_Code::PresharedKey});

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

   // Check that extension omissions are justified. RFC 8446 4.1.2 lists the
   // only mutations the client may make between CH1 and CH2; any other
   // extension removal is an illegal parameter regardless of whether the
   // extension is one this implementation recognizes.
   for(const auto oldext : oldexts) {
      if(!newexts.contains(oldext)) {
         // RFC 8446 4.1.2
         //    Removing the "early_data" extension (Section 4.2.10) if one was
         //    present.  Early data is not permitted after a HelloRetryRequest.
         if(oldext == EarlyDataIndication::static_type()) {
            continue;
         }

         // RFC 8446 4.1.2
         //    Optionally adding, removing, or changing the length of the
         //    "padding" extension.
         if(oldext == Extension_Code::Padding) {
            continue;
         }

         throw TLS_Exception(Alert::IllegalParameter, "Extension removed in updated Client Hello");
      }
   }

   // Check that extension additions are justified. Same reasoning: only the
   // RFC-listed mutations are allowed, including for unknown extension codes.
   for(const auto newext : newexts) {
      if(!oldexts.contains(newext)) {
         // RFC 8446 4.1.2
         //    Including a "cookie" extension if one was provided in the
         //    HelloRetryRequest.
         if(newext == Cookie::static_type()) {
            continue;
         }

         // RFC 8446 4.1.2
         //    Optionally adding, removing, or changing the length of the
         //    "padding" extension.
         if(newext == Extension_Code::Padding) {
            continue;
         }

         throw TLS_Exception(Alert::UnsupportedExtension, "Added an extension in updated Client Hello");
      }
   }

   // RFC 8446 4.1.2
   //    Removing the "early_data" extension (Section 4.2.10) if one was
   //    present.  Early data is not permitted after a HelloRetryRequest.
   if(new_ch.extensions().has<EarlyDataIndication>()) {
      throw TLS_Exception(Alert::IllegalParameter, "Updated Client Hello indicates early data");
   }

   // RFC 8446 4.1.2
   //    The client MUST send the same ClientHello without modification,
   //    except as follows: [key_share, pre_shared_key, early_data, cookie, padding]
   //
   // Verify that extensions whose content must not change between the
   // initial and retried Client Hello have identical wire encodings.
   const std::set<Extension_Code> extensions_allowed_to_change = {
      Extension_Code::KeyShare,
      Extension_Code::PresharedKey,
      Extension_Code::EarlyData,
      Extension_Code::Cookie,
      Extension_Code::Padding,
   };

   for(const auto ext_type : oldexts) {
      if(extensions_allowed_to_change.contains(ext_type)) {
         continue;
      }

      const auto old_bytes = extensions().extension_raw_bytes(ext_type);
      const auto new_bytes = new_ch.extensions().extension_raw_bytes(ext_type);

      // Both Client Hellos validated here are received from the peer and went
      // through Extensions::deserialize, which records raw bytes for every
      // parsed extension. A missing raw_bytes on either side would mean an
      // extension was added by us programmatically - which shouldn't happen
      BOTAN_ASSERT_NOMSG(old_bytes.has_value() && new_bytes.has_value());
      if(old_bytes.value() != new_bytes.value()) {
         throw TLS_Exception(Alert::IllegalParameter, "Extension content changed in updated Client Hello");
      }
   }
}

void Client_Hello_13::calculate_psk_binders(Transcript_Hash_State transcript_hash) {
   auto* psk = m_data->extensions().get<PSK>();
   if(psk == nullptr || psk->empty()) {
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
   Handshake_Layer::prepare_message(*this, transcript_hash);
   psk->calculate_binders(transcript_hash);
}

std::optional<Protocol_Version> Client_Hello_13::highest_supported_version(const Policy& policy) const {
   // RFC 8446 4.2.1
   //    The "supported_versions" extension is used by the client to indicate
   //    which versions of TLS it supports and by the server to indicate which
   //    version it is using. The extension contains a list of supported
   //    versions in preference order, with the most preferred version first.
   auto* const supvers = m_data->extensions().get<Supported_Versions>();
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

}  // namespace Botan::TLS
