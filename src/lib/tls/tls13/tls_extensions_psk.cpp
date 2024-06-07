/*
* TLS Extension Pre Shared Key
* (C) 2022-2023 Jack Lloyd
*     2022 René Meusel - neXenio GmbH
*     2023 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_extensions.h>

#include <botan/credentials_manager.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_session.h>
#include <botan/tls_session_manager.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_cipher_state.h>
#include <botan/internal/tls_reader.h>

#include <algorithm>
#include <utility>

#if defined(BOTAN_HAS_TLS_13)

namespace Botan::TLS {

namespace {

decltype(auto) calculate_age(std::chrono::system_clock::time_point then, std::chrono::system_clock::time_point now) {
   // TODO: Currently this does not provide actual millisecond resolution.
   //       This might become a problem when "early data" is implemented and we
   //       deal with servers that employ a strict "freshness" criteria on the
   //       ticket's age.
   return std::chrono::duration_cast<std::chrono::milliseconds>(now - then);
}

class Client_PSK {
   public:
      Client_PSK(Session_with_Handle& session_to_resume, std::chrono::system_clock::time_point timestamp) :
            Client_PSK(PskIdentity(session_to_resume.handle.opaque_handle(),
                                   calculate_age(session_to_resume.session.start_time(), timestamp),
                                   session_to_resume.session.session_age_add()),
                       session_to_resume.session.ciphersuite().prf_algo(),
                       session_to_resume.session.extract_master_secret(),
                       Cipher_State::PSK_Type::Resumption) {}

      // NOLINTNEXTLINE(*-rvalue-reference-param-not-moved)
      Client_PSK(ExternalPSK&& psk) :
            Client_PSK(PskIdentity(PresharedKeyID(psk.identity())),
                       psk.prf_algo(),
                       psk.extract_master_secret(),
                       Cipher_State::PSK_Type::External) {}

      Client_PSK(PskIdentity id, std::vector<uint8_t> bndr) :
            m_identity(std::move(id)), m_binder(std::move(bndr)), m_is_resumption(false) {}

      Client_PSK(PskIdentity id,
                 std::string_view prf_algo,
                 secure_vector<uint8_t>&& master_secret,
                 Cipher_State::PSK_Type psk_type) :
            m_identity(std::move(id)),

            // RFC 8446 4.2.11.2
            //    Each entry in the binders list is computed as an HMAC over a transcript
            //    hash (see Section 4.4.1) containing a partial ClientHello up to and
            //    including the PreSharedKeyExtension.identities field.  That is, it
            //    includes all of the ClientHello but not the binders list itself.  The
            //    length fields for the message (including the overall length, the length
            //    of the extensions block, and the length of the "pre_shared_key"
            //    extension) are all set as if binders of the correct lengths were
            //    present.
            //
            // Hence, we fill the binders with dummy values of the correct length and use
            // `Client_Hello_13::truncate()` to split them off before calculating the
            // transcript hash that underpins the PSK binders. S.a. `calculate_binders()`
            m_binder(HashFunction::create_or_throw(prf_algo)->output_length()),
            m_is_resumption(psk_type == Cipher_State::PSK_Type::Resumption),
            m_cipher_state(
               Cipher_State::init_with_psk(Connection_Side::Client, psk_type, std::move(master_secret), prf_algo)) {}

      const PskIdentity& identity() const { return m_identity; }

      const std::vector<uint8_t>& binder() const { return m_binder; }

      bool is_resumption() const { return m_is_resumption; }

      void set_binder(std::vector<uint8_t> binder) { m_binder = std::move(binder); }

      const Cipher_State& cipher_state() const {
         BOTAN_ASSERT_NONNULL(m_cipher_state);
         return *m_cipher_state;
      }

      std::unique_ptr<Cipher_State> take_cipher_state() { return std::exchange(m_cipher_state, nullptr); }

   private:
      PskIdentity m_identity;
      std::vector<uint8_t> m_binder;
      bool m_is_resumption;

      // Clients set up associated cipher states for PSKs
      // Servers leave this as nullptr
      std::unique_ptr<Cipher_State> m_cipher_state;
};

class Server_PSK {
   public:
      Server_PSK(uint16_t id) : m_selected_identity(id), m_session_to_resume_or_psk(std::monostate()) {}

      Server_PSK(uint16_t id, Session session) :
            m_selected_identity(id), m_session_to_resume_or_psk(std::move(session)) {}

      Server_PSK(uint16_t id, ExternalPSK psk) : m_selected_identity(id), m_session_to_resume_or_psk(std::move(psk)) {}

      uint16_t selected_identity() const { return m_selected_identity; }

      std::variant<std::monostate, Session, ExternalPSK> take_session_to_resume_or_psk() {
         BOTAN_STATE_CHECK(!std::holds_alternative<std::monostate>(m_session_to_resume_or_psk));
         return std::exchange(m_session_to_resume_or_psk, std::monostate());
      }

   private:
      uint16_t m_selected_identity;

      // Servers store the Session to resume or the PSK of their selection
      std::variant<std::monostate, Session, ExternalPSK> m_session_to_resume_or_psk;
};

}  // namespace

class PSK::PSK_Internal {
   public:
      PSK_Internal(Server_PSK srv_psk) : psk(std::move(srv_psk)) {}

      PSK_Internal(std::vector<Client_PSK> clt_psks) : psk(std::move(clt_psks)) {}

      // NOLINTNEXTLINE(*-non-private-member-variables-in-classes)
      std::variant<std::vector<Client_PSK>, Server_PSK> psk;
};

PSK::PSK(TLS_Data_Reader& reader, uint16_t extension_size, Handshake_Type message_type) {
   if(message_type == Handshake_Type::ServerHello) {
      if(extension_size != 2) {
         throw TLS_Exception(Alert::DecodeError, "Server provided a malformed PSK extension");
      }

      const uint16_t selected_id = reader.get_uint16_t();
      m_impl = std::make_unique<PSK_Internal>(Server_PSK(selected_id));
   } else if(message_type == Handshake_Type::ClientHello) {
      const auto identities_length = reader.get_uint16_t();
      const auto identities_offset = reader.read_so_far();

      std::vector<PskIdentity> psk_identities;
      while(reader.has_remaining() && (reader.read_so_far() - identities_offset) < identities_length) {
         auto identity = reader.get_tls_length_value(2);
         const auto obfuscated_ticket_age = reader.get_uint32_t();
         psk_identities.emplace_back(std::move(identity), obfuscated_ticket_age);
      }

      if(psk_identities.empty()) {
         throw TLS_Exception(Alert::DecodeError, "Empty PSK list");
      }

      if(reader.read_so_far() - identities_offset != identities_length) {
         throw TLS_Exception(Alert::DecodeError, "Inconsistent PSK identity list");
      }

      const auto binders_length = reader.get_uint16_t();
      const auto binders_offset = reader.read_so_far();

      if(binders_length == 0) {
         throw TLS_Exception(Alert::DecodeError, "Empty PSK binders list");
      }

      std::vector<Client_PSK> psks;
      for(auto& psk_identity : psk_identities) {
         if(!reader.has_remaining() || reader.read_so_far() - binders_offset >= binders_length) {
            throw TLS_Exception(Alert::IllegalParameter, "Not enough PSK binders");
         }

         psks.emplace_back(std::move(psk_identity), reader.get_tls_length_value(1));
      }

      if(reader.read_so_far() - binders_offset != binders_length) {
         throw TLS_Exception(Alert::IllegalParameter, "Too many PSK binders");
      }

      m_impl = std::make_unique<PSK_Internal>(std::move(psks));
   } else {
      throw TLS_Exception(Alert::DecodeError, "Found a PSK extension in an unexpected handshake message");
   }
}

PSK::PSK(std::optional<Session_with_Handle>& session_to_resume, std::vector<ExternalPSK> psks, Callbacks& callbacks) {
   std::vector<Client_PSK> cpsk;

   if(session_to_resume.has_value()) {
      cpsk.emplace_back(session_to_resume.value(), callbacks.tls_current_timestamp());
   }

   for(auto&& psk : psks) {
      cpsk.emplace_back(std::move(psk));
   }

   m_impl = std::make_unique<PSK_Internal>(std::move(cpsk));
}

PSK::PSK(Session session_to_resume, const uint16_t psk_index) :
      m_impl(std::make_unique<PSK_Internal>(Server_PSK(psk_index, std::move(session_to_resume)))) {}

PSK::PSK(ExternalPSK psk, const uint16_t psk_index) :
      m_impl(std::make_unique<PSK_Internal>(Server_PSK(psk_index, std::move(psk)))) {}

PSK::~PSK() = default;

bool PSK::empty() const {
   if(std::holds_alternative<Server_PSK>(m_impl->psk)) {
      return false;
   }

   BOTAN_ASSERT_NOMSG(std::holds_alternative<std::vector<Client_PSK>>(m_impl->psk));
   return std::get<std::vector<Client_PSK>>(m_impl->psk).empty();
}

std::pair<std::optional<std::string>, std::unique_ptr<Cipher_State>> PSK::take_selected_psk_info(
   const PSK& server_psk, const Ciphersuite& cipher) {
   BOTAN_STATE_CHECK(std::holds_alternative<std::vector<Client_PSK>>(m_impl->psk));
   BOTAN_STATE_CHECK(std::holds_alternative<Server_PSK>(server_psk.m_impl->psk));

   const auto id = std::get<Server_PSK>(server_psk.m_impl->psk).selected_identity();
   auto& ids = std::get<std::vector<Client_PSK>>(m_impl->psk);

   // RFC 8446 4.2.11
   //    Clients MUST verify that the server's selected_identity is within the
   //    range supplied by the client, [...].  If these values are not
   //    consistent, the client MUST abort the handshake with an
   //    "illegal_parameter" alert.
   if(id >= ids.size()) {
      throw TLS_Exception(Alert::IllegalParameter, "PSK identity selected by server is out of bounds");
   }

   auto& selected_psk = ids.at(id);
   auto cipher_state = selected_psk.take_cipher_state();

   BOTAN_ASSERT_NONNULL(cipher_state);

   auto psk_id = [&]() -> std::optional<std::string> {
      if(selected_psk.is_resumption()) {
         return std::nullopt;
      }
      return selected_psk.identity().identity_as_string();
   }();

   // destroy cipher states and PSKs that were not selected by the server
   ids.clear();

   // RFC 8446 4.2.11
   //    Clients MUST verify that [...] the server selected a cipher suite
   //    indicating a Hash associated with the PSK [...].  If these values
   //    are not consistent, the client MUST abort the handshake with an
   //   "illegal_parameter" alert.
   if(!cipher_state->is_compatible_with(cipher)) {
      throw TLS_Exception(Alert::IllegalParameter, "PSK and ciphersuite selected by server are not compatible");
   }

   return {std::move(psk_id), std::move(cipher_state)};
}

std::unique_ptr<PSK> PSK::select_offered_psk(std::string_view host,
                                             const Ciphersuite& cipher,
                                             Session_Manager& session_mgr,
                                             Credentials_Manager& credentials_mgr,
                                             Callbacks& callbacks,
                                             const Policy& policy) {
   BOTAN_STATE_CHECK(std::holds_alternative<std::vector<Client_PSK>>(m_impl->psk));

   auto& psks = std::get<std::vector<Client_PSK>>(m_impl->psk);

   //
   // PSK for Session Resumption
   //
   std::vector<PskIdentity> psk_identities;
   std::transform(
      psks.begin(), psks.end(), std::back_inserter(psk_identities), [&](const auto& psk) { return psk.identity(); });
   if(auto selected_session =
         session_mgr.choose_from_offered_tickets(psk_identities, cipher.prf_algo(), callbacks, policy)) {
      auto& [session, psk_index] = selected_session.value();

      // RFC 8446 4.6.1
      //    Any ticket MUST only be resumed with a cipher suite that has the
      //    same KDF hash algorithm as that used to establish the original
      //    connection.
      if(session.ciphersuite().prf_algo() != cipher.prf_algo()) {
         throw TLS_Exception(Alert::InternalError,
                             "Application chose a ticket that is not compatible with the negotiated ciphersuite");
      }

      return std::unique_ptr<PSK>(new PSK(std::move(session), psk_index));
   }

   //
   // Externally provided PSKs
   //
   std::vector<std::string> psk_ids;
   std::transform(psks.begin(), psks.end(), std::back_inserter(psk_ids), [&](const auto& psk) {
      return psk.identity().identity_as_string();
   });
   if(auto selected_psk =
         credentials_mgr.choose_preshared_key(host, Connection_Side::Server, psk_ids, cipher.prf_algo())) {
      auto& psk = selected_psk.value();

      // RFC 8446 4.2.11
      //    Each PSK is associated with a single Hash algorithm. [...]
      //    The server MUST ensure that it selects a compatible PSK (if any)
      //    and cipher suite.
      if(psk.prf_algo() != cipher.prf_algo()) {
         throw TLS_Exception(Alert::InternalError,
                             "Application chose a PSK that is not compatible with the negotiated ciphersuite");
      }

      const auto selected_itr =
         std::find_if(psk_identities.begin(), psk_identities.end(), [&](const auto& offered_psk) {
            return offered_psk.identity_as_string() == psk.identity();
         });
      if(selected_itr == psk_identities.end()) {
         throw TLS_Exception(Alert::InternalError,
                             "Application provided a PSK with an identity that was not offered by the client");
      }

      // When implementing a server that works with PSKs exclusively, we might
      // want to take TLS::Policy::hide_unknown_users() into account and
      // obfuscate malicious "identity guesses" by generating a random PSK and
      // letting the handshake continue.
      //
      // Currently, we do not have a notion of "a server that solely supports
      // PSK handshakes". However, such applications are free to implement such
      // a mitigation in their override of Credentials_Manager::choose_preshared_key().
      //
      // TODO: Take RFC 8446 Appendix E.6 into account, especially when
      //       implementing PSK_KE (aka. PSK-only mode).
      return std::unique_ptr<PSK>(
         new PSK(std::move(psk), static_cast<uint16_t>(std::distance(psk_identities.begin(), selected_itr))));
   }

   return nullptr;
}

void PSK::filter(const Ciphersuite& cipher) {
   BOTAN_STATE_CHECK(std::holds_alternative<std::vector<Client_PSK>>(m_impl->psk));
   auto& psks = std::get<std::vector<Client_PSK>>(m_impl->psk);

   const auto r = std::remove_if(psks.begin(), psks.end(), [&](const auto& psk) {
      const auto& cipher_state = psk.cipher_state();
      return !cipher_state.is_compatible_with(cipher);
   });
   psks.erase(r, psks.end());
}

std::variant<Session, ExternalPSK> PSK::take_session_to_resume_or_psk() {
   BOTAN_STATE_CHECK(std::holds_alternative<Server_PSK>(m_impl->psk));

   return std::visit(
      [](auto out) -> std::variant<Session, ExternalPSK> {
         if constexpr(std::is_same_v<decltype(out), std::monostate>) {
            throw TLS_Exception(AlertType::InternalError, "cannot extract an empty PSK");
         } else {
            return out;
         }
      },
      std::get<Server_PSK>(m_impl->psk).take_session_to_resume_or_psk());
}

std::vector<uint8_t> PSK::serialize(Connection_Side side) const {
   std::vector<uint8_t> result;

   std::visit(overloaded{
                 [&](const Server_PSK& psk) {
                    BOTAN_STATE_CHECK(side == Connection_Side::Server);
                    result.reserve(2);
                    const uint16_t id = psk.selected_identity();
                    result.push_back(get_byte<0>(id));
                    result.push_back(get_byte<1>(id));
                 },
                 [&](const std::vector<Client_PSK>& psks) {
                    BOTAN_STATE_CHECK(side == Connection_Side::Client);

                    std::vector<uint8_t> identities;
                    std::vector<uint8_t> binders;
                    for(const auto& psk : psks) {
                       const auto& psk_identity = psk.identity();
                       append_tls_length_value(identities, psk_identity.identity(), 2);

                       const uint32_t obfuscated_ticket_age = psk_identity.obfuscated_age();
                       identities.push_back(get_byte<0>(obfuscated_ticket_age));
                       identities.push_back(get_byte<1>(obfuscated_ticket_age));
                       identities.push_back(get_byte<2>(obfuscated_ticket_age));
                       identities.push_back(get_byte<3>(obfuscated_ticket_age));

                       append_tls_length_value(binders, psk.binder(), 1);
                    }

                    append_tls_length_value(result, identities, 2);
                    append_tls_length_value(result, binders, 2);
                 },
              },
              m_impl->psk);

   return result;
}

// See RFC 8446 4.2.11.2 for details on how these binders are calculated
void PSK::calculate_binders(const Transcript_Hash_State& truncated_transcript_hash) {
   BOTAN_ASSERT_NOMSG(std::holds_alternative<std::vector<Client_PSK>>(m_impl->psk));
   for(auto& psk : std::get<std::vector<Client_PSK>>(m_impl->psk)) {
      auto tth = truncated_transcript_hash.clone();
      const auto& cipher_state = psk.cipher_state();
      tth.set_algorithm(cipher_state.hash_algorithm());
      psk.set_binder(cipher_state.psk_binder_mac(tth.truncated()));
   }
}

bool PSK::validate_binder(const PSK& server_psk, const std::vector<uint8_t>& binder) const {
   BOTAN_STATE_CHECK(std::holds_alternative<std::vector<Client_PSK>>(m_impl->psk));
   BOTAN_STATE_CHECK(std::holds_alternative<Server_PSK>(server_psk.m_impl->psk));

   const uint16_t index = std::get<Server_PSK>(server_psk.m_impl->psk).selected_identity();
   const auto& psks = std::get<std::vector<Client_PSK>>(m_impl->psk);

   BOTAN_STATE_CHECK(index < psks.size());
   return psks[index].binder() == binder;
}

}  // namespace Botan::TLS

#endif  // HAS_TLS_13
