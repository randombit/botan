/*
* TLS Extension Pre Shared Key
* (C) 2022 Jack Lloyd
*     2022 René Meusel, neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_cipher_state.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/stl_util.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_extensions.h>
#include <botan/tls_session.h>
#include <botan/tls_session_manager.h>

#include <utility>

#if defined(BOTAN_HAS_TLS_13)

namespace Botan::TLS {

namespace {

struct Client_PSK
   {
   Ticket ticket;
   std::vector<uint8_t> binder;

   // Clients set up associated cipher states for PSKs
   // Servers leave this as nullptr
   std::unique_ptr<Cipher_State> cipher_state;
   };

struct Server_PSK
   {
   uint16_t selected_identity;

   // Servers store the Session to resume from the selected PSK
   // Clients leave this as std::nullopt
   std::optional<Session> session_to_resume;
   };

}  // namespace


class PSK::PSK_Internal
   {
   public:
      PSK_Internal(Server_PSK srv_psk) : psk(srv_psk) {}
      PSK_Internal(std::vector<Client_PSK> clt_psks) : psk(std::move(clt_psks)) {}

      std::variant<std::vector<Client_PSK>, Server_PSK> psk;
   };


PSK::PSK(TLS_Data_Reader& reader,
         uint16_t extension_size,
         Handshake_Type message_type)
   {
   if(message_type == Handshake_Type::ServerHello)
      {
      if(extension_size != 2)
         throw TLS_Exception(Alert::DecodeError, "Server provided a malformed PSK extension");

      m_impl =
         std::make_unique<PSK_Internal>(
            Server_PSK
               {
               .selected_identity = reader.get_uint16_t(),
               .session_to_resume = std::nullopt
               });
      }
   else if(message_type == Handshake_Type::ClientHello)
      {
      std::vector<Client_PSK> psks;

      const auto identities_length = reader.get_uint16_t();
      const auto identities_offset = reader.read_so_far();

      while(reader.has_remaining() && (reader.read_so_far() - identities_offset) < identities_length)
         {
         auto identity = Opaque_Session_Handle(reader.get_tls_length_value(2));
         const auto obfuscated_ticket_age = reader.get_uint32_t();

         psks.emplace_back(
            Client_PSK{
               .ticket = Ticket(std::move(identity), obfuscated_ticket_age),
               .binder = {},
               .cipher_state = nullptr
            });
         }

      if(psks.empty())
         {
         throw TLS_Exception(Alert::DecodeError, "Empty PSK list");
         }

      if(reader.read_so_far() - identities_offset != identities_length)
         {
         throw TLS_Exception(Alert::DecodeError, "Inconsistent PSK identity list");
         }

      const auto binders_length = reader.get_uint16_t();
      const auto binders_offset = reader.read_so_far();

      if(binders_length == 0)
         {
         throw TLS_Exception(Alert::DecodeError, "Empty PSK binders list");
         }

      for(auto& psk : psks)
         {
         if(!reader.has_remaining() || reader.read_so_far() - binders_offset >= binders_length)
            {
            throw TLS_Exception(Alert::IllegalParameter, "Not enough PSK binders");
            }

         psk.binder = reader.get_tls_length_value(1);
         }

      if(reader.read_so_far() - binders_offset != binders_length)
         {
         throw TLS_Exception(Alert::IllegalParameter, "Too many PSK binders");
         }

      m_impl = std::make_unique<PSK_Internal>(std::move(psks));
      }
   else
      {
      throw TLS_Exception(Alert::DecodeError, "Found a PSK extension in an unexpected handshake message");
      }
   }


PSK::PSK(const Session_with_Handle& session_to_resume, Callbacks& callbacks)
   {
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
   const auto cipher = session_to_resume.session.ciphersuite();
   const auto binder_length =
      HashFunction::create_or_throw(cipher.prf_algo())->output_length();

   // TODO: This unneccesarily creates a copy of the master secret. Maybe we want
   //       to provide something like Session::extract_master_secret()?
   auto psk = session_to_resume.session.master_secret();

   // TODO: Currently this does not provide actual millisecond resolution.
   //       This might become a problem when "early data" is implemented and we
   //       deal with servers that employ a strict "freshness" criteria on the
   //       ticket's age.
   const auto age =
      std::chrono::duration_cast<std::chrono::milliseconds>(
         callbacks.tls_current_timestamp() - session_to_resume.session.start_time());

   std::vector<Client_PSK> cpsk;
   cpsk.emplace_back(Client_PSK
      {
      .ticket = Ticket(session_to_resume.handle.opaque_handle(), age,
                       session_to_resume.session.session_age_add()),
      .binder = std::vector<uint8_t>(binder_length),
      .cipher_state = Cipher_State::init_with_psk(Connection_Side::Client,
                                                   Cipher_State::PSK_Type::Resumption,
                                                   std::move(psk),
                                                   cipher)
      });

   m_impl = std::make_unique<PSK_Internal>(std::move(cpsk));
   }


PSK::~PSK() = default;


bool PSK::empty() const
   {
   if(std::holds_alternative<Server_PSK>(m_impl->psk))
      return false;

   BOTAN_ASSERT_NOMSG(std::holds_alternative<std::vector<Client_PSK>>(m_impl->psk));
   return std::get<std::vector<Client_PSK>>(m_impl->psk).empty();
   }


std::unique_ptr<Cipher_State> PSK::select_cipher_state(const PSK& server_psk, const Ciphersuite& cipher)
   {
   BOTAN_STATE_CHECK(std::holds_alternative<std::vector<Client_PSK>>(m_impl->psk));
   BOTAN_STATE_CHECK(std::holds_alternative<Server_PSK>(server_psk.m_impl->psk));

   const auto id = std::get<Server_PSK>(server_psk.m_impl->psk).selected_identity;
   auto& ids = std::get<std::vector<Client_PSK>>(m_impl->psk);

   // RFC 8446 4.2.11
   //    Clients MUST verify that the server's selected_identity is within the
   //    range supplied by the client, [...].  If these values are not
   //    consistent, the client MUST abort the handshake with an
   //    "illegal_parameter" alert.
   if(id >= ids.size())
      {
      throw TLS_Exception(Alert::IllegalParameter, "PSK identity selected by server is out of bounds");
      }

   auto cipher_state = std::exchange(ids[id].cipher_state, nullptr);
   BOTAN_ASSERT_NONNULL(cipher_state);

   // destroy cipher states and PSKs that were not selected by the server
   ids.clear();

   // RFC 8446 4.2.11
   //    Clients MUST verify that [...] the server selected a cipher suite
   //    indicating a Hash associated with the PSK [...].  If these values
   //    are not consistent, the client MUST abort the handshake with an
   //   "illegal_parameter" alert.
   if(!cipher_state->is_compatible_with(cipher))
      {
      throw TLS_Exception(Alert::IllegalParameter, "PSK and ciphersuite selected by server are not compatible");
      }

   return cipher_state;
   }


void PSK::filter(const Ciphersuite& cipher)
   {
   BOTAN_STATE_CHECK(std::holds_alternative<std::vector<Client_PSK>>(m_impl->psk));
   auto& psks = std::get<std::vector<Client_PSK>>(m_impl->psk);

   const auto r = std::remove_if(psks.begin(), psks.end(), [&](const auto& psk)
      {
      BOTAN_ASSERT_NONNULL(psk.cipher_state);
      return !psk.cipher_state->is_compatible_with(cipher);
      });
   psks.erase(r, psks.end());
   }


std::vector<uint8_t> PSK::serialize(Connection_Side side) const
   {
   std::vector<uint8_t> result;

   std::visit(overloaded
      {
      [&](const Server_PSK& psk)
         {
         BOTAN_STATE_CHECK(side == Connection_Side::Server);
         result.reserve(2);
         result.push_back(get_byte<0>(psk.selected_identity));
         result.push_back(get_byte<1>(psk.selected_identity));
         },
      [&](const std::vector<Client_PSK>& psks)
         {
         BOTAN_STATE_CHECK(side == Connection_Side::Client);

         std::vector<uint8_t> identities;
         std::vector<uint8_t> binders;
         for(const auto& psk : psks)
            {
            append_tls_length_value(identities, psk.ticket.identity().get(), 2);

            const auto obfuscated_ticket_age = psk.ticket.obfuscated_age();
            identities.push_back(get_byte<0>(obfuscated_ticket_age));
            identities.push_back(get_byte<1>(obfuscated_ticket_age));
            identities.push_back(get_byte<2>(obfuscated_ticket_age));
            identities.push_back(get_byte<3>(obfuscated_ticket_age));

            append_tls_length_value(binders, psk.binder, 1);
            }

         append_tls_length_value(result, identities, 2);
         append_tls_length_value(result, binders, 2);
         },
      },
      m_impl->psk);

   return result;
   }

// See RFC 8446 4.2.11.2 for details on how these binders are calculated
void PSK::calculate_binders(const Transcript_Hash_State& truncated_transcript_hash)
   {
   BOTAN_ASSERT_NOMSG(std::holds_alternative<std::vector<Client_PSK>>(m_impl->psk));
   for(auto& psk : std::get<std::vector<Client_PSK>>(m_impl->psk))
      {
      auto tth = truncated_transcript_hash.clone();
      BOTAN_ASSERT_NONNULL(psk.cipher_state);
      tth.set_algorithm(psk.cipher_state->hash_algorithm());
      psk.binder = psk.cipher_state->psk_binder_mac(tth.truncated());
      }
   }

}  // Botan::TLS

#endif  // HAS_TLS_13
