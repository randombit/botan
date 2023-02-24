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
   std::vector<uint8_t> identity;
   std::vector<uint8_t> binder;
   uint32_t             obfuscated_ticket_age;

   std::string hash_algorithm;
   std::unique_ptr<Cipher_State> cipher_state;
   };

struct Server_PSK
   {
   uint16_t selected_identity;
   };

// RFC 8446 4.2.11.1
//    The "obfuscated_ticket_age" field of each PskIdentity contains an
//    obfuscated version of the ticket age formed by taking the age in
//    milliseconds and adding the "ticket_age_add" value that was included with
//    the ticket, modulo 2^32.
uint32_t obfuscate_ticket_age(std::chrono::milliseconds ticket_age, uint32_t ticket_age_add)
   {
   const uint64_t age = ticket_age.count();
   const uint64_t add = ticket_age_add;
   return static_cast<uint32_t>(age + add);
   }

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

      m_impl = std::make_unique<PSK_Internal>(Server_PSK{reader.get_uint16_t()});
      }
   else if(message_type == Handshake_Type::ClientHello)
      {
      std::vector<Client_PSK> psks;

      const auto identities_length = reader.get_uint16_t();
      const auto identities_offset = reader.read_so_far();

      while(reader.has_remaining() && (reader.read_so_far() - identities_offset) < identities_length)
         {
         auto& psk = psks.emplace_back();
         psk.identity = reader.get_tls_length_value(2);
         psk.obfuscated_ticket_age = reader.get_uint32_t();
         }

      if(reader.read_so_far() - identities_offset != identities_length)
         {
         throw TLS_Exception(Alert::DecodeError, "Inconsistent PSK identity list");
         }

      const auto binders_length = reader.get_uint16_t();
      const auto binders_offset = reader.read_so_far();

      for(auto& psk : psks)
         {
         if(!reader.has_remaining() || reader.read_so_far() - binders_offset >= binders_length)
            {
            throw TLS_Exception(Alert::DecodeError, "Not enough PSK binders");
            }

         psk.binder = reader.get_tls_length_value(1);
         }

      if(reader.read_so_far() - binders_offset != binders_length)
         {
         throw TLS_Exception(Alert::DecodeError, "Inconsistent PSK binders list");
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
   std::vector<Client_PSK> psks;
   auto& cpsk = psks.emplace_back();

   cpsk.identity = session_to_resume.handle.opaque_handle().get();

   const auto age =
      std::chrono::duration_cast<std::chrono::milliseconds>(
         callbacks.tls_current_timestamp() - session_to_resume.session.start_time());

   cpsk.obfuscated_ticket_age =
      obfuscate_ticket_age(age, session_to_resume.session.session_age_add());

   auto psk = session_to_resume.session.master_secret();
   cpsk.hash_algorithm = session_to_resume.session.ciphersuite().prf_algo();
   cpsk.cipher_state = Cipher_State::init_with_psk(Connection_Side::Client,
                                                   Cipher_State::PSK_Type::Resumption,
                                                   std::move(psk),
                                                   session_to_resume.session.ciphersuite());

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
   const auto binder_length = HashFunction::create_or_throw(cpsk.hash_algorithm)->output_length();
   cpsk.binder = std::vector<uint8_t>(binder_length);

   m_impl = std::make_unique<PSK_Internal>(std::move(psks));
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

   // RFC 8446 4.2.11
   //    Clients MUST verify that [...] the server selected a cipher suite
   //    indicating a Hash associated with the PSK [...].  If these values
   //    are not consistent, the client MUST abort the handshake with an
   //   "illegal_parameter" alert.
   if(!cipher_state->is_compatible_with(cipher))
      {
      throw TLS_Exception(Alert::IllegalParameter, "PSK and ciphersuite selected by server are not compatible");
      }

   // destroy cipher states and PSKs that were not selected by the server
   ids.clear();

   return cipher_state;
   }


void PSK::filter(const Ciphersuite& cipher)
   {
   BOTAN_STATE_CHECK(std::holds_alternative<std::vector<Client_PSK>>(m_impl->psk));
   auto& psks = std::get<std::vector<Client_PSK>>(m_impl->psk);

   const auto r = std::remove_if(psks.begin(), psks.end(), [&](const auto& psk)
      { return psk.hash_algorithm != cipher.prf_algo(); });
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
            append_tls_length_value(identities, psk.identity, 2);
            identities.push_back(get_byte<0>(psk.obfuscated_ticket_age));
            identities.push_back(get_byte<1>(psk.obfuscated_ticket_age));
            identities.push_back(get_byte<2>(psk.obfuscated_ticket_age));
            identities.push_back(get_byte<3>(psk.obfuscated_ticket_age));

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
      tth.set_algorithm(psk.hash_algorithm);
      BOTAN_ASSERT_NONNULL(psk.cipher_state);
      psk.binder = psk.cipher_state->psk_binder_mac(tth.truncated());
      }
   }

}  // Botan::TLS

#endif  // HAS_TLS_13
