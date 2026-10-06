/*
* TLS transcript hash implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_transcript_hash_13.h>

#include <botan/hash.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_extensions.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_reader.h>

#include <utility>

namespace Botan::TLS {

Transcript_Hash_State::Transcript_Hash_State(TLS_Flavor flavor) : m_flavor(flavor) {}

Transcript_Hash_State::Transcript_Hash_State(TLS_Flavor flavor, std::string_view algo_spec) :
      Transcript_Hash_State(flavor) {
   set_algorithm(algo_spec);
}

Transcript_Hash_State::~Transcript_Hash_State() = default;

Transcript_Hash_State::Transcript_Hash_State(Transcript_Hash_State&& other) noexcept = default;
Transcript_Hash_State& Transcript_Hash_State::operator=(Transcript_Hash_State&& other) noexcept = default;

Transcript_Hash_State::Transcript_Hash_State(const Transcript_Hash_State& other) :
      m_flavor(other.m_flavor),
      m_hash((other.m_hash != nullptr) ? other.m_hash->copy_state() : nullptr),
      m_unprocessed_transcript(other.m_unprocessed_transcript),
      m_current(other.m_current),
      m_previous(other.m_previous),
      m_truncated(other.m_truncated) {}

Transcript_Hash_State Transcript_Hash_State::recreate_after_hello_retry_request(
   std::string_view algo_spec, const Transcript_Hash_State& prev_transcript_hash_state) {
   // make sure that we have seen exactly 'client_hello' and 'hello_retry_request'
   // before re-creating the transcript hash state
   BOTAN_STATE_CHECK(prev_transcript_hash_state.m_hash == nullptr);
   BOTAN_STATE_CHECK(prev_transcript_hash_state.m_unprocessed_transcript.size() == 2);

   Transcript_Hash_State transcript_hash(prev_transcript_hash_state.m_flavor, algo_spec);

   const auto& client_hello_1 = prev_transcript_hash_state.m_unprocessed_transcript.front();
   const auto& hello_retry_request = prev_transcript_hash_state.m_unprocessed_transcript.back();

   const auto hash_length = transcript_hash.m_hash->output_length();
   BOTAN_DEBUG_ASSERT(hash_length <= 0xFF);

   // RFC 9846 4.1
   //    [...], when the server responds to a ClientHello with a HelloRetryRequest,
   //    the value of ClientHello1 is replaced with a special synthetic handshake
   //    message of handshake type "message_hash" [...]:
   const auto message_hash_header =
      HandshakeProtocolHeader({to_underlying(Handshake_Type::MessageHash), 0, 0, static_cast<uint8_t>(hash_length)});

   transcript_hash.m_hash->update(client_hello_1.first);
   transcript_hash.m_hash->update(client_hello_1.second);
   const auto message_hash_msg = transcript_hash.m_hash->final<SerializedHandshakeMessage>();

   transcript_hash.update(message_hash_header, message_hash_msg);
   transcript_hash.update(hello_retry_request.first, hello_retry_request.second);

   return transcript_hash;
}

namespace {

// TODO: This is a massive code duplication of the client hello parsing code,
//       as well as basic parsing of extensions. We should resolve this.
//
// Ad-hoc idea: When parsing the production objects, we could keep markers into
//              the original buffer. E.g. the PSK extensions would keep its off-
//              set into the entire client hello buffer. Using that offset we
//              could quickly identify the offset of the binders list slice the
//              buffer without re-parsing it.
//
// Finds the truncation offset in a serialization of Client Hello as defined in
// RFC 8446 4.2.11.2 used for the calculation of PSK binder MACs.
// Returns std::nullopt if the Client Hello does not contain a PSK extension.
std::optional<size_t> find_client_hello_truncation_mark(std::span<const uint8_t> client_hello, TLS_Flavor flavor) {
   BOTAN_UNUSED(flavor);

   TLS_Data_Reader reader("Client Hello Truncation", client_hello);

   // legacy version
   reader.discard_next(2);

   // random
   reader.discard_next(32);

   // session ID
   const auto session_id_length = reader.get_byte();
   reader.discard_next(session_id_length);

   // cipher suites
   const auto ciphersuites_length = reader.get_uint16_t();
   reader.discard_next(ciphersuites_length);

   // compression methods
   const auto compression_methods_length = reader.get_byte();
   reader.discard_next(compression_methods_length);

   // extensions
   const auto extensions_length = reader.get_uint16_t();
   const auto extensions_offset = reader.read_so_far();
   while(reader.has_remaining() && reader.read_so_far() - extensions_offset < extensions_length) {
      const auto ext_type = static_cast<Extension_Code>(reader.get_uint16_t());
      const auto ext_length = reader.get_uint16_t();

      // skip over all extensions, finding the PSK extension to be truncated
      if(ext_type != Extension_Code::PresharedKey) {
         reader.discard_next(ext_length);
         continue;
      }

      // PSK identities list
      const auto identities_length = reader.get_uint16_t();
      reader.discard_next(identities_length);

      // check that only the binders are left in the buffer...
      const auto binders_length = reader.peek_uint16_t();
      if(binders_length != reader.remaining_bytes() - 2 /* binders_length */) {
         throw TLS_Exception(Alert::IllegalParameter,
                             "Failed to truncate Client Hello that doesn't end on the PSK binders list");
      }

      // the reader now points to the truncation point
      return reader.read_so_far();
   }

   // if no PSK extension was found, no truncation is necessary
   return std::nullopt;
}

std::vector<uint8_t> read_hash_state(std::unique_ptr<HashFunction>& hash) {
   // Botan does not support finalizing a HashFunction without resetting
   // the internal state of the hash. Hence we first copy the internal
   // state and then finalize the transient HashFunction.
   return hash->copy_state()->final_stdvec();
}

}  // namespace

void Transcript_Hash_State::update(HandshakeProtocolHeader tls_message_header,
                                   StrongSpan<const SerializedHandshakeMessage> serialized_message_s) {
   if(m_hash != nullptr) {
      m_hash->update(tls_message_header);

      // Check whether we should generate a truncated hash for supporting PSK
      // binder calculation or verification. See RFC 9846 4.3.11.2.
      const auto message_type = static_cast<Handshake_Type>(tls_message_header[0]);
      if(message_type == Handshake_Type::ClientHello) {
         const auto truncation_mark = find_client_hello_truncation_mark(serialized_message_s, m_flavor);
         if(truncation_mark.has_value()) {
            m_hash->update(serialized_message_s.get().first(*truncation_mark));
            m_truncated = read_hash_state(m_hash);
            m_hash->update(serialized_message_s.get().subspan(*truncation_mark));
         } else {
            m_hash->update(serialized_message_s);
         }
      } else {
         m_truncated.clear();
         m_hash->update(serialized_message_s);
      }

      m_previous = std::exchange(m_current, read_hash_state(m_hash));
   } else {
      m_unprocessed_transcript.emplace_back(tls_message_header, serialized_message_s);
   }
}

const Transcript_Hash& Transcript_Hash_State::current() const {
   BOTAN_STATE_CHECK(!m_current.empty());
   return m_current;
}

const Transcript_Hash& Transcript_Hash_State::previous() const {
   BOTAN_STATE_CHECK(!m_previous.empty());
   return m_previous;
}

const Transcript_Hash& Transcript_Hash_State::truncated() const {
   BOTAN_STATE_CHECK(!m_truncated.empty());
   return m_truncated;
}

void Transcript_Hash_State::set_algorithm(std::string_view algo_spec) {
   BOTAN_STATE_CHECK(m_hash == nullptr || m_hash->name() == algo_spec);
   if(m_hash != nullptr) {
      return;
   }

   m_hash = HashFunction::create_or_throw(algo_spec);
   for(const auto& [header, msg] : m_unprocessed_transcript) {
      update(header, msg);
   }
   m_unprocessed_transcript.clear();
}

Transcript_Hash_State Transcript_Hash_State::clone() const {
   return *this;
}

}  // namespace Botan::TLS
