/*
* TLS transcript hash implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_transcript_hash_13.h>

#include <utility>

namespace Botan::TLS {

Transcript_Hash_State::Transcript_Hash_State(const std::string &algo_spec)
   {
   set_algorithm(algo_spec);
   }

Transcript_Hash_State::Transcript_Hash_State(const Transcript_Hash_State& other)
   : m_hash((other.m_hash != nullptr) ? other.m_hash->copy_state() : nullptr)
   , m_unprocessed_transcript(other.m_unprocessed_transcript)
   , m_current(other.m_current)
   , m_previous(other.m_previous)
   {}


Transcript_Hash_State Transcript_Hash_State::recreate_after_hello_retry_request(
                                          const std::string& algo_spec,
                                          const Transcript_Hash_State& prev_transcript_hash_state)
   {
   // make sure that we have seen exactly 'client_hello' and 'hello_retry_request'
   // before re-creating the transcript hash state
   BOTAN_STATE_CHECK(prev_transcript_hash_state.m_hash == nullptr);
   BOTAN_STATE_CHECK(prev_transcript_hash_state.m_unprocessed_transcript.size() == 2);

   Transcript_Hash_State ths(algo_spec);

   const auto& client_hello_1      = prev_transcript_hash_state.m_unprocessed_transcript.front();
   const auto& hello_retry_request = prev_transcript_hash_state.m_unprocessed_transcript.back();

   const size_t hash_length = ths.m_hash->output_length();
   BOTAN_ASSERT_NOMSG(hash_length < 256);

   // RFC 8446 4.4.1
   //    [...], when the server responds to a ClientHello with a HelloRetryRequest,
   //    the value of ClientHello1 is replaced with a special synthetic handshake
   //    message of handshake type "message_hash" [(0xFE)] containing:
   std::vector<uint8_t> message_hash;
   message_hash.reserve(4 + hash_length);
   message_hash.push_back(0xFE /* message type 'message_hash' RFC 8446 4. */);
   message_hash.push_back(0x00);
   message_hash.push_back(0x00);
   message_hash.push_back(static_cast<uint8_t>(hash_length));
   message_hash += ths.m_hash->process(client_hello_1);

   ths.update(message_hash);
   ths.update(hello_retry_request);

   return ths;
   }

void Transcript_Hash_State::update(const uint8_t* serialized_message, const size_t serialized_message_length)
   {
   if(m_hash != nullptr)
      {
      // Botan does not support finalizing a HashFunction without resetting
      // the internal state of the hash. Hence we first copy the internal
      // state and then finalize the transient HashFunction.
      m_hash->update(serialized_message, serialized_message_length);
      m_previous = std::exchange(m_current, m_hash->copy_state()->final_stdvec());
      }
   else
      {
      m_unprocessed_transcript.push_back(std::vector(serialized_message, serialized_message + serialized_message_length));
      }
   }

const Transcript_Hash& Transcript_Hash_State::current() const
   {
   BOTAN_STATE_CHECK(!m_current.empty());
   return m_current;
   }

const Transcript_Hash& Transcript_Hash_State::previous() const
   {
   BOTAN_STATE_CHECK(!m_previous.empty());
   return m_previous;
   }

void Transcript_Hash_State::set_algorithm(const std::string& algo_spec)
   {
   BOTAN_STATE_CHECK(m_hash == nullptr || m_hash->name() == algo_spec);
   if(m_hash != nullptr)
      return;

   m_hash = HashFunction::create_or_throw(algo_spec);
   for(const auto& msg : m_unprocessed_transcript)
      {
      update(msg);
      }
   m_unprocessed_transcript.clear();
   }

Transcript_Hash_State Transcript_Hash_State::clone() const
   {
   return *this;
   }

}
