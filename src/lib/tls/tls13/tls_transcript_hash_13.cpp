/*
* TLS transcript hash implementation for TLS 1.3
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_transcript_hash_13.h>

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

void Transcript_Hash_State::update(const std::vector<uint8_t>& serialized_message)
   {
   if(m_hash != nullptr)
      {
      // Botan does not support finalizing a HashFunction without resetting
      // the internal state of the hash. Hence we first copy the internal
      // state and then finalize the transient HashFunction.
      m_hash->update(serialized_message);
      m_previous = std::exchange(m_current, m_hash->copy_state()->final_stdvec());
      }
   else
      {
      m_unprocessed_transcript.insert(m_unprocessed_transcript.end(),
                                      serialized_message.cbegin(),
                                      serialized_message.cend());
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
   if(!m_unprocessed_transcript.empty())
      {
      update(m_unprocessed_transcript);
      m_unprocessed_transcript.clear();
      }
   }

Transcript_Hash_State Transcript_Hash_State::clone() const
   {
   return *this;
   }

}
