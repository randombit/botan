/*
* TLS transcript hash implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_TRANSCRIPT_HASH_13_H_
#define BOTAN_TLS_TRANSCRIPT_HASH_13_H_

#include <memory>
#include <string>
#include <vector>

#include <botan/hash.h>
#include <botan/tls_magic.h>

namespace Botan::TLS {

/**
 * Wraps the behaviour of the TLS 1.3 transcript hash as described in
 * RFC 8446 4.4.1. Particularly, it hides the complexity that the
 * utilized hash algorithm might become evident only after receiving
 * a server hello message.
 */
class BOTAN_TEST_API Transcript_Hash_State
   {
   public:
      Transcript_Hash_State() = default;
      Transcript_Hash_State(const std::string &algo_spec);
      ~Transcript_Hash_State() = default;

      /**
       * Recreates a Transcript_Hash_State after receiving a Hello Retry Request.
       * Note that the `prev_transcript_hash_state` must not have an hash algorithm
       * set, yet. Furthermore it must contain exactly TWO unprocessed messages:
       *   * Client Hello 1, and
       *   * Hello Retry Request
       * The result of this function is an ordinary transcript hash that can replace
       * the previously used object in client and server implementations.
       */
      static Transcript_Hash_State recreate_after_hello_retry_request(
                        const std::string& algo_spec,
                        const Transcript_Hash_State& prev_transcript_hash_state);

      Transcript_Hash_State& operator=(const Transcript_Hash_State&) = delete;

      Transcript_Hash_State(Transcript_Hash_State&&) = default;
      Transcript_Hash_State& operator=(Transcript_Hash_State&&) = default;

      void update(const std::vector<uint8_t>& serialized_message)
         {
         update(serialized_message.data(), serialized_message.size());
         }

      // TODO: C++20 replace this C-style API with std::span
      void update(const uint8_t* serialized_message, const size_t serialized_message_length);

      /**
       * returns the latest transcript hash
       * (given an algorithm was already specified and some data was provided to `update`)
       */
      const Transcript_Hash& current() const;

      /**
       * returns the second-latest transcript hash
       * throws if no 'current' was ever replaced by a call to `update`
       */
      const Transcript_Hash& previous() const;

      void set_algorithm(const std::string& algo_spec);

      Transcript_Hash_State clone() const;

   private:
      Transcript_Hash_State(const Transcript_Hash_State& other);

   private:
      std::unique_ptr<HashFunction> m_hash;

      // This buffer is filled with the data that is passed into
      // `update()` before `set_algorithm()` was called.
      std::vector<std::vector<uint8_t>> m_unprocessed_transcript;

      Transcript_Hash m_current;
      Transcript_Hash m_previous;
   };

}

#endif // BOTAN_TLS_TRANSCRIPT_HASH_13_H_
