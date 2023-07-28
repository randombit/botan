/*
* TLS handshake layer implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_HANDSHAKE_LAYER_13_H_
#define BOTAN_TLS_HANDSHAKE_LAYER_13_H_

#include <optional>
#include <vector>

#include <botan/tls_magic.h>
#include <botan/tls_messages.h>

namespace Botan::TLS {

class Transcript_Hash_State;

/**
 * Implementation of the TLS 1.3 handshake protocol layer
 *
 * This component transforms payload bytes received in TLS records
 * from the peer into parsed handshake messages and vice versa.
 */
class BOTAN_TEST_API Handshake_Layer {
   public:
      Handshake_Layer(Connection_Side whoami) :
            m_peer(whoami == Connection_Side::Server ? Connection_Side::Client : Connection_Side::Server) {}

      /**
       * Reads data that was received in handshake records and stores it internally for further
       * processing during the invocation of `next_message()`.
       *
       * @param data_from_peer  The data to be parsed.
       */
      void copy_data(std::span<const uint8_t> data_from_peer);

      /**
       * Parses one handshake message off the internal buffer that is being filled using `copy_data`.
       *
       * @param policy the TLS policy
       * @param transcript_hash the transcript hash state to be updated
       *
       * @return the parsed handshake message, or nullopt if more data is needed to complete the message
       */
      std::optional<Handshake_Message_13> next_message(const Policy& policy, Transcript_Hash_State& transcript_hash);

      /**
       * Parses one post-handshake message off the internal buffer that is being filled using `copy_data`.
       *
       * @param policy the TLS policy
       *
       * @return the parsed post-handshake message, or nullopt if more data is needed to complete the message
       */
      std::optional<Post_Handshake_Message_13> next_post_handshake_message(const Policy& policy);

      /**
       * Marshalls one handshake message for sending in an (encrypted) record and updates the
       * provided transcript hash state accordingly.
       *
       * @param message the handshake message to be marshalled
       * @param transcript_hash the transcript hash state to be updated
       *
       * @return the marshalled handshake message
       */
      static std::vector<uint8_t> prepare_message(Handshake_Message_13_Ref message,
                                                  Transcript_Hash_State& transcript_hash);

      /**
       * Marshalls one post-handshake message for sending in an (encrypted) record.
       *
       * @param message the post handshake message to be marshalled
       *
       * @return the marshalled post-handshake message
       */
      static std::vector<uint8_t> prepare_post_handshake_message(const Post_Handshake_Message_13& message);

      /**
       * Check if the Handshake_Layer has stored a partial message in its internal buffer.
       * This can happen if a handshake message spans multiple records.
       */
      bool has_pending_data() const { return !m_read_buffer.empty(); }

   private:
      std::vector<uint8_t> m_read_buffer;
      Connection_Side m_peer;
};

}  // namespace Botan::TLS

#endif
