/*
* TLS handshake layer implementation for TLS 1.3
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_HANDSHAKE_LAYER_13_H_
#define BOTAN_TLS_HANDSHAKE_LAYER_13_H_

#include <optional>
#include <type_traits>
#include <variant>
#include <vector>

#include <botan/tls_magic.h>
#include <botan/tls_messages.h>

namespace Botan::TLS {

using BytesNeeded = size_t;

class Transcript_Hash_State;

/**
 * Implementation of the TLS 1.3 handshake protocol layer
 *
 * This component transforms payload bytes received in TLS records
 * from the peer into parsed handshake messages and vice versa.
 */
class BOTAN_TEST_API Handshake_Layer
   {
   public:
      Handshake_Layer(Connection_Side whoami) : m_peer(whoami == SERVER ? CLIENT : SERVER) {}

      template <typename ResT>
      using ReadResult = std::variant<BytesNeeded, ResT>;

      /**
       * Reads data that was received in handshake records and stores it internally for further
       * processing during the invocation of `next_message()`.
       *
       * @param data_from_peer  The data to be parsed.
       */
      void copy_data(const std::vector<uint8_t>& data_from_peer);

      /**
       * Parses one handshake message off the internal buffer that is being filled using `copy_data`.
       *
       * Return value contains either the number of bytes (`size_t`) needed to proceed
       * with processing TLS records or a single parsed TLS handshake message.
       *
       * @param policy the TLS policy
       */
      ReadResult<Handshake_Message_13> next_message(const Policy& policy, Transcript_Hash_State& transcript_hash);

      std::vector<uint8_t> prepare_message(const Handshake_Message_13_Ref message, Transcript_Hash_State& transcript_hash);

      // TODO: add interfaces and checks for conditions in 8446 5.1

   private:
      Handshake_Message_13 parse_message(const Botan::TLS::Policy& policy,
                                         Botan::TLS::Handshake_Type type,
                                         const std::vector<uint8_t>& msg);

      std::vector<uint8_t> m_read_buffer;
      Connection_Side m_peer;
   };

}

#endif
