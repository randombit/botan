/*
* TLS 1.3 Flights
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_FLIGHT_13_H_
#define BOTAN_TLS_FLIGHT_13_H_

#include <botan/tls_magic.h>
#include <botan/tls_messages_13.h>
#include <botan/internal/tls_types_13.h>
#include <optional>
#include <variant>
#include <vector>

namespace Botan::TLS {

class Callbacks;
class Transcript_Hash_State;

/**
 * Helper class to coalesce handshake messages into a TLS flight. The class
 * keeps track of the serialized messages and updates the transcript hash
 * accordingly.
 *
 * Once the flight is constructed, using code must commit() it and pass on the
 * prepared list of serialized messages for sending. After commit() the flight
 * object is invalid and must not be used anymore.
 *
 * Note that this class takes references to transcript hash and callbacks
 * objects. The caller is responsible for ensuring that these objects remain
 * valid for the lifetime of the Flight object. The flight object is meant to be
 * used in a single stack frame and not stored for later use.
 */
class BOTAN_TEST_API Flight {
   public:
      struct Dummy_ChangeCipherSpec {};

      struct Message_Info {
            Handshake_Type wire_type;
            HandshakeProtocolHeader header;
            SerializedHandshakeMessage serialized;
      };

      using Message = std::variant<Dummy_ChangeCipherSpec, Message_Info>;

      enum class PostHandshake : bool { No = false, Yes = true };

   protected:
      explicit Flight(Callbacks& callbacks) : m_callbacks(callbacks) { m_messages.emplace(); }

      Flight(Flight&& other) = default;

   public:
      Flight(Transcript_Hash_State& transcript_hash, Callbacks& callbacks) :
            m_transcript_hash(transcript_hash), m_callbacks(callbacks) {
         m_messages.emplace();
      }

      Flight(const Flight& other) = delete;
      Flight& operator=(const Flight& other) = delete;
      Flight& operator=(Flight&& other) = delete;
      ~Flight() = default;

      /**
       * Add a @p msg to this flight, updating the transcript hash associated
       * with this flight and letting the user inspect the message first via the
       * callbacks.
       *
       * TODO(C++23): deducing-this
       *
       * @param msg The handshake message to add to the flight
       * @throws Invalid_State if the flight was already committed
       */
      Flight& add(Handshake_Message_13_Ref msg) & {
         std::visit([&](const auto m) { append(m.get(), PostHandshake::No); }, msg);
         return *this;
      }

      /**
       * Add a @p msg to this flight, updating the transcript hash associated
       * with this flight and letting the user inspect the message first via the
       * callbacks.
       *
       * TODO(C++23): deducing-this
       *
       * @param msg The handshake message to add to the flight
       * @throws Invalid_State if the flight was already committed
       */
      Flight add(Handshake_Message_13_Ref msg) && {
         std::visit([&](const auto m) { append(m.get(), PostHandshake::No); }, msg);
         return std::move(*this);
      }

      /**
       * Add a dummy ChangeCipherSpec message to the flight when following the
       * compatibility mode for TLS 1.3. See RFC 9846 E.4 for details.
       *
       * TODO(C++23): deducing-this
       *
       * @throws Invalid_State if the flight was already committed
       */
      Flight& add_dummy_change_cipher_spec() & {
         append_ccs();
         return *this;
      }

      /**
       * Add a dummy ChangeCipherSpec message to the flight when following the
       * compatibility mode for TLS 1.3. See RFC 9846 E.4 for details.
       *
       * TODO(C++23): deducing-this
       *
       * @throws Invalid_State if the flight was already committed
       */
      Flight add_dummy_change_cipher_spec() && {
         append_ccs();
         return std::move(*this);
      }

      /**
       * Extract the messages from the flight for sending. This invalidates the
       * flight object and it cannot be used anymore.
       *
       * @throws Invalid_State if the flight was already committed or if it
       *                        is empty
       */
      std::vector<Message> commit();

   protected:
      void append(const Handshake_Message& message, PostHandshake post_handshake);
      void append_ccs();

   private:
      std::optional<std::reference_wrapper<Transcript_Hash_State>> m_transcript_hash;
      Callbacks& m_callbacks;

      std::optional<std::vector<Message>> m_messages;
};

/**
 * Helper class to coalesce post-handshake messages into a TLS flight.
 */
class BOTAN_TEST_API PostHandshakeFlight final : protected Flight {
   public:
      explicit PostHandshakeFlight(Callbacks& callbacks) : Flight(callbacks) {}

   public:
      /**
       * Add a @p msg to this flight, letting the user inspect the message first
       * via the callbacks. The transcript hash is unchanged for post-handshake
       * messages.
       *
       * TODO(C++23): deducing-this
       *
       * @param msg The post-handshake message to add to the flight
       * @throws Invalid_State if the flight was already committed
       */
      PostHandshakeFlight& add(const Post_Handshake_Message_13& msg) & {
         std::visit([&](const auto& m) { append(m, PostHandshake::Yes); }, msg);
         return *this;
      }

      /**
       * Add a @p msg to this flight, letting the user inspect the message first
       * via the callbacks. The transcript hash is unchanged for post-handshake
       * messages.
       *
       * TODO(C++23): deducing-this
       *
       * @param msg The post-handshake message to add to the flight
       * @throws Invalid_State if the flight was already committed
       */
      PostHandshakeFlight add(const Post_Handshake_Message_13& msg) && {
         std::visit([&](const auto& m) { append(m, PostHandshake::Yes); }, msg);
         return std::move(*this);
      }

      using Flight::commit;
};

}  // namespace Botan::TLS

#endif
