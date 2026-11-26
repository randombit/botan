/*
* TLS handshake layer implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*     2026 René Meusel, Amos Treiber - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_HANDSHAKE_LAYER_13_H_
#define BOTAN_TLS_HANDSHAKE_LAYER_13_H_

#include <optional>
#include <vector>

#include <botan/tls_magic.h>
#include <botan/tls_messages_13.h>
#include <botan/internal/tls_types_13.h>

#include <botan/internal/concat_util.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/tls_record_13.h>

namespace Botan::TLS {

class Transcript_Hash_State;

/**
 * Implementation of the TLS 1.3 handshake protocol layer
 *
 * This component transforms payload bytes received in TLS records
 * from the peer into parsed handshake messages and vice versa.
 */
class BOTAN_TEST_API Handshake_Layer {
   protected:
      explicit Handshake_Layer(Connection_Side whoami) :
            m_peer(whoami == Connection_Side::Server ? Connection_Side::Client : Connection_Side::Server)
            // RFC 8446 4.4.2
            //    If the corresponding certificate type extension
            //    ("server_certificate_type" or "client_certificate_type") was not
            //    negotiated in EncryptedExtensions, or the X.509 certificate type
            //    was negotiated, then each CertificateEntry contains a DER-encoded
            //    X.509 certificate.
            //
            // We need the certificate_type info to parse Certificate messages.
            ,
            m_certificate_type(Certificate_Type::X509) {}

   public:
      /**
       * The outcome of ingesting handshake data via copy_data(). This
       * information is relevant for DTLS, where handshake messages can be
       * fragmented and fragments may be maliciously forged or arrive
       * out of order.
       */
      enum class [[nodiscard]] CopyDataResult : uint8_t {
         /// The passed-in data was discarded without being processed or buffered
         Discarded,

         /// The passed-in data consisted solely of retransmitted fragments
         DiscardedDuplicate,

         /// Some of the passed-in data was discarded, but some was buffered
         ConsumedPartially,

         /// All of the passed-in data was successfully consumed
         Consumed,
      };

      static SerializedHandshakeMessage serialize(const Handshake_Message& message) {
         return SerializedHandshakeMessage(message.serialize());
      }

   public:
      Handshake_Layer(const Handshake_Layer&) = delete;
      Handshake_Layer(Handshake_Layer&&) = delete;
      Handshake_Layer& operator=(const Handshake_Layer&) = delete;
      Handshake_Layer& operator=(Handshake_Layer&&) = delete;

      virtual ~Handshake_Layer() = default;

      /**
       * Reads data that was received in handshake records and stores it internally for further
       * processing during the invocation of `next_message()`.
       *
       * @param policy          The TLS policy
       * @param data_from_peer  The data to be parsed. In DTLS this is assumed to be one or
       *                        more full handshake message fragments. In TLS it might be a
       *                        an in-order portion of any size
       *
       * @returns a CopyDataResult indicating whether the data contained new
       *          handshake information and/or fragments that had to be
       *          discarded (relevant for DTLS only).
       */
      virtual CopyDataResult copy_data(const Policy& policy, const Handshake_Record& data_from_peer) = 0;

      /**
       * Parses one handshake message off the internal buffer that is being filled using `copy_data`.
       *
       * TODO: remove the std::optional<std::reference_wrapper<>> shenanigan
       *       when integrating the re-vamped DTLS-enabled data influx routine.
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
       * @param policy                   the TLS policy
       * @param latest_read_epoch_number the number of the latest available read epoch
       *
       * @return the parsed post-handshake message, or nullopt if more data is needed to complete the message
       */
      std::optional<Post_Handshake_Message_13> next_post_handshake_message(const Policy& policy,
                                                                           EpochNumber latest_read_epoch_number);

      /**
       * Marshals a ClientHello prematurely for a truncated transcript hash
       * calculation (cf. RFC 8446 Section 4.2.11.2).
       *
       * @param message the ClientHello message to be marshalled
       * @param transcript_hash the transcript hash state to be updated
       */
      static void update_transcript_for_psk_binder_calc(const Client_Hello_13& message,
                                                        Transcript_Hash_State& transcript_hash);

      /**
       * Check if the Handshake_Layer has stored a partial message in its internal buffer.
       * This can happen if a handshake message spans multiple records.
       */
      virtual bool has_pending_data() const = 0;

      /**
       * Set the certificate_type used for parsing Certificate messages. This
       * is determined via (client/server)_certificate_type extensions during
       * the handshake.
       *
       * RFC 7250 4.3 and 4.4
       *    When the TLS server has specified RawPublicKey as the
       *    [client_certificate_type/server_certificate_type], authentication
       *    of the TLS [client/server] to the TLS [server/client] is supported
       *    only through authentication of the received client
       *    SubjectPublicKeyInfo via an out-of-band method.
       *
       * If the peer sends a Certificate message containing an incompatible
       * means of authentication, a 'decode_error' will be generated.
       */
      void set_selected_certificate_type(Certificate_Type cert_type) { m_certificate_type = cert_type; }

   protected:
      struct Message final {
            std::optional<EpochNumber> epoch_number;
            Handshake_Type type = Handshake_Type::None;
            HandshakeProtocolHeader header = {};
            SerializedHandshakeMessage payload;
      };

      virtual std::optional<Message> take_next_message() = 0;

      virtual TLS_Flavor tls_flavor() const = 0;

      Handshake_Type read_handshake_message_type(uint8_t msg_type_byte) const;

      Connection_Side peer() const { return m_peer; }

      Certificate_Type certificate_type() const { return m_certificate_type; }

      virtual Handshake_Message_13 parse_handshake_message(const Message& message, const Policy& policy) const;
      Post_Handshake_Message_13 parse_post_handshake_message(const Message& message) const;

   private:
      Connection_Side m_peer;
      Certificate_Type m_certificate_type;
      bool m_peer_speaks_tls13 = false;
};

class BOTAN_TEST_API TLS_Handshake_Layer final : public Handshake_Layer {
   public:
      explicit TLS_Handshake_Layer(Connection_Side whoami);

      TLS_Handshake_Layer(const TLS_Handshake_Layer&) = delete;
      TLS_Handshake_Layer(TLS_Handshake_Layer&&) = delete;
      TLS_Handshake_Layer& operator=(const TLS_Handshake_Layer&) = delete;
      TLS_Handshake_Layer& operator=(TLS_Handshake_Layer&&) = delete;
      ~TLS_Handshake_Layer() override;

      /**
       * Prepare the TLS message header according to RFC9846 Section 4
       */
      static HandshakeProtocolHeader prepare_header(Handshake_Type type, size_t payload_length) {
         BOTAN_ASSERT_NOMSG(payload_length <= 0xFFFFFF);
         auto header = HandshakeProtocolHeader(store_be(static_cast<uint32_t>(payload_length)));
         header[0] = static_cast<uint8_t>(type);
         return header;
      }

      bool has_pending_data() const override;

      CopyDataResult copy_data(const Policy& policy, const Handshake_Record& data_from_peer) override;

      static auto marshal(const Handshake_Message& message) {
         const auto bytes = serialize(message);
         return concat<MarshalledHandshakeMessage>(prepare_header(message.wire_type(), bytes.size()), bytes);
      }

   private:
      class PendingMessage;

      std::optional<Message> take_next_message() override;

      TLS_Flavor tls_flavor() const override { return TLS_Flavor::TLS; }

   private:
      std::vector<PendingMessage> m_pending_messages;
};

}  // namespace Botan::TLS

#endif
