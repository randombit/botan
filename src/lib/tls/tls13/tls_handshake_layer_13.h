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

   private:
      std::vector<uint8_t> m_read_buffer;
      Connection_Side m_peer;
      Certificate_Type m_certificate_type;
};

}  // namespace Botan::TLS

#endif
