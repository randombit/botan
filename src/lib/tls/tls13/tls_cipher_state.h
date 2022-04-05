/*
* TLS cipher state implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CIPHER_STATE_H_
#define BOTAN_TLS_CIPHER_STATE_H_

#include <botan/secmem.h>
#include <botan/tls_magic.h>

#include <botan/internal/tls_transcript_hash_13.h>

namespace Botan {

class AEAD_Mode;
class HashFunction;
class HKDF_Extract;
class HKDF_Expand;

namespace TLS {
class Ciphersuite;
}
}

namespace Botan::TLS {

/**
 * This class implements the key schedule for TLS 1.3 as described in RFC 8446 7.1.
 *
 * Internally, it reflects the state machine pictured in the same RFC section.
 * It provides the following entry points and state advancement methods that
 * each facilitate certain cryptographic functionality:
 *
 * * init_with_psk()
 *   not yet implemented
 *
 * * init_with_server_hello() / advance_with_server_hello()
 *   allows encrypting and decrypting handshake traffic, as well as producing
 *   and validating the client/server handshake finished MACs
 *
 * * advance_with_server_finished()
 *   allows encrypting and decrypting application traffic
 *
 * * advance_with_client_finished()
 *   allows negotiation of resumption PSKs
 *
 * While encrypting and decrypting records (RFC 8446 5.2) Cipher_State
 * internally keeps track of the current sequence numbers (RFC 8446 5.3) to
 * calculate the correct Per-Record Nonce. Sequence numbers are reset
 * appropriately, whenever traffic secrets change.
 *
 * Handshake finished MAC calculation and verification is described in RFC 8446 4.4.4.
 *
 * PSKs calculation is described in RFC 8446 4.6.1.
 */
class BOTAN_TEST_API Cipher_State
   {
   public:
      ~Cipher_State();

      /**
       * Construct a Cipher_State after receiving a server hello message.
       */
      static std::unique_ptr<Cipher_State> init_with_server_hello(
         const Connection_Side side,
         secure_vector<uint8_t>&& shared_secret,
         const Ciphersuite& cipher,
         const Transcript_Hash& transcript_hash);

      /**
       * Transition internal secrets/keys for transporting application data.
       */
      void advance_with_server_finished(const Transcript_Hash& transcript_hash);

      /**
       * Transition to the final internal state allowing to create resumptions.
       */
      void advance_with_client_finished(const Transcript_Hash& transcript_hash);

      /**
       * Encrypt a TLS record fragment (RFC 8446 5.2 -- TLSInnerPlaintext) using the
       * currently available traffic secret keys and the current sequence number.
       * This will internally increment the sequence number. Hence, multiple
       * calls with the same input will not produce the same result.
       *
       * @returns  the sequence number of the encrypted record
       */
      uint64_t encrypt_record_fragment(const std::vector<uint8_t>& header, secure_vector<uint8_t>& fragment);

      /**
       * Decrypt a TLS record fragment (RFC 8446 5.2 -- TLSCiphertext.encrypted_record)
       * using the currently available traffic secret keys and the current sequence number.
       * This will internally increment the sequence number. Hence, multiple
       * calls with the same input will not produce the same result.
       *
       * @returns  the sequence number of the decrypted record
       */
      uint64_t decrypt_record_fragment(const std::vector<uint8_t>& header, secure_vector<uint8_t>& encrypted_fragment);

      /**
       * @returns  number of bytes needed to encrypt \p input_length bytes
       */
      size_t encrypt_output_length(const size_t input_length) const;

      /**
       * @returns  number of bytes needed to decrypt \p input_length bytes
       */
      size_t decrypt_output_length(const size_t input_length) const;

      /**
       * @returns  the minimum ciphertext length for decryption
       */
      size_t minimum_decryption_input_length() const;

      /**
       * Calculate the MAC for a TLS "Finished" handshake message (RFC 8446 4.4.4)
       */
      std::vector<uint8_t> finished_mac(const Transcript_Hash& transcript_hash) const;

      /**
       * Validate a MAC received in a TLS "Finished" handshake message (RFC 8446 4.4.4)
       */
      bool verify_peer_finished_mac(const Transcript_Hash& transcript_hash,
                                    const std::vector<uint8_t>& peer_mac) const;

      /**
       * Calculate the PSK for the given nonce (RFC 8446 4.6.1)
       */
      secure_vector<uint8_t> psk(const std::vector<uint8_t>& nonce) const;

      /**
       * Derive key material to export (RFC 8446 7.5 and RFC 5705)
       *
       * TODO: this does not yet support key export based on the `early_exporter_master_secret`.
       *
       * RFC 8446 7.5
       *    Implementations MUST use the exporter_master_secret unless explicitly
       *    specified by the application. The early_exporter_master_secret is
       *    defined for use in settings where an exporter is needed for 0-RTT data.
       *    A separate interface for the early exporter is RECOMMENDED [...].
       *
       * @param label     a disambiguating label string
       * @param context   a per-association context value
       * @param length    the length of the desired key in bytes
       * @return          key of length bytes
       */
      secure_vector<uint8_t> export_key(const std::string& label,
                                        const std::string& context,
                                        size_t length) const;

      /**
       * Indicates whether the appropriate secrets to export keys are available
       */
      bool can_export_keys() const
         {
         return (m_state == State::ApplicationTraffic || m_state == State::Completed) &&
                !m_exporter_master_secret.empty();
         }

      /**
       * Indicates whether the appropriate secrets to encrypt application traffic are available
       */
      bool can_encrypt_application_traffic() const
         {
         return m_state != State::Uninitialized && m_state != State::HandshakeTraffic
                && !m_write_key.empty() && !m_write_iv.empty();
         }

      /**
       * Updates the key material used for decrypting data
       * This is triggered after we received a Key_Update from the peer.
       *
       * Note that this must not be called before the connection is ready for
       * application traffic.
       */
      void update_read_keys();

      /**
       * Updates the key material used for encrypting data
       * This is triggered after we send a Key_Update to the peer.
       *
       * Note that this must not be called before the connection is ready for
       * application traffic.
       */
      void update_write_keys();

      /**
       * Remove handshake/traffic secrets for decrypting data from peer
       */
      void clear_read_keys();

      /**
       * Remove handshake/traffic secrets for encrypting data
       */
      void clear_write_keys();

   private:
      /**
       * @param cipher  the negotiated cipher suite
       * @param whoami  whether we play the SERVER or CLIENT
       */
      Cipher_State(Connection_Side whoami, const Ciphersuite& cipher);

      void advance_without_psk();

      void advance_with_server_hello(secure_vector<uint8_t>&& shared_secret,
                                     const Transcript_Hash& transcript_hash);

      std::vector<uint8_t> current_nonce(const uint64_t seq_no,
                                         const secure_vector<uint8_t>& iv) const;

      void derive_write_traffic_key(const secure_vector<uint8_t>& traffic_secret,
                                    const bool handshake_traffic_secret = false);
      void derive_read_traffic_key(const secure_vector<uint8_t>& traffic_secret,
                                   const bool handshake_traffic_secret = false);

      /**
       * HKDF-Extract from RFC 8446 7.1
       */
      secure_vector<uint8_t> hkdf_extract(secure_vector<uint8_t>&& ikm) const;

      /**
       * HKDF-Expand-Label from RFC 8446 7.1
       */
      secure_vector<uint8_t> hkdf_expand_label(
         const secure_vector<uint8_t>& secret,
         const std::string&            label,
         const std::vector<uint8_t>&   context,
         const size_t                  length) const;

      /**
       * Derive-Secret from RFC 8446 7.1
       */
      secure_vector<uint8_t> derive_secret(
         const secure_vector<uint8_t>& secret,
         const std::string&            label,
         const Transcript_Hash&        messages_hash) const;

      std::vector<uint8_t> empty_hash() const;

   private:
      enum class State
         {
         Uninitialized,
         EarlyTraffic,
         HandshakeTraffic,
         ApplicationTraffic,
         Completed
         };

   private:
      State           m_state;
      Connection_Side m_connection_side;

      std::unique_ptr<AEAD_Mode> m_encrypt;
      std::unique_ptr<AEAD_Mode> m_decrypt;

      std::unique_ptr<HKDF_Extract> m_extract;
      std::unique_ptr<HKDF_Expand>  m_expand;
      std::unique_ptr<HashFunction> m_hash;

      secure_vector<uint8_t> m_salt;

      secure_vector<uint8_t> m_write_application_traffic_secret;
      secure_vector<uint8_t> m_read_application_traffic_secret;

      secure_vector<uint8_t> m_write_key;
      secure_vector<uint8_t> m_write_iv;
      secure_vector<uint8_t> m_read_key;
      secure_vector<uint8_t> m_read_iv;

      uint64_t m_write_seq_no;
      uint64_t m_read_seq_no;

      secure_vector<uint8_t> m_finished_key;
      secure_vector<uint8_t> m_peer_finished_key;
      secure_vector<uint8_t> m_exporter_master_secret;
      secure_vector<uint8_t> m_resumption_master_secret;
   };

}

#endif // BOTAN_TLS_CIPHER_STATE_H_
