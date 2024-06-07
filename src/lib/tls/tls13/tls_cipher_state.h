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
#include <botan/tls_messages.h>

#include <botan/internal/tls_transcript_hash_13.h>

namespace Botan {

class AEAD_Mode;
class HashFunction;
class HKDF_Extract;
class HKDF_Expand;

}  // namespace Botan

namespace Botan::TLS {

class Ciphersuite;
class Secret_Logger;

/**
 * This class implements the key schedule for TLS 1.3 as described in RFC 8446 7.1.
 *
 * Internally, it reflects the state machine pictured in the same RFC section.
 * It provides the following entry points and state advancement methods that
 * each facilitate certain cryptographic functionality:
 *
 * * init_with_psk()
 *   sets up the cipher state with a pre-shared key (out of band or via session
 *   ticket). will allow sending early data in the future
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
class BOTAN_TEST_API Cipher_State {
   public:
      enum class PSK_Type {
         Resumption,
         External,  // currently not implemented
      };

   public:
      ~Cipher_State();

      /**
       * Construct a Cipher_State from a Pre-Shared-Key.
       */
      static std::unique_ptr<Cipher_State> init_with_psk(Connection_Side side,
                                                         PSK_Type type,
                                                         secure_vector<uint8_t>&& psk,
                                                         std::string_view prf_algo);

      /**
       * Construct a Cipher_State after receiving a server hello message.
       */
      static std::unique_ptr<Cipher_State> init_with_server_hello(Connection_Side side,
                                                                  secure_vector<uint8_t>&& shared_secret,
                                                                  const Ciphersuite& cipher,
                                                                  const Transcript_Hash& transcript_hash,
                                                                  const Secret_Logger& channel);

      /**
       * Transition internal secrets/keys for transporting early application data.
       * Note that this state transition is legal only for handshakes using PSK.
       */
      void advance_with_client_hello(const Transcript_Hash& transcript_hash, const Secret_Logger& channel);

      /**
       * Transition internal secrets/keys for transporting handshake data.
       */
      void advance_with_server_hello(const Ciphersuite& cipher,
                                     secure_vector<uint8_t>&& shared_secret,
                                     const Transcript_Hash& transcript_hash,
                                     const Secret_Logger& channel);

      /**
       * Transition internal secrets/keys for transporting application data.
       */
      void advance_with_server_finished(const Transcript_Hash& transcript_hash, const Secret_Logger& channel);

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
      size_t encrypt_output_length(size_t input_length) const;

      /**
       * @returns  number of bytes needed to decrypt \p input_length bytes
       */
      size_t decrypt_output_length(size_t input_length) const;

      /**
       * @returns  the minimum ciphertext length for decryption
       */
      size_t minimum_decryption_input_length() const;

      /**
       * Calculates the MAC for a PSK binder value in Client Hellos. Note that
       * the transcript hash passed into this method is computed from a partial
       * Client Hello (RFC 8446 4.2.11.2)
       */
      std::vector<uint8_t> psk_binder_mac(const Transcript_Hash& transcript_hash_with_truncated_client_hello) const;

      /**
       * Calculate the MAC for a TLS "Finished" handshake message (RFC 8446 4.4.4)
       */
      std::vector<uint8_t> finished_mac(const Transcript_Hash& transcript_hash) const;

      /**
       * Validate a MAC received in a TLS "Finished" handshake message (RFC 8446 4.4.4)
       */
      bool verify_peer_finished_mac(const Transcript_Hash& transcript_hash, const std::vector<uint8_t>& peer_mac) const;

      /**
       * Calculate the PSK for the given nonce (RFC 8446 4.6.1)
       */
      secure_vector<uint8_t> psk(const Ticket_Nonce& nonce) const;

      /**
       * Generates a nonce value that is unique for any given Cipher_State object.
       * Note that the number of nonces is limited to 2^16 and this method will
       * throw if more nonces are requested.
       */
      Ticket_Nonce next_ticket_nonce();

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
      secure_vector<uint8_t> export_key(std::string_view label, std::string_view context, size_t length) const;

      /**
       * Indicates whether the appropriate secrets to export keys are available
       */
      bool can_export_keys() const {
         return (m_state == State::EarlyTraffic || m_state == State::ServerApplicationTraffic ||
                 m_state == State::Completed) &&
                !m_exporter_master_secret.empty();
      }

      /**
       * Indicates whether unprotected Alert records are to be expected
       */
      bool must_expect_unprotected_alert_traffic() const;

      /**
       * Indicates whether the appropriate secrets to encrypt application traffic are available
       */
      bool can_encrypt_application_traffic() const;

      /**
       * Indicates whether the appropriate secrets to decrypt application traffic are available
       */
      bool can_decrypt_application_traffic() const;

      /**
       * The name of the hash algorithm used for the KDF in this cipher suite
       */
      std::string hash_algorithm() const;

      /**
       * @returns  true if the selected cipher primitives are compatible with
       *           the \p cipher suite.
       *
       * Note that cipher suites are considered "compatible" as long as the
       * already selected cipher primitives in this cipher state are compatible.
       */
      bool is_compatible_with(const Ciphersuite& cipher) const;

      /**
       * Updates the key material used for decrypting data
       * This is triggered after we received a Key_Update from the peer.
       *
       * Note that this must not be called before the connection is ready for
       * application traffic.
       */
      void update_read_keys(const Secret_Logger& channel);

      /**
       * Updates the key material used for encrypting data
       * This is triggered after we send a Key_Update to the peer.
       *
       * Note that this must not be called before the connection is ready for
       * application traffic.
       */
      void update_write_keys(const Secret_Logger& channel);

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
       * @param whoami         whether we play the Server or Client
       * @param hash_function  the negotiated hash function to be used
       */
      Cipher_State(Connection_Side whoami, std::string_view hash_function);

      void advance_with_psk(PSK_Type type, secure_vector<uint8_t>&& psk);
      void advance_without_psk();

      void derive_write_traffic_key(const secure_vector<uint8_t>& traffic_secret,
                                    bool handshake_traffic_secret = false);
      void derive_read_traffic_key(const secure_vector<uint8_t>& traffic_secret, bool handshake_traffic_secret = false);

      /**
       * HKDF-Extract from RFC 8446 7.1
       */
      secure_vector<uint8_t> hkdf_extract(std::span<const uint8_t> ikm) const;

      /**
       * HKDF-Expand-Label from RFC 8446 7.1
       */
      secure_vector<uint8_t> hkdf_expand_label(const secure_vector<uint8_t>& secret,
                                               std::string_view label,
                                               const std::vector<uint8_t>& context,
                                               size_t length) const;

      /**
       * Derive-Secret from RFC 8446 7.1
       */
      secure_vector<uint8_t> derive_secret(const secure_vector<uint8_t>& secret,
                                           std::string_view label,
                                           const Transcript_Hash& messages_hash) const;

      std::vector<uint8_t> empty_hash() const;

   private:
      enum class State {
         Uninitialized,
         PskBinder,
         EarlyTraffic,
         HandshakeTraffic,
         ServerApplicationTraffic,
         Completed
      };

   private:
      State m_state;
      Connection_Side m_connection_side;

      std::unique_ptr<AEAD_Mode> m_encrypt;
      std::unique_ptr<AEAD_Mode> m_decrypt;

      std::unique_ptr<HKDF_Extract> m_extract;
      std::unique_ptr<HKDF_Expand> m_expand;
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

      uint32_t m_write_key_update_count;
      uint32_t m_read_key_update_count;

      uint16_t m_ticket_nonce;

      secure_vector<uint8_t> m_finished_key;
      secure_vector<uint8_t> m_peer_finished_key;
      secure_vector<uint8_t> m_exporter_master_secret;
      secure_vector<uint8_t> m_resumption_master_secret;

      secure_vector<uint8_t> m_early_secret;
      secure_vector<uint8_t> m_binder_key;
};

}  // namespace Botan::TLS

#endif  // BOTAN_TLS_CIPHER_STATE_H_
