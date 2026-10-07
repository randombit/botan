/*
* TLS cipher state implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CIPHER_STATE_H_
#define BOTAN_TLS_CIPHER_STATE_H_

#include <botan/assert.h>
#include <botan/cipher_mode.h>
#include <botan/secmem.h>
#include <botan/tls_ciphersuite.h>
#include <botan/tls_magic.h>

#include <botan/internal/tls_record_13.h>
#include <botan/internal/tls_transcript_hash_13.h>
#include <botan/internal/tls_types_13.h>

#include <optional>

namespace Botan {

class AEAD_Mode;
class HashFunction;
class HKDF_Extract;
class HKDF_Expand;

}  // namespace Botan

namespace Botan::TLS {

class Ciphersuite;

/**
 * This class implements the key schedule for (D)TLS 1.3 as described in RFC 9846 7.1.
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
 * This is an abstract base class that implements the key schedule and leaves
 * the management of the resulting traffic epochs (as well as record
 * protection) to concrete subclasses for TLS and DTLS.
 *
 * While encrypting and decrypting records (RFC 9846 5.2) the concrete
 * subclasses internally keep track of the current sequence numbers
 * (RFC 9846 5.3) to calculate the correct Per-Record Nonce. Sequence numbers
 * are reset appropriately, whenever traffic secrets change.
 *
 * Handshake finished MAC calculation and verification is described in RFC 9846 4.5.3.
 * PSKs calculation is described in RFC 9846 4.7.1
 */
class BOTAN_TEST_API Cipher_State {
   public:
      enum class PSK_Type : uint8_t {
         Resumption,  // RFC 8446
         External,    // RFC 8446
         Imported,    // RFC 9258 PSK importer - uses "imp binder" label
      };

   public:
      /**
       * The cryptographic state required to protect or deprotect records in
       * one direction. Concrete subclasses manage the available epochs, e.g.
       * a single current epoch per direction for TLS 1.3.
       */
      struct Epoch {
            std::unique_ptr<AEAD_Mode> cipher;
            secure_vector<uint8_t> iv;
            uint64_t sequence_number;

            secure_vector<uint8_t> traffic_secret;

            /// only relevant in the handshake traffic epoch to
            /// calculate and verify the handshake's Finished MACs
            std::optional<secure_vector<uint8_t>> finished_key;
      };

      using ExpansionLabelPrefix = std::array<uint8_t, 6>;

   private:
      static std::unique_ptr<Cipher_State> create(Connection_Side side, TLS_Flavor flavor, std::string_view prf_algo);

   public:
      virtual ~Cipher_State();

      Cipher_State(const Cipher_State& other) = delete;
      Cipher_State(Cipher_State&& other) = delete;
      Cipher_State& operator=(const Cipher_State& other) = delete;
      Cipher_State& operator=(Cipher_State&& other) = delete;

      /**
       * Construct a Cipher_State from a Pre-Shared-Key.
       */
      static std::unique_ptr<Cipher_State> init_with_psk(Connection_Side side,
                                                         TLS_Flavor flavor,
                                                         PSK_Type type,
                                                         secure_vector<uint8_t>&& psk,
                                                         std::string_view prf_algo);

      /**
       * Construct a Cipher_State after receiving a server hello message.
       */
      static std::unique_ptr<Cipher_State> init_with_server_hello(Connection_Side side,
                                                                  TLS_Flavor flavor,
                                                                  secure_vector<uint8_t>&& shared_secret,
                                                                  const Ciphersuite& cipher,
                                                                  const Transcript_Hash& transcript_hash,
                                                                  SecretLoggerFn secret_logger);

      /**
       * Transition internal secrets/keys for transporting early application data.
       * Note that this state transition is legal only for handshakes using PSK.
       */
      void advance_with_client_hello(const Transcript_Hash& transcript_hash);

      /**
       * Transition internal secrets/keys for transporting handshake data.
       */
      void advance_with_server_hello(const Ciphersuite& cipher,
                                     secure_vector<uint8_t>&& shared_secret,
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
       * @returns number of bytes needed to encrypt \p input_length bytes
       */
      size_t encrypt_output_length(size_t input_length) const;

      /**
       * @returns number of bytes needed to decrypt \p input_length bytes
       */
      size_t decrypt_output_length(size_t input_length) const;

      /**
       * @returns the minimum ciphertext length for decryption
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
       * Indicates whether both peers' Finished messages were processed, i.e.
       * the key schedule reached its final state.
       */
      bool is_handshake_complete() const { return m_state == State::Completed; }

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
       * @returns true if the selected cipher primitives are compatible with
       *          the \p cipher suite.
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
       * @returns the number of records encrypted with the current write key
       */
      uint64_t records_encrypted_with_current_key() const;

      /**
       * @returns the number of records decrypted with the current read key
       */
      uint64_t records_decrypted_with_current_key() const;

      /**
       * Remove handshake/traffic secrets for decrypting data from peer
       */
      virtual void clear_read_keys() = 0;

      /**
       * Remove handshake/traffic secrets for encrypting data
       */
      virtual void clear_write_keys() = 0;

      /**
       * Register an optional callback function to extract secrets bound for a
       * SSLKEYLOGFILE. See SSLKEYLOGFILE RFC 9850 for details.
       */
      void set_secret_logger(SecretLoggerFn secret_logger) { m_secret_logger = std::move(secret_logger); }

   private:
      void advance_with_psk(PSK_Type type, secure_vector<uint8_t>&& psk);
      void advance_without_psk();

      /**
       * HKDF-Extract from RFC 8446 7.1
       */
      secure_vector<uint8_t> hkdf_extract(std::span<const uint8_t> ikm) const;

      /**
       * Derive-Secret from RFC 8446 7.1
       */
      secure_vector<uint8_t> derive_secret(const secure_vector<uint8_t>& secret,
                                           std::string_view label,
                                           const Transcript_Hash& messages_hash) const;

      void maybe_log_secret(std::string_view label, std::span<const uint8_t> secret) const {
         if(m_secret_logger) {
            m_secret_logger(label, secret);
         }
      }

      std::vector<uint8_t> empty_hash() const;

   protected:
      /**
       * @param whoami         whether we play the Server or Client
       * @param hash_function  the negotiated hash function to be used
       * @param expand_prefix  the prefix to be used for HKDF-Expand-Label
       */
      Cipher_State(Connection_Side whoami, std::string_view hash_function, ExpansionLabelPrefix expand_prefix);

      static size_t protected_record_length(Epoch& epoch, size_t payload_length, size_t padding_bytes);
      static MarshalledRecord marshall_and_protect(Epoch& epoch,
                                                   std::span<const uint8_t> header,
                                                   std::span<const uint8_t> payload,
                                                   Record_Type type,
                                                   size_t padding_bytes);
      void deprotect_and_hydrate_content_type(Epoch& epoch,
                                              std::span<const uint8_t> header,
                                              Record_Content& protected_record,
                                              size_t incoming_record_size_limit) const;

      /**
       * HKDF-Expand-Label from RFC 8446 7.1
       */
      secure_vector<uint8_t> hkdf_expand_label(const secure_vector<uint8_t>& secret,
                                               std::string_view label,
                                               const std::vector<uint8_t>& context,
                                               size_t length) const;

      Cipher_State::Epoch create_epoch(Cipher_Dir direction,
                                       const secure_vector<uint8_t>& traffic_secret,
                                       bool handshake_epoch) const;

      const Ciphersuite& ciphersuite() const;

      virtual void advance_write_epoch(const secure_vector<uint8_t>& traffic_secret, bool handshake_epoch = false) = 0;
      virtual void advance_read_epoch(const secure_vector<uint8_t>& traffic_secret, bool handshake_epoch = false) = 0;

      virtual bool has_write_epoch() const = 0;
      virtual bool has_read_epoch() const = 0;
      virtual Epoch& latest_write_epoch() = 0;
      virtual const Epoch& latest_write_epoch() const = 0;
      virtual Epoch& latest_read_epoch() = 0;
      virtual const Epoch& latest_read_epoch() const = 0;

   private:
      enum class State : uint8_t {
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
      std::optional<Ciphersuite> m_ciphersuite;
      SecretLoggerFn m_secret_logger;

      std::unique_ptr<HKDF_Extract> m_extract;
      std::unique_ptr<HKDF_Expand> m_expand;
      std::unique_ptr<HashFunction> m_hash;

      ExpansionLabelPrefix m_expansion_label_prefix;
      secure_vector<uint8_t> m_salt;
      secure_vector<uint8_t> m_client_application_traffic_secret_0;

      uint32_t m_write_key_update_count = 0;
      uint32_t m_read_key_update_count = 0;

      uint16_t m_ticket_nonce;
      bool m_ticket_nonce_exhausted = false;

      secure_vector<uint8_t> m_exporter_master_secret;
      secure_vector<uint8_t> m_resumption_master_secret;

      secure_vector<uint8_t> m_early_secret;
      secure_vector<uint8_t> m_binder_key;
};

/**
 * Cipher State implementation for TLS 1.3 (RFC 9846).
 *
 * This re-uses the key schedule implementation in the Cipher_State base class
 * and implements record (de)protection and epoch management for TLS 1.3. Epochs
 * in TLS 1.3 are simply rolled over whenever necessary. No historic epochs are
 * kept.
 */
class BOTAN_TEST_API TLS_Cipher_State final : public Cipher_State {
   public:
      TLS_Cipher_State(Connection_Side side, std::string_view prf_algo);

      ~TLS_Cipher_State() override;
      TLS_Cipher_State(const TLS_Cipher_State&) = delete;
      TLS_Cipher_State& operator=(const TLS_Cipher_State&) = delete;
      TLS_Cipher_State(TLS_Cipher_State&&) = delete;
      TLS_Cipher_State& operator=(TLS_Cipher_State&&) = delete;

      /**
       * Protect a TLS record (RFC 9846 5.2 -- TLSInnerPlaintext) using the
       * currently available traffic secret keys and the current sequence
       * number. This will internally increment the sequence number. Hence,
       * multiple calls with the same input will not produce the same result.
       *
       * @param type           the record type to be protected
       * @param payload        the record plaintext to be protected in-place
       * @param padding_bytes  the number of padding zero-bytes to be added
       *
       * @returns the marshalled and protected record to be sent on the wire
       */
      [[nodiscard]] MarshalledRecord protect_record(Record_Type type,
                                                    std::span<const uint8_t> payload,
                                                    size_t padding_bytes);

      /**
       * Deprotect a TLS record (RFC 9846 5.2 -- TLSCiphertext.encrypted_record)
       * using the currently available traffic secret keys and the current
       * sequence number. This will internally increment the sequence number.
       * Hence, multiple calls with the same input will not produce the same
       * result.
       *
       * @param record                      the record to be deprotected in-place
       * @param incoming_record_size_limit  the maximum allowed size for the incoming record
       *
       * @returns the record payload and deprotected content type
       */
      [[nodiscard]] Record deprotect_record(Record_TLS record, size_t incoming_record_size_limit);

      void clear_write_keys() override;

      void clear_read_keys() override;

   private:
      void advance_write_epoch(const secure_vector<uint8_t>& traffic_secret, bool handshake_epoch = false) override;
      void advance_read_epoch(const secure_vector<uint8_t>& traffic_secret, bool handshake_epoch = false) override;

      bool has_write_epoch() const override { return m_write_epoch.has_value(); }

      bool has_read_epoch() const override { return m_read_epoch.has_value(); }

      Epoch& latest_write_epoch() override {
         BOTAN_ASSERT_NOMSG(has_write_epoch());
         return *m_write_epoch;
      }

      const Epoch& latest_write_epoch() const override {
         BOTAN_ASSERT_NOMSG(has_write_epoch());
         return *m_write_epoch;
      }

      Epoch& latest_read_epoch() override {
         BOTAN_ASSERT_NOMSG(has_read_epoch());
         return *m_read_epoch;
      }

      const Epoch& latest_read_epoch() const override {
         BOTAN_ASSERT_NOMSG(has_read_epoch());
         return *m_read_epoch;
      }

   private:
      std::optional<Epoch> m_write_epoch;
      std::optional<Epoch> m_read_epoch;
};

inline TLS_Cipher_State* as_tls_cipher_state(Cipher_State* cs) {
   auto* tls_cs = dynamic_cast<TLS_Cipher_State*>(cs);
   BOTAN_ASSERT_IMPLICATION(
      tls_cs == nullptr, cs == nullptr, "If the cipher state is not a TLS_Cipher_State, it must be null");
   return tls_cs;
}

}  // namespace Botan::TLS

#endif  // BOTAN_TLS_CIPHER_STATE_H_
