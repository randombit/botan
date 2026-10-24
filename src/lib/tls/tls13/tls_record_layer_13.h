/*
* TLS record layer implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_RECORD_LAYER_13_H_
#define BOTAN_TLS_RECORD_LAYER_13_H_

#include <botan/secmem.h>
#include <botan/tls_magic.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tls_record_13.h>
#include <botan/internal/tls_types_13.h>
#include <deque>
#include <memory>
#include <span>

namespace Botan::TLS {

class Cipher_State;
class Policy;

/**
 * Implementation of the TLS 1.3 record protocol layer
 *
 * This component transforms bytes received from the peer into bytes
 * containing plaintext TLS messages and vice versa.
 */
class BOTAN_TEST_API Record_Layer {
   protected:
      explicit Record_Layer(Connection_Side side);

   public:
      virtual ~Record_Layer() = default;
      Record_Layer(const Record_Layer&) = delete;
      Record_Layer& operator=(const Record_Layer&) = delete;
      Record_Layer(Record_Layer&&) = delete;
      Record_Layer& operator=(Record_Layer&&) = delete;

      using ReadResult = variant_append_t<Record, BytesNeeded>;

      /// @name Record Ingestion
      /// @{

      /**
       * Reads data that was received by the peer and stores it internally for further
       * processing during the invocation of `next_record()`.
       *
       * @param data_from_peer  The data to be parsed.
       */
      virtual void copy_data(std::span<const uint8_t> data_from_peer) = 0;

      /**
       * Parses one record off the internal buffer that is being filled using `copy_data`.
       *
       * Return value contains either the number of bytes (`size_t`) needed to proceed
       * with processing TLS records or a single plaintext TLS record content containing
       * higher level protocol or application data.
       *
       * @param cipher_state  Optional pointer to a Cipher_State instance. If provided, the
       *                      cipher_state should be ready to decrypt data. Pass nullptr to
       *                      process plaintext data.
       */
      virtual ReadResult next_record(Cipher_State* cipher_state = nullptr) = 0;

      /// @}

      /// @name Record Preparation
      /// @{

      /**
       * Prepares a record for transmission.
       *
       * The payload passed into this function must fit into a single record,
       * @sa record_payload_size_limit() for the maximum allowed payload size.
       *
       * @param type          The type of the record to be prepared.
       * @param payload       The plaintext payload to be included in the record.
       * @param policy        The TLS policy for record size constraints
       * @param cipher_state  If not nullptr, the record will be encrypted using
       *                      this cipher state. Pass nullptr to prepare a
       *                      plaintext record.
       * @param out           The container the marshalled record is written to
       *
       * @returns The record number (epoch and sequence number) of the
       *          prepared record
       */
      virtual RecordNumber prepare_record(Record_Type type,
                                          std::span<const uint8_t> payload,
                                          const Policy& policy,
                                          Cipher_State* cipher_state,
                                          secure_vector<uint8_t>& out) = 0;

      /// @}

      /**
       * Returns the maximum number of bytes that can be put into a record.
       *
       * Both the specified and negotiated record size limit is taken into
       * account. Depending on the @p cipher_state, the size of the record
       * overhead (e.g. MAC, padding, record header, etc.) is also considered.
       */
      virtual uint16_t record_payload_size_limit(const Policy& policy, Cipher_State* cipher_state = nullptr) const = 0;

      /**
       * Clears any data currently stored in the read buffer. This is typically
       * used for memory cleanup when the peer sent a CloseNotify alert.
       */
      virtual void clear_read_buffer() = 0;

   public:
      /**
       * Set the record size limits as negotiated by the "record_size_limit"
       * extension (RFC 8449). The limits refer to the number of plaintext bytes
       * to be encrypted/decrypted -- INCLUDING the encrypted content type byte
       * introduced with TLS 1.3. The record size limit is _not_ applied to
       * unprotected records. Incoming records that exceed the set limit will
       * result in a fatal alert.
       *
       * @param outgoing_limit  the maximal number of plaintext bytes to be
       *                        sent in a protected record
       * @param incoming_limit  the maximal number of plaintext bytes to be
       *                        accepted in a received protected record
       */
      void set_record_size_limits(uint16_t outgoing_limit, uint16_t incoming_limit);

      uint16_t outgoing_record_size_limit() const noexcept { return m_outgoing_record_size_limit; }

      uint16_t incoming_record_size_limit() const noexcept { return m_incoming_record_size_limit; }

      void disable_receiving_compat_mode() noexcept { m_receiving_compat_mode = false; }

      bool receiving_compat_mode() const noexcept { return m_receiving_compat_mode; }

      Connection_Side side() const noexcept { return m_side; }

   private:
      Connection_Side m_side;

      // Those are either the limits set by the TLS 1.3 specification (RFC 8446),
      // or the ones negotiated via the "record_size_limit" extension (RFC 8449).
      uint16_t m_outgoing_record_size_limit;
      uint16_t m_incoming_record_size_limit;

      // This status flag is required for version validation where the initial
      // records for sending and receiving is handled differently for backward
      // compatibility reasons. (RFC 8446 5.1 regarding "legacy_record_version")
      bool m_receiving_compat_mode;
};

class BOTAN_TEST_API TLS_Record_Layer final : public Record_Layer {
   public:
      explicit TLS_Record_Layer(Connection_Side side);

      void copy_data(std::span<const uint8_t> data) override;
      ReadResult next_record(Cipher_State* cipher_state = nullptr) override;
      RecordNumber prepare_record(Record_Type type,
                                  std::span<const uint8_t> payload,
                                  const Policy& policy,
                                  Cipher_State* cipher_state,
                                  secure_vector<uint8_t>& out) override;

      void clear_read_buffer() override;

      uint16_t record_payload_size_limit(const Policy& policy, Cipher_State* cipher_state = nullptr) const override;

      void disable_sending_compat_mode() noexcept { m_sending_compat_mode = false; }

   private:
      bool m_sending_compat_mode;
      std::deque<Record_TLS> m_incoming_records;
};

}  // namespace Botan::TLS

#endif
