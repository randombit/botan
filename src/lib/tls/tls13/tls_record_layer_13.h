/*
* TLS record layer implementation for TLS 1.3
* (C) 2022 Jack Lloyd
*     2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_RECORD_LAYER_13_H_
#define BOTAN_TLS_RECORD_LAYER_13_H_

#include <optional>
#include <span>
#include <variant>
#include <vector>

#include <botan/secmem.h>
#include <botan/tls_magic.h>
#include <botan/internal/tls_channel_impl.h>

namespace Botan::TLS {

/**
 * Resembles the `TLSPlaintext` structure in RFC 8446 5.1
 * minus the record protocol specifics and ossified bytes.
 */
struct Record {
      Record_Type type;
      secure_vector<uint8_t> fragment;
      std::optional<uint64_t> seq_no;  // unprotected records have no sequence number

      Record(Record_Type record_type, secure_vector<uint8_t> frgmnt) :
            type(record_type), fragment(std::move(frgmnt)), seq_no(std::nullopt) {}
};

using BytesNeeded = size_t;

class Cipher_State;

/**
 * Implementation of the TLS 1.3 record protocol layer
 *
 * This component transforms bytes received from the peer into bytes
 * containing plaintext TLS messages and vice versa.
 */
class BOTAN_TEST_API Record_Layer {
   public:
      Record_Layer(Connection_Side side);

      template <typename ResT>
      using ReadResult = std::variant<BytesNeeded, ResT>;

      /**
       * Reads data that was received by the peer and stores it internally for further
       * processing during the invocation of `next_record()`.
       *
       * @param data_from_peer  The data to be parsed.
       */
      void copy_data(std::span<const uint8_t> data_from_peer);

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
      ReadResult<Record> next_record(Cipher_State* cipher_state = nullptr);

      std::vector<uint8_t> prepare_records(Record_Type type,
                                           std::span<const uint8_t> data,
                                           Cipher_State* cipher_state = nullptr) const;

      /**
       * Clears any data currently stored in the read buffer. This is typically
       * used for memory cleanup when the peer sent a CloseNotify alert.
       */
      void clear_read_buffer() { zap(m_read_buffer); }

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

      void disable_sending_compat_mode() { m_sending_compat_mode = false; }

      void disable_receiving_compat_mode() { m_receiving_compat_mode = false; }

   private:
      std::vector<uint8_t> m_read_buffer;
      Connection_Side m_side;

      // Those are either the limits set by the TLS 1.3 specification (RFC 8446),
      // or the ones negotiated via the "record_size_limit" extension (RFC 8449).
      uint16_t m_outgoing_record_size_limit;
      uint16_t m_incoming_record_size_limit;

      // Those status flags are required for version validation where the initial
      // records for sending and receiving is handled differently for backward
      // compatibility reasons. (RFC 8446 5.1 regarding "legacy_record_version")
      bool m_sending_compat_mode;
      bool m_receiving_compat_mode;
};

}  // namespace Botan::TLS

#endif
