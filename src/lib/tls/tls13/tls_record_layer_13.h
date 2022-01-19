/*
* TLS record layer implementation for TLS 1.3
* (C) 2022 Jack Lloyd
* (C) 2022 Hannes Rantzsch, René Meusel - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_RECORD_LAYER_13_H_
#define BOTAN_TLS_RECORD_LAYER_13_H_

#include <optional>
#include <variant>
#include <vector>

#include <botan/secmem.h>
#include <botan/tls_magic.h>

namespace Botan::TLS {

/**
 * Resembles the `TLSPlaintext` structure in RFC 8446 5.1
 * minus the record protocol specifics and ossified bytes.
 */
struct Record
   {
   Record_Type             type;
   secure_vector<uint8_t>  fragment;
   std::optional<uint64_t> seq_no;  // unprotected records have no sequence number

   Record(Record_Type record_type, secure_vector<uint8_t> frgmnt)
      : type(record_type)
      , fragment(std::move(frgmnt))
      , seq_no(std::nullopt) {}
   };

using BytesNeeded = size_t;

class Cipher_State;

/**
 * Implementation of the TLS 1.3 record protocol layer
 *
 * This component transforms bytes received from the peer into bytes
 * containing plaintext TLS messages and vice versa.
 */
class BOTAN_TEST_API Record_Layer
   {
   public:
      Record_Layer(Connection_Side side);

      template <typename ResT>
      using ReadResult = std::variant<BytesNeeded, ResT>;

      /**
       * Reads data that was received by the peer.
       *
       * Return value contains either the number of bytes (`size_t`) needed to proceed
       * with processing TLS records or a list of plaintext TLS record contents
       * containing higher level protocol or application data.
       *
       * @param data_from_peer  The data to be parsed.
       * @param cipher_state    Optional pointer to a Cipher_State instance. If provided, the
       *                        cipher_state should be ready to decrypt data. Pass nullptr to
       *                        process plaintext data.
       */
      ReadResult<std::vector<Record>> parse_records(const std::vector<uint8_t>& data_from_peer,
                                   Cipher_State* cipher_state=nullptr);

      std::vector<uint8_t> prepare_records(const Record_Type type,
                                           const std::vector<uint8_t>& data,
                                           Cipher_State* cipher_state=nullptr);

      std::vector<uint8_t> prepare_dummy_ccs_record();

   private:
      ReadResult<Record> read_record(Cipher_State* cipher_state);

   private:
      std::vector<uint8_t> m_read_buffer;
      Connection_Side      m_side;
      bool                 m_initial_record;
   };

}

#endif
