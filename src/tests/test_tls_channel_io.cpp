/*
* Integration tests for the TLS 1.3 Channel_IO
* (C) 2026 Jack Lloyd
*     2026 Amos Treiber, René Meusel - Rohde & Schwarz Networks and Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_TLS_13)

   #include <botan/exceptn.h>
   #include <botan/hex.h>
   #include <botan/tls_alert.h>
   #include <botan/tls_callbacks.h>
   #include <botan/tls_ciphersuite.h>
   #include <botan/tls_exceptn.h>
   #include <botan/tls_magic.h>
   #include <botan/tls_messages_13.h>
   #include <botan/tls_policy.h>
   #include <botan/internal/buffer_slicer.h>
   #include <botan/internal/concat_util.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/tls_channel_io.h>
   #include <botan/internal/tls_cipher_state.h>
   #include <botan/internal/tls_flight_13.h>
   #include <botan/internal/tls_handshake_layer_13.h>
   #include <botan/internal/tls_record_13.h>
   #include <botan/internal/tls_transcript_hash_13.h>
   #include <algorithm>
   #include <functional>
   #include <memory>
   #include <optional>
   #include <vector>

namespace Botan_Tests {

namespace {

namespace TLS = Botan::TLS;

class Mock_Callbacks final : public TLS::Callbacks {
   public:
      void tls_emit_data(std::span<const uint8_t> data) override {
         m_emitted_chunks.emplace_back(data.begin(), data.end());
      }

      void tls_record_received(uint64_t /*seq_no*/, std::span<const uint8_t> /*data*/) override {
         throw Botan::Invalid_State("Channel_IO does not invoke tls_record_received");
      }

      void tls_alert(TLS::Alert alert) override { m_alerts.push_back(alert); }

      void tls_inspect_handshake_msg(const TLS::Handshake_Message& message) override {
         m_inspected_types.push_back(message.type());
      }

      /// All invocations of tls_emit_data() as individual chunks
      const std::vector<std::vector<uint8_t>>& emitted_chunks() const { return m_emitted_chunks; }

      /// Concatenation of all data ever passed to tls_emit_data()
      std::vector<uint8_t> emitted() const {
         std::vector<uint8_t> result;
         for(const auto& chunk : m_emitted_chunks) {
            result.insert(result.end(), chunk.begin(), chunk.end());
         }
         return result;
      }

      void clear_emitted() { m_emitted_chunks.clear(); }

      const std::vector<TLS::Handshake_Type>& inspected_types() const { return m_inspected_types; }

   private:
      std::vector<std::vector<uint8_t>> m_emitted_chunks;
      std::vector<TLS::Alert> m_alerts;
      std::vector<TLS::Handshake_Type> m_inspected_types;
};

class Test_Policy : public Botan::TLS::Policy {
   public:
      explicit Test_Policy(std::function<size_t(size_t)> record_padding = {}) :
            m_record_padding(std::move(record_padding)) {}

      size_t record_padding_bytes(size_t plaintext_bytes) const override {
         return m_record_padding ? m_record_padding(plaintext_bytes) : 0;
      }

      // The RFC 8448 test vectors use a 1024-bit RSA server certificate
      size_t minimum_rsa_bits() const override { return 1024; }

   private:
      std::function<size_t(size_t)> m_record_padding;
};

std::function<size_t(size_t)> pad_to_minimum_size(size_t minimum_record_size) {
   return [=](size_t plaintext_bytes) {
      return (plaintext_bytes < minimum_record_size) ? minimum_record_size - plaintext_bytes : 0;
   };
}

std::shared_ptr<TLS::Channel_IO> make_channel_io(
   TLS::Connection_Side side,
   const std::shared_ptr<Mock_Callbacks>& callbacks,
   std::shared_ptr<const TLS::Policy> policy = std::make_shared<Test_Policy>()) {
   return TLS::Channel_IO::create(side, TLS::TLS_Flavor::TLS, std::move(policy), callbacks);
}

std::optional<TLS::Transcript_Hash_State> make_transcript_hash() {
   return TLS::Transcript_Hash_State(TLS::TLS_Flavor::TLS, "SHA-256");
}

/**
 * Pulls events off the channel until no more are pending.
 * Returns the events along with the terminal BytesNeeded value.
 */
struct Drained_Events {
      std::vector<TLS::Channel_IO::ReceiveEvent> events;
      TLS::BytesNeeded bytes_needed = 0;
};

Drained_Events drain_events(TLS::Channel_IO& io,
                            std::optional<TLS::Transcript_Hash_State>& transcript_hash,
                            bool handshake_complete) {
   Drained_Events drained;
   while(true) {
      auto event = io.next_pending_event(transcript_hash, handshake_complete);
      if(std::holds_alternative<TLS::BytesNeeded>(event)) {
         drained.bytes_needed = std::get<TLS::BytesNeeded>(event);
         return drained;
      }
      drained.events.emplace_back(std::move(event));
   }
}

/// Minimal record header view for high-level assertions on emitted data
struct Record_Header {
      Botan::TLS::Record_Type type;
      uint16_t version;
      uint16_t payload_length;
      size_t payload_offset;  // Absolute offset of the payload in the parsed buffer
};

std::vector<Record_Header> record_headers(std::span<const uint8_t> buffer) {
   std::vector<Record_Header> result;
   Botan::BufferSlicer slicer(buffer);
   while(slicer.remaining() >= TLS::TLS_HEADER_SIZE) {
      const size_t offset = buffer.size() - slicer.remaining();
      const auto header = slicer.take<TLS::TLS_HEADER_SIZE>();
      const auto length = Botan::load_be(header.subspan<3, 2>());
      if(slicer.remaining() < length) {
         break;  // Truncated record; assertions on the result will fail
      }
      result.push_back({Botan::TLS::Record_Type(header[0]),
                        Botan::load_be(header.subspan<1, 2>()),
                        length,
                        offset + TLS::TLS_HEADER_SIZE});
      slicer.skip(length);
   }
   return result;
}

bool all_records_have_version(const std::vector<Record_Header>& headers, uint16_t version) {
   return std::all_of(headers.begin(), headers.end(), [&](const auto& header) { return header.version == version; });
}

bool all_records_have_type(const std::vector<Record_Header>& headers, TLS::Record_Type type) {
   return std::all_of(headers.begin(), headers.end(), [&](const auto& header) { return header.type == type; });
}

namespace rfc8448 {

// Operative test data and cipher state key material from
// RFC 8448, Section 3 ("Simple 1-RTT Handshake")

constexpr std::string_view shared_secret =
   "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d"
   "35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d";

// Transcript hash over the client hello handshake message
constexpr std::string_view th_client_hello =
   "4d b2 55 f3 0d a0 9a 40 7c 84 17 20 be 83 1a 06"
   "a5 aa 9b 36 62 a5 f4 42 67 d3 77 06 b7 3c 2b 8c";

// Transcript hash over client_hello ... server_hello
constexpr std::string_view th_server_hello =
   "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed"
   "d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8";

// Transcript hash over client_hello ... server Finished
constexpr std::string_view th_server_finished =
   "96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a"
   "00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13";

// Transcript hash over client_hello ... client Finished
constexpr std::string_view th_client_finished =
   "20 91 45 a9 6e e8 e2 a1 22 ff 81 00 47 cc 95 26"
   "84 65 8d 60 49 e8 64 29 42 6d b8 7c 54 ad 14 3d";

constexpr std::string_view client_hello_record =
   "16 03 01 00 c4 01 00 00 c0 03 03 cb"
   "34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12"
   "ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00"
   "00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
   "00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02"
   "01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d"
   "e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d"
   "54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e"
   "04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02"
   "01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";

// The client hello handshake message body (without the handshake protocol header)
constexpr std::string_view client_hello_body =
   "03 03 cb"
   "34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12"
   "ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00"
   "00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
   "00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02"
   "01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d"
   "e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d"
   "54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e"
   "04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02"
   "01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";

constexpr std::string_view server_hello_record =
   "16 03 03 00 5a 02 00 00 56 03 03 a6"
   "af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14"
   "34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00"
   "1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6"
   "cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04";

// The server hello handshake message (including the handshake protocol header)
constexpr std::string_view server_hello_message =
   "02 00 00 56 03 03 a6"
   "af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14"
   "34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00"
   "1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6"
   "cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04";

constexpr std::string_view encrypted_extensions_message =
   "08 00 00 24 00 22 00 0a 00 14 00 12 00 1d"
   "00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c 00 02 40"
   "01 00 00 00 00";

constexpr std::string_view server_handshake_messages_record =
   "17 03 03 02 a2 d1 ff 33 4a 56 f5 bf"
   "f6 59 4a 07 cc 87 b5 80 23 3f 50 0f 45 e4 89 e7 f3 3a f3 5e df"
   "78 69 fc f4 0a a4 0a a2 b8 ea 73 f8 48 a7 ca 07 61 2e f9 f9 45"
   "cb 96 0b 40 68 90 51 23 ea 78 b1 11 b4 29 ba 91 91 cd 05 d2 a3"
   "89 28 0f 52 61 34 aa dc 7f c7 8c 4b 72 9d f8 28 b5 ec f7 b1 3b"
   "d9 ae fb 0e 57 f2 71 58 5b 8e a9 bb 35 5c 7c 79 02 07 16 cf b9"
   "b1 18 3e f3 ab 20 e3 7d 57 a6 b9 d7 47 76 09 ae e6 e1 22 a4 cf"
   "51 42 73 25 25 0c 7d 0e 50 92 89 44 4c 9b 3a 64 8f 1d 71 03 5d"
   "2e d6 5b 0e 3c dd 0c ba e8 bf 2d 0b 22 78 12 cb b3 60 98 72 55"
   "cc 74 41 10 c4 53 ba a4 fc d6 10 92 8d 80 98 10 e4 b7 ed 1a 8f"
   "d9 91 f0 6a a6 24 82 04 79 7e 36 a6 a7 3b 70 a2 55 9c 09 ea d6"
   "86 94 5b a2 46 ab 66 e5 ed d8 04 4b 4c 6d e3 fc f2 a8 94 41 ac"
   "66 27 2f d8 fb 33 0e f8 19 05 79 b3 68 45 96 c9 60 bd 59 6e ea"
   "52 0a 56 a8 d6 50 f5 63 aa d2 74 09 96 0d ca 63 d3 e6 88 61 1e"
   "a5 e2 2f 44 15 cf 95 38 d5 1a 20 0c 27 03 42 72 96 8a 26 4e d6"
   "54 0c 84 83 8d 89 f7 2c 24 46 1a ad 6d 26 f5 9e ca ba 9a cb bb"
   "31 7b 66 d9 02 f4 f2 92 a3 6a c1 b6 39 c6 37 ce 34 31 17 b6 59"
   "62 22 45 31 7b 49 ee da 0c 62 58 f1 00 d7 d9 61 ff b1 38 64 7e"
   "92 ea 33 0f ae ea 6d fa 31 c7 a8 4d c3 bd 7e 1b 7a 6c 71 78 af"
   "36 87 90 18 e3 f2 52 10 7f 24 3d 24 3d c7 33 9d 56 84 c8 b0 37"
   "8b f3 02 44 da 8c 87 c8 43 f5 e5 6e b4 c5 e8 28 0a 2b 48 05 2c"
   "f9 3b 16 49 9a 66 db 7c ca 71 e4 59 94 26 f7 d4 61 e6 6f 99 88"
   "2b d8 9f c5 08 00 be cc a6 2d 6c 74 11 6d bd 29 72 fd a1 fa 80"
   "f8 5d f8 81 ed be 5a 37 66 89 36 b3 35 58 3b 59 91 86 dc 5c 69"
   "18 a3 96 fa 48 a1 81 d6 b6 fa 4f 9d 62 d5 13 af bb 99 2f 2b 99"
   "2f 67 f8 af e6 7f 76 91 3f a3 88 cb 56 30 c8 ca 01 e0 c6 5d 11"
   "c6 6a 1e 2a c4 c8 59 77 b7 c7 a6 99 9b bf 10 dc 35 ae 69 f5 51"
   "56 14 63 6c 0b 9b 68 c1 9e d2 e3 1c 0b 3b 66 76 30 38 eb ba 42"
   "f3 b3 8e dc 03 99 f3 a9 f2 3f aa 63 97 8c 31 7f c9 fa 66 a7 3f"
   "60 f0 50 4d e9 3b 5b 84 5e 27 55 92 c1 23 35 ee 34 0b bc 4f dd"
   "d5 02 78 40 16 e4 b3 be 7e f0 4d da 49 f4 b4 40 a3 0c b5 d2 af"
   "93 98 28 fd 4a e3 79 4e 44 f9 4d f5 a6 31 ed e4 2c 17 19 bf da"
   "bf 02 53 fe 51 75 be 89 8e 75 0e dc 53 37 0d 2b";

constexpr std::string_view client_finished_record =
   "17 03 03 00 35 75 ec 4d c2 38 cc e6"
   "0b 29 80 44 a7 1e 21 9c 56 cc 77 b0 51 7f e9 b9 3c 7a 4b fc 44"
   "d8 7f 38 f8 03 38 ac 98 fc 46 de b3 84 bd 1c ae ac ab 68 67 d7"
   "26 c4 05 46";

constexpr std::string_view new_session_ticket_record =
   "17 03 03 00 de 3a 6b 8f 90 41 4a 97"
   "d6 95 9c 34 87 68 0d e5 13 4a 2b 24 0e 6c ff ac 11 6e 95 d4 1d"
   "6a f8 f6 b5 80 dc f3 d1 1d 63 c7 58 db 28 9a 01 59 40 25 2f 55"
   "71 3e 06 1d c1 3e 07 88 91 a3 8e fb cf 57 53 ad 8e f1 70 ad 3c"
   "73 53 d1 6d 9d a7 73 b9 ca 7f 2b 9f a1 b6 c0 d4 a3 d0 3f 75 e0"
   "9c 30 ba 1e 62 97 2a c4 6f 75 f7 b9 81 be 63 43 9b 29 99 ce 13"
   "06 46 15 13 98 91 d5 e4 c5 b4 06 f1 6e 3f c1 81 a7 7c a4 75 84"
   "00 25 db 2f 0a 77 f8 1b 5a b0 5b 94 c0 13 46 75 5f 69 23 2c 86"
   "51 9d 86 cb ee ac 87 aa c3 47 d1 43 f9 60 5d 64 f6 50 db 4d 02"
   "3e 70 e9 52 ca 49 fe 51 37 12 1c 74 bc 26 97 68 7e 24 87 46 d6"
   "df 35 30 05 f3 bc e1 86 96 12 9c 81 53 55 6b 3b 6c 67 79 b3 7b"
   "f1 59 85 68 4f";

constexpr std::string_view app_data =
   "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e"
   "0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23"
   "24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31";

constexpr std::string_view client_app_data_record =
   "17 03 03 00 43 a2 3f 70 54 b6 2c 94"
   "d0 af fa fe 82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab 3f 2b"
   "98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b 62 97 4e 1f 5a 62"
   "92 a2 97 70 14 bd 1e 3d ea e6 3a ee bb 21 69 49 15 e4";

constexpr std::string_view server_app_data_record =
   "17 03 03 00 43 2e 93 7e 11 ef 4a c7"
   "40 e5 38 ad 36 00 5f c4 a4 69 32 fc 32 25 d0 5f 82 aa 1b 36 e3"
   "0e fa f9 7d 90 e6 df fc 60 2d cb 50 1a 59 a8 fc c4 9c 4b f2 e5"
   "f0 a2 1c 00 47 c2 ab f3 32 54 0d d0 32 e1 67 c2 95 5d";

constexpr std::string_view client_close_notify_record =
   "17 03 03 00 13 c9 87 27 60 65 56 66 b7 4d 7f f1 15 3e fd 6d b6 d0 b0 e3";

constexpr std::string_view ccs_record = "14 03 03 00 01 01";

}  // namespace rfc8448

/// Cipher state used within the tests, manually steering the cipher epochs
// (not done by Channel_IO but necessary for the tests).
std::shared_ptr<TLS::Cipher_State> rfc8448_handshake_traffic(TLS::Connection_Side side) {
   const auto cipher = TLS::Ciphersuite::from_name("AES_128_GCM_SHA256").value();
   return TLS::Cipher_State::init_with_server_hello(side,
                                                    TLS::TLS_Flavor::TLS,
                                                    Botan::hex_decode_locked(rfc8448::shared_secret),
                                                    cipher,
                                                    Botan::hex_decode(rfc8448::th_server_hello),
                                                    {});
}

/// Cipher state holding the RFC 8448 application traffic keys
/// (advanced past both Finished messages).
std::shared_ptr<TLS::Cipher_State> rfc8448_application_traffic(TLS::Connection_Side side) {
   const auto cs = rfc8448_handshake_traffic(side);
   cs->advance_with_server_finished(Botan::hex_decode(rfc8448::th_server_finished));
   cs->advance_with_client_finished(Botan::hex_decode(rfc8448::th_client_finished));
   BOTAN_ASSERT_NOMSG(cs->can_encrypt_application_traffic());
   BOTAN_ASSERT_NOMSG(cs->can_decrypt_application_traffic());
   return cs;
}

std::vector<Test::Result> receive_unprotected_records() {
   return {
      CHECK("empty input yields BytesNeeded(0)",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Server, callbacks);
               auto th = make_transcript_hash();

               const auto drained = drain_events(*io, th, false);
               result.test_sz_eq("no events", drained.events.size(), 0);
               result.test_sz_eq("no bytes needed", drained.bytes_needed, 0);
            }),

      CHECK("receive client hello in one record",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Server, callbacks);
               auto th = make_transcript_hash();

               io->copy_data(Botan::hex_decode(rfc8448::client_hello_record));
               const auto drained = drain_events(*io, th, false);

               result.require("one event", drained.events.size() == 1);
               result.require("event is a handshake message",
                              std::holds_alternative<TLS::Handshake_Message_13>(drained.events.front()));
               result.test_is_true("event is a client hello",
                                   std::holds_alternative<TLS::Client_Hello_13>(
                                      std::get<TLS::Handshake_Message_13>(drained.events.front())));
               result.test_sz_eq("no more bytes needed", drained.bytes_needed, 0);
               result.test_bin_eq("transcript hash was updated with the client hello",
                                  th->current(),
                                  Botan::hex_decode(rfc8448::th_client_hello));
            }),

      CHECK("receive client hello in fragments",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Server, callbacks);
               auto th = make_transcript_hash();

               const auto record = Botan::hex_decode(rfc8448::client_hello_record);

               io->copy_data(std::span{record}.first(3));
               auto drained = drain_events(*io, th, false);
               result.test_sz_eq("no events yet", drained.events.size(), 0);
               result.test_sz_eq(
                  "missing bytes to complete the header", drained.bytes_needed, TLS::TLS_HEADER_SIZE - 3);

               io->copy_data(std::span{record}.subspan(3, 2));
               drained = drain_events(*io, th, false);
               result.test_sz_eq("no events yet", drained.events.size(), 0);
               result.test_sz_eq("missing payload bytes", drained.bytes_needed, record.size() - TLS::TLS_HEADER_SIZE);

               const auto partial_length = 100;
               io->copy_data(std::span{record}.subspan(TLS::TLS_HEADER_SIZE, partial_length));
               drained = drain_events(*io, th, false);
               result.test_sz_eq("no events yet", drained.events.size(), 0);
               result.test_sz_eq(
                  "missing payload bytes", drained.bytes_needed, record.size() - TLS::TLS_HEADER_SIZE - partial_length);

               io->copy_data(std::span{record}.subspan(TLS::TLS_HEADER_SIZE + partial_length));
               drained = drain_events(*io, th, false);
               result.require("one event", drained.events.size() == 1);
               result.require("event is a handshake message",
                              std::holds_alternative<TLS::Handshake_Message_13>(drained.events.front()));
               result.test_is_true("event is a client hello",
                                   std::holds_alternative<TLS::Client_Hello_13>(
                                      std::get<TLS::Handshake_Message_13>(drained.events.front())));
               result.test_sz_eq("no more bytes needed", drained.bytes_needed, 0);
            }),

      CHECK("receive change cipher spec record",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Server, callbacks);
               auto th = make_transcript_hash();

               io->copy_data(Botan::hex_decode(rfc8448::ccs_record));
               const auto drained = drain_events(*io, th, false);

               result.require("one event", drained.events.size() == 1);
               result.require("event is a CCS record",
                              std::holds_alternative<TLS::ChangeCipherSpec_Record>(drained.events.front()));
               result.test_bin_eq(
                  "CCS byte is 0x01", std::get<TLS::ChangeCipherSpec_Record>(drained.events.front()).payload, "01");
               result.test_sz_eq("no more bytes needed", drained.bytes_needed, 0);
            }),

      CHECK("receive client hello followed by coalesced CCS",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Server, callbacks);
               auto th = make_transcript_hash();

               io->copy_data(Botan::concat(Botan::hex_decode(rfc8448::client_hello_record),
                                           Botan::hex_decode(rfc8448::ccs_record)));
               const auto drained = drain_events(*io, th, false);

               result.require("two events", drained.events.size() == 2);
               result.require("first event is a handshake message",
                              std::holds_alternative<TLS::Handshake_Message_13>(drained.events.at(0)));
               result.test_is_true("first event is a client hello",
                                   std::holds_alternative<TLS::Client_Hello_13>(
                                      std::get<TLS::Handshake_Message_13>(drained.events.at(0))));
               result.test_is_true("second event is a CCS record",
                                   std::holds_alternative<TLS::ChangeCipherSpec_Record>(drained.events.at(1)));
               result.test_sz_eq("no more bytes needed", drained.bytes_needed, 0);
            }),

      CHECK("notify_closed_for_reading discards a partially received record",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Server, callbacks);
               auto th = make_transcript_hash();

               const auto ch = Botan::hex_decode(rfc8448::client_hello_record);
               io->copy_data(std::span(ch).first(ch.size() / 2));
               result.test_is_true("partial record yields BytesNeeded", drain_events(*io, th, false).bytes_needed > 0);

               // Discards the pending partial record from the read buffer
               io->notify_closed_for_reading();

               // ... such that a subsequently received record is ignored
               io->copy_data(ch);
               const auto drained = drain_events(*io, th, false);
               result.require("no more events", drained.events.empty());
            }),

      CHECK("client receives server hello",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Client, callbacks);
               auto th = make_transcript_hash();

               io->copy_data(Botan::hex_decode(rfc8448::server_hello_record));
               const auto drained = drain_events(*io, th, false);

               result.require("one event", drained.events.size() == 1);
               result.require("event is a handshake message",
                              std::holds_alternative<TLS::Handshake_Message_13>(drained.events.front()));
               result.test_is_true("event is a server hello",
                                   std::holds_alternative<TLS::Server_Hello_13>(
                                      std::get<TLS::Handshake_Message_13>(drained.events.front())));
               result.test_sz_eq("no more bytes needed", drained.bytes_needed, 0);
            }),
   };
}

std::vector<Test::Result> receive_protected_records() {
   return {
   #if defined(BOTAN_HAS_RSA)
      CHECK("client receives the encrypted handshake flight",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Client, callbacks);
               auto th = make_transcript_hash();

               // Epoch steering: install the handshake traffic keys
               const auto cs = rfc8448_handshake_traffic(TLS::Connection_Side::Client);
               io->set_cipher_state(cs);

               io->copy_data(Botan::hex_decode(rfc8448::server_handshake_messages_record));
               const auto drained_flight = drain_events(*io, th, false);

               result.require("four events", drained_flight.events.size() == 4);
               result.require(
                  "all events are handshake messages",
                  std::all_of(drained_flight.events.begin(), drained_flight.events.end(), [](const auto& e) {
                     return std::holds_alternative<TLS::Handshake_Message_13>(e);
                  }));
               result.test_is_true("event 1 is encrypted extensions",
                                   std::holds_alternative<TLS::Encrypted_Extensions>(
                                      std::get<TLS::Handshake_Message_13>(drained_flight.events.at(0))));
               result.test_is_true("event 2 is certificate",
                                   std::holds_alternative<TLS::Certificate_13>(
                                      std::get<TLS::Handshake_Message_13>(drained_flight.events.at(1))));
               result.test_is_true("event 3 is certificate verify",
                                   std::holds_alternative<TLS::Certificate_Verify_13>(
                                      std::get<TLS::Handshake_Message_13>(drained_flight.events.at(2))));
               result.test_is_true("event 4 is finished",
                                   std::holds_alternative<TLS::Finished_13>(
                                      std::get<TLS::Handshake_Message_13>(drained_flight.events.at(3))));
               result.test_sz_eq("no more bytes needed", drained_flight.bytes_needed, 0);
            }),
   #endif

         CHECK("server receives encrypted client finished",
               [&](Test::Result& result) {
                  const auto callbacks = std::make_shared<Mock_Callbacks>();
                  const auto io = make_channel_io(TLS::Connection_Side::Server, callbacks);
                  auto th = make_transcript_hash();

                  // Epoch steering: install the handshake traffic keys
                  const auto cs = rfc8448_handshake_traffic(TLS::Connection_Side::Server);
                  io->set_cipher_state(cs);

                  io->copy_data(Botan::hex_decode(rfc8448::client_finished_record));
                  const auto drained = drain_events(*io, th, false);

                  result.require("one event", drained.events.size() == 1);
                  result.require("event is a handshake message",
                                 std::holds_alternative<TLS::Handshake_Message_13>(drained.events.front()));
                  result.test_is_true("event is a finished",
                                      std::holds_alternative<TLS::Finished_13>(
                                         std::get<TLS::Handshake_Message_13>(drained.events.front())));
                  result.test_sz_eq("no more bytes needed", drained.bytes_needed, 0);
               }),

         CHECK("receive post-handshake new session ticket and application data",
               [&](Test::Result& result) {
                  const auto callbacks = std::make_shared<Mock_Callbacks>();
                  const auto io = make_channel_io(TLS::Connection_Side::Client, callbacks);
                  auto th = make_transcript_hash();

                  // Epoch steering: install the application traffic keys
                  const auto cs = rfc8448_application_traffic(TLS::Connection_Side::Client);
                  io->set_cipher_state(cs);

                  // Feed the records in RFC order to match the sequence numbers
                  // the RFC 8448 transcripts were produced with
                  io->copy_data(Botan::concat(Botan::hex_decode(rfc8448::new_session_ticket_record),
                                              Botan::hex_decode(rfc8448::server_app_data_record)));
                  const auto drained = drain_events(*io, th, true /* handshake complete */);

                  result.require("two events", drained.events.size() == 2);
                  result.require("first event is a post-handshake message",
                                 std::holds_alternative<TLS::Post_Handshake_Message_13>(drained.events.at(0)));
                  result.test_is_true("first event is a new session ticket",
                                      std::holds_alternative<TLS::New_Session_Ticket_13>(
                                         std::get<TLS::Post_Handshake_Message_13>(drained.events.at(0))));

                  result.require("second event is application data",
                                 std::holds_alternative<TLS::ApplicationData_Record>(drained.events.at(1)));
                  result.test_bin_eq("application payload",
                                     std::get<TLS::ApplicationData_Record>(drained.events.at(1)).payload,
                                     Botan::hex_decode(rfc8448::app_data));
                  result.test_sz_eq("no more bytes needed", drained.bytes_needed, 0);
               }),

         CHECK("receive application data and close-notify alert",
               [&](Test::Result& result) {
                  const auto callbacks = std::make_shared<Mock_Callbacks>();
                  const auto io = make_channel_io(TLS::Connection_Side::Server, callbacks);
                  auto th = make_transcript_hash();

                  // Epoch steering: install the application traffic keys
                  const auto cs = rfc8448_application_traffic(TLS::Connection_Side::Server);
                  io->set_cipher_state(cs);

                  // Feed the records in RFC order to match the sequence numbers
                  // the RFC 8448 transcripts were produced with
                  io->copy_data(Botan::concat(Botan::hex_decode(rfc8448::client_app_data_record),
                                              Botan::hex_decode(rfc8448::client_close_notify_record)));
                  const auto drained = drain_events(*io, th, true /* handshake complete */);

                  result.require("two events", drained.events.size() == 2);

                  result.require("first event is application data",
                                 std::holds_alternative<TLS::ApplicationData_Record>(drained.events.at(0)));
                  result.test_bin_eq("application payload",
                                     std::get<TLS::ApplicationData_Record>(drained.events.at(0)).payload,
                                     Botan::hex_decode(rfc8448::app_data));

                  result.require("second event is an alert",
                                 std::holds_alternative<TLS::Alert_Record>(drained.events.at(1)));
                  const TLS::Alert alert(std::get<TLS::Alert_Record>(drained.events.at(1)).payload);
                  result.test_enum_eq("alert is close-notify", alert.type(), TLS::AlertType::CloseNotify);
                  result.test_is_false("close-notify is not fatal", alert.is_fatal());
                  result.test_sz_eq("no more bytes needed", drained.bytes_needed, 0);
               }),

         CHECK("receive fragmented application data record", [&](Test::Result& result) {
            const auto callbacks = std::make_shared<Mock_Callbacks>();
            const auto io = make_channel_io(TLS::Connection_Side::Server, callbacks);
            auto th = make_transcript_hash();

            // Epoch steering: install the application traffic keys
            const auto cs = rfc8448_application_traffic(TLS::Connection_Side::Server);
            io->set_cipher_state(cs);

            const auto record = Botan::hex_decode(rfc8448::client_app_data_record);

            io->copy_data(std::span{record}.first(3));
            auto drained = drain_events(*io, th, true);
            result.test_sz_eq("missing bytes to complete the header", drained.bytes_needed, TLS::TLS_HEADER_SIZE - 3);

            io->copy_data(std::span{record}.subspan(3, 2));
            drained = drain_events(*io, th, true);
            result.test_sz_eq("missing payload bytes", drained.bytes_needed, record.size() - TLS::TLS_HEADER_SIZE);

            const auto partial_length = 30;
            io->copy_data(std::span{record}.subspan(TLS::TLS_HEADER_SIZE, partial_length));
            drained = drain_events(*io, th, true);
            result.test_sz_eq(
               "missing payload bytes", drained.bytes_needed, record.size() - TLS::TLS_HEADER_SIZE - partial_length);

            io->copy_data(std::span{record}.subspan(TLS::TLS_HEADER_SIZE + partial_length));
            drained = drain_events(*io, th, true);
            result.require("one event", drained.events.size() == 1);
            result.require("event is application data",
                           std::holds_alternative<TLS::ApplicationData_Record>(drained.events.front()));
            result.test_bin_eq("application payload",
                               std::get<TLS::ApplicationData_Record>(drained.events.front()).payload,
                               Botan::hex_decode(rfc8448::app_data));
         }),
   };
}

std::vector<Test::Result> receive_error_cases() {
   return {

      CHECK("handshake message preceding a key change must align with a record boundary",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Client, callbacks);
               auto th = make_transcript_hash();

               // A single record containing the server hello immediately followed
               // by another handshake message (RFC 8446 5.1 violation)
               const auto payload = Botan::concat(Botan::hex_decode(rfc8448::server_hello_message),
                                                  Botan::hex_decode(rfc8448::encrypted_extensions_message));
               auto record = Botan::concat<std::vector<uint8_t>>(std::array<uint8_t, 3>{0x16, 0x03, 0x03},
                                                                 Botan::store_be(static_cast<uint16_t>(payload.size())),
                                                                 payload);

               io->copy_data(record);
               result.test_throws("server hello must not be followed by more data in the same record",
                                  "Unexpected additional handshake message data found in record",
                                  [&] { drain_events(*io, th, false); });
            }),

      CHECK("handshake messages must not be interleaved with other record types",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Server, callbacks);
               auto th = make_transcript_hash();

               // A record containing only the first half of the client hello
               // handshake message, followed by a CCS record
               const auto ch = Botan::hex_decode(rfc8448::client_hello_record);
               const auto partial_length = uint16_t(100);
               const auto partial_record =
                  Botan::concat<std::vector<uint8_t>>(std::array<uint8_t, 3>{0x16, 0x03, 0x03},
                                                      Botan::store_be(partial_length),
                                                      std::span(ch).subspan(TLS::TLS_HEADER_SIZE, partial_length));

               io->copy_data(Botan::concat(partial_record, Botan::hex_decode(rfc8448::ccs_record)));
               result.test_throws("CCS record interleaved with partial handshake message",
                                  "Expected remainder of a handshake message",
                                  [&] { drain_events(*io, th, false); });

               // The same must happen for any other non-handshake record
               const auto io2 = make_channel_io(TLS::Connection_Side::Server, callbacks);
               auto th2 = make_transcript_hash();
               const auto warning_alert_record = Botan::concat<std::vector<uint8_t>>(
                  std::array<uint8_t, 3>{0x15, 0x03, 0x03},
                  Botan::store_be(uint16_t(2)),
                  std::array<uint8_t, 2>{0x01, 0x70});  // warning alert: no_renegotiation (100)
               io2->copy_data(Botan::concat(partial_record, warning_alert_record));
               result.test_throws("alert record interleaved with partial handshake message",
                                  "Expected remainder of a handshake message",
                                  [&] { drain_events(*io2, th2, false); });
            }),

      CHECK("legacy record version 0x0301 is rejected after the first handshake message",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Server, callbacks);
               auto th = make_transcript_hash();

               io->copy_data(Botan::hex_decode(rfc8448::client_hello_record));
               const auto drained = drain_events(*io, th, false);
               result.require("client hello was delivered", drained.events.size() == 1);

               // After the first handshake message was delivered, the record layer
               // must not accept legacy versions other than 0x0303 anymore
               result.test_throws(
                  "0x0301 not okay once client hello was received", "Received unexpected record version", [&] {
                     io->copy_data(Botan::hex_decode("16 03 01 00 01 42"));
                     drain_events(*io, th, false);
                  });
            }),
   };
}

std::vector<Test::Result> send_flights() {
   return {
      CHECK("client's first flight uses legacy version 0x0301 (even when sharded)",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Client, callbacks);

               // A large synthetic handshake message that cannot fit into a
               // single record (a flight that big does not need to be produced
               // via the Flight helper, Channel_IO only sees the marshalled form)
               const size_t message_size = TLS::MAX_PLAINTEXT_SIZE + 4096;
               const TLS::Flight::Message_Info big_message{
                  .wire_type = TLS::Handshake_Type::Certificate,
                  .epoch = TLS::EpochNumber::Unprotected,
                  .header = TLS::TLS_Handshake_Layer::prepare_header(TLS::Handshake_Type::Certificate, message_size),
                  .serialized = TLS::SerializedHandshakeMessage(std::vector<uint8_t>(message_size)),
               };

               io->send({big_message});

               const auto headers = record_headers(callbacks->emitted());
               result.test_sz_eq("large message was sharded into two records", headers.size(), 2);
               result.test_is_true("all records of the first flight carry version 0x0301",
                                   all_records_have_version(headers, 0x0301));
               result.test_is_true("all records are handshake records",
                                   all_records_have_type(headers, TLS::Record_Type::Handshake));
               result.test_is_true("no record exceeds the plaintext limit",
                                   std::all_of(headers.begin(), headers.end(), [](const auto& header) {
                                      return header.payload_length <= TLS::MAX_PLAINTEXT_SIZE;
                                   }));

               // After the first handshake message was sent, subsequent records
               // must use version 0x0303
               callbacks->clear_emitted();
               const TLS::Flight::Message_Info small_message{
                  .wire_type = TLS::Handshake_Type::Finished,
                  .epoch = TLS::EpochNumber::Unprotected,
                  .header = TLS::TLS_Handshake_Layer::prepare_header(TLS::Handshake_Type::Finished, 5),
                  .serialized = TLS::SerializedHandshakeMessage(std::vector<uint8_t>(5)),
               };
               io->send({small_message});

               const auto headers_after = record_headers(callbacks->emitted());
               result.test_sz_eq("one record", headers_after.size(), 1);
               result.test_is_true("subsequent records carry version 0x0303",
                                   all_records_have_version(headers_after, 0x0303));
            }),

      CHECK("dummy CCS in a flight first sends pending handshake messages",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Client, callbacks);
               auto th = make_transcript_hash();

               auto client_hello = std::get<TLS::Client_Hello_13>(
                  TLS::Client_Hello_13::parse(Botan::hex_decode(rfc8448::client_hello_body)));
               auto flight = TLS::Flight(*th, *callbacks).add(client_hello).add_dummy_change_cipher_spec();

               io->send(flight.commit());

               const auto headers = record_headers(callbacks->emitted());
               result.test_sz_eq("two records emitted", headers.size(), 2);
               result.test_enum_eq(
                  "first record is a handshake record", headers.at(0).type, TLS::Record_Type::Handshake);

               result.test_enum_eq(
                  "second record is the dummy CCS record", headers.at(1).type, TLS::Record_Type::ChangeCipherSpec);
            }),

      // TODO: Add a similar test for the first server flight, once we support
      //       coalesced flights over multiple epochs
      //
      // (i.e. ServerHello + CCS + [EncryptedExtensions + ... + Finished]).
   };
}

std::vector<Test::Result> send_application_data() {
   return {
      CHECK("send application data",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Client, callbacks);

               // Epoch steering: install the application traffic keys
               const auto cs = rfc8448_application_traffic(TLS::Connection_Side::Client);
               io->set_cipher_state(cs);

               // First record under the client application traffic secret (seq 0),
               // hence byte-identical to the RFC 8448 transcript
               io->send(Botan::hex_decode(rfc8448::app_data));

               result.test_bin_eq("emitted record matches RFC 8448",
                                  callbacks->emitted(),
                                  Botan::hex_decode(rfc8448::client_app_data_record));
            }),

      CHECK("write a lot of data producing two protected records",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Client, callbacks);

               const auto cs = rfc8448_application_traffic(TLS::Connection_Side::Client);
               io->set_cipher_state(cs);

               const std::vector<uint8_t> big_data(TLS::MAX_PLAINTEXT_SIZE + TLS::MAX_PLAINTEXT_SIZE / 2);
               io->send(big_data);

               const auto headers = record_headers(callbacks->emitted());
               result.test_sz_eq("data was sharded into two records", headers.size(), 2);
               result.test_is_true("all records carry version 0x0303", all_records_have_version(headers, 0x0303));
               result.test_is_true("all records are application data records",
                                   all_records_have_type(headers, TLS::Record_Type::ApplicationData));
               result.test_is_true("no record exceeds the ciphertext limit",
                                   std::all_of(headers.begin(), headers.end(), [](const auto& header) {
                                      return header.payload_length <= TLS::MAX_CIPHERTEXT_SIZE_TLS13;
                                   }));

               // The first record is filled up to the plaintext limit
               // (plus content type byte and AEAD tag)
               result.test_sz_eq("first record is maximal",
                                 headers.at(0).payload_length,
                                 cs->encrypt_output_length(TLS::MAX_PLAINTEXT_SIZE + 1));
               result.test_sz_eq("second record contains the remainder",
                                 headers.at(1).payload_length,
                                 cs->encrypt_output_length(TLS::MAX_PLAINTEXT_SIZE / 2 + 1));
            }),

      CHECK("only the final record of a multi-record write is padded",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(
                  TLS::Connection_Side::Client, callbacks, std::make_shared<Test_Policy>(pad_to_minimum_size(1024)));

               const auto cs = rfc8448_application_traffic(TLS::Connection_Side::Client);
               io->set_cipher_state(cs);

               const std::vector<uint8_t> data(TLS::MAX_PLAINTEXT_SIZE + 10);
               io->send(data);

               const auto expected_length = 2 * TLS::TLS_HEADER_SIZE +
                                            cs->encrypt_output_length(TLS::MAX_PLAINTEXT_SIZE + 1) +
                                            cs->encrypt_output_length(1024);
               result.test_sz_eq(
                  "first record is full, trailing record is padded", callbacks->emitted().size(), expected_length);

               const auto headers = record_headers(callbacks->emitted());
               result.test_sz_eq("data was sharded into two records", headers.size(), 2);
               result.test_sz_eq("first record is full (not padded)",
                                 headers.at(0).payload_length,
                                 cs->encrypt_output_length(TLS::MAX_PLAINTEXT_SIZE + 1));
               result.test_sz_eq("final record is padded to the minimum size",
                                 headers.at(1).payload_length,
                                 cs->encrypt_output_length(1024));
            }),

      CHECK("outgoing record size limit is respected",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Client, callbacks);
               const auto cs = rfc8448_application_traffic(TLS::Connection_Side::Client);
               io->set_cipher_state(cs);

               io->set_record_size_limits(127 + 1 /* content type byte */, TLS::MAX_PLAINTEXT_SIZE + 1);

               io->send(std::vector<uint8_t>(127));
               result.test_sz_eq("one record generated", record_headers(callbacks->emitted()).size(), 1);

               callbacks->clear_emitted();
               io->send(std::vector<uint8_t>(128));
               result.test_sz_eq("two records generated", record_headers(callbacks->emitted()).size(), 2);
            }),
   };
}

std::vector<Test::Result> send_alerts_and_ccs() {
   return {
      CHECK("send unprotected alert",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Server, callbacks);

               io->send(TLS::Alert(TLS::AlertType::CloseNotify), false /* handle_compat_mode */);

               result.test_bin_eq("emitted alert record", callbacks->emitted(), "15 03 03 00 02 01 00");
            }),

      CHECK("send protected alert",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Client, callbacks);

               const auto cs = rfc8448_application_traffic(TLS::Connection_Side::Client);
               io->set_cipher_state(cs);

               io->send(TLS::Alert(TLS::AlertType::CloseNotify), false /* handle_compat_mode */);

               const auto headers = record_headers(callbacks->emitted());
               result.test_sz_eq("one record generated", headers.size(), 1);
               result.test_is_true("protected record looks like application data on the wire",
                                   all_records_have_type(headers, TLS::Record_Type::ApplicationData));
               result.test_sz_eq("protected alert has the expected size",
                                 headers.at(0).payload_length,
                                 cs->encrypt_output_length(2 /* alert */ + 1 /* content type */));
            }),

      CHECK("client emits a dummy CCS before an alert in compat mode",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Client, callbacks);

               // The dummy CCS is only sent if a cipher state exists already
               const auto cs = rfc8448_handshake_traffic(TLS::Connection_Side::Client);
               io->set_cipher_state(cs);

               io->send(TLS::Alert(TLS::AlertType::UnexpectedMessage, true), true /* handle_compat_mode */);

               const auto headers = record_headers(callbacks->emitted());
               result.require("two tls_emit_data invocations", headers.size() == 2);
               // No handshake record was sent, yet, hence the record layer is
               // still in "sending compat mode" and uses legacy version 0x0301
               result.test_enum_eq(
                  "first chunk is the dummy CCS record", headers.at(0).type, TLS::Record_Type::ChangeCipherSpec);
               result.test_enum_eq(
                  "second chunk is the protected alert", headers.at(1).type, TLS::Record_Type::ApplicationData);

               callbacks->clear_emitted();
               io->send(TLS::Alert(TLS::AlertType::UnexpectedMessage, true), true /* handle_compat_mode */);
               result.test_sz_eq("dummy CCS is sent only once", callbacks->emitted_chunks().size(), 1);
            }),

      CHECK("no dummy CCS is emitted before an alert without a cipher state",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Client, callbacks);

               io->send(TLS::Alert(TLS::AlertType::CloseNotify), true /* handle_compat_mode */);

               const auto headers = record_headers(callbacks->emitted());
               result.test_sz_eq("exactly one record is emitted (no CCS)", headers.size(), 1);
               result.test_is_true("the record is an alert record",
                                   all_records_have_type(headers, TLS::Record_Type::Alert));
            }),

      CHECK("server does not emit a dummy CCS before an alert in compat mode",
            [&](Test::Result& result) {
               const auto callbacks = std::make_shared<Mock_Callbacks>();
               const auto io = make_channel_io(TLS::Connection_Side::Server, callbacks);

               const auto cs = rfc8448_handshake_traffic(TLS::Connection_Side::Server);
               io->set_cipher_state(cs);

               io->send(TLS::Alert(TLS::AlertType::UnexpectedMessage, true), true /* handle_compat_mode */);

               const auto& chunks = callbacks->emitted_chunks();
               result.require("one tls_emit_data invocation", chunks.size() == 1);
               result.test_is_true("chunk is the protected alert", chunks.at(0).front() == 0x17);
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tls",
                       "tls_channel_io_tls",
                       receive_unprotected_records,
                       receive_protected_records,
                       receive_error_cases,
                       send_flights,
                       send_application_data,
                       send_alerts_and_ccs);

}  // namespace Botan_Tests

#endif
