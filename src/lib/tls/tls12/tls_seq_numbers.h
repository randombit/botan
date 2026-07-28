/*
* TLS Sequence Number Handling
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_SEQ_NUMBERS_H_
#define BOTAN_TLS_SEQ_NUMBERS_H_

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <limits>
#include <map>

namespace Botan::TLS {

class Connection_Sequence_Numbers /* NOLINT(*-special-member-functions) */ {
   public:
      virtual ~Connection_Sequence_Numbers() = default;

      virtual void new_read_cipher_state() = 0;
      virtual void new_write_cipher_state() = 0;

      virtual uint16_t current_read_epoch() const = 0;
      virtual uint16_t current_write_epoch() const = 0;

      virtual uint64_t next_write_sequence(uint16_t) = 0;
      virtual uint64_t next_read_sequence() = 0;

      virtual bool already_seen(uint64_t seq) const = 0;
      virtual void read_accept(uint64_t seq) = 0;

      virtual void reset() = 0;
};

class Stream_Sequence_Numbers final : public Connection_Sequence_Numbers {
   public:
      Stream_Sequence_Numbers() : m_write_seq_no(0), m_read_seq_no(0), m_read_epoch(0), m_write_epoch(0) {}

      void reset() override {
         m_write_seq_no = 0;
         m_read_seq_no = 0;
         m_read_epoch = 0;
         m_write_epoch = 0;
      }

      void new_read_cipher_state() override {
         m_read_seq_no = 0;
         m_read_epoch++;
      }

      void new_write_cipher_state() override {
         m_write_seq_no = 0;
         m_write_epoch++;
      }

      uint16_t current_read_epoch() const override { return m_read_epoch; }

      uint16_t current_write_epoch() const override { return m_write_epoch; }

      uint64_t next_write_sequence(uint16_t /*epoch*/) override {
         if(m_write_seq_no == std::numeric_limits<uint64_t>::max()) {
            throw Invalid_State("TLS 1.2 write sequence number overflow");
         }
         return m_write_seq_no++;
      }

      uint64_t next_read_sequence() override { return m_read_seq_no; }

      bool already_seen(uint64_t /*seq*/) const override { return false; }

      void read_accept(uint64_t /*seq*/) override {
         if(m_read_seq_no == std::numeric_limits<uint64_t>::max()) {
            throw Invalid_State("TLS 1.2 read sequence number overflow");
         }
         m_read_seq_no++;
      }

   private:
      uint64_t m_write_seq_no;
      uint64_t m_read_seq_no;
      uint16_t m_read_epoch;
      uint16_t m_write_epoch;
};

class Datagram_Sequence_Numbers final : public Connection_Sequence_Numbers {
   public:
      Datagram_Sequence_Numbers() { Datagram_Sequence_Numbers::reset(); }

      void reset() override {
         m_write_seqs.clear();
         m_write_seqs[0] = 0;
         m_write_epoch = 0;
         m_read_epoch = 0;
         m_read_windows.clear();
         m_read_windows[0] = Replay_Window{};
      }

      void new_read_cipher_state() override {
         m_read_epoch++;
         m_read_windows.try_emplace(m_read_epoch);
      }

      void new_write_cipher_state() override {
         m_write_epoch++;
         m_write_seqs[m_write_epoch] = 0;
      }

      uint16_t current_read_epoch() const override { return m_read_epoch; }

      uint16_t current_write_epoch() const override { return m_write_epoch; }

      uint64_t next_write_sequence(uint16_t epoch) override {
         auto i = m_write_seqs.find(epoch);
         BOTAN_ASSERT(i != m_write_seqs.end(), "Found epoch");
         if(i->second > 0x0000FFFFFFFFFFFF) {
            throw Invalid_State("DTLS write sequence number overflow");
         }
         return (static_cast<uint64_t>(epoch) << 48) | i->second++;
      }

      uint64_t next_read_sequence() override { throw Invalid_State("DTLS uses explicit sequence numbers"); }

      bool already_seen(uint64_t sequence) const override {
         const uint16_t epoch = static_cast<uint16_t>(sequence >> 48);
         const uint64_t record_sequence = sequence & 0x0000FFFFFFFFFFFF;
         const auto window = m_read_windows.find(epoch);

         if(window == m_read_windows.end()) {
            return false;
         }

         const size_t window_size = sizeof(window->second.bits) * 8;

         if(record_sequence > window->second.highest) {
            return false;
         }

         const uint64_t offset = window->second.highest - record_sequence;

         if(offset >= window_size) {
            return true;  // really old?
         }

         return (((window->second.bits >> offset) & 1) == 1);
      }

      void read_accept(uint64_t sequence) override {
         const uint16_t epoch = static_cast<uint16_t>(sequence >> 48);
         const uint64_t record_sequence = sequence & 0x0000FFFFFFFFFFFF;
         auto& window = m_read_windows[epoch];
         const size_t window_size = sizeof(window.bits) * 8;

         if(record_sequence > window.highest) {
            // We've received a later sequence which advances our window
            const uint64_t offset = record_sequence - window.highest;
            window.highest += offset;

            if(offset >= window_size) {
               window.bits = 0;
            } else {
               window.bits <<= offset;
            }

            window.bits |= 0x01;
         } else {
            const uint64_t offset = window.highest - record_sequence;

            if(offset < window_size) {
               // We've received an old sequence but still within our window
               window.bits |= (static_cast<uint64_t>(1) << offset);
            } else {
               // This occurs only if we have reset state (DTLS reconnection case)
               window.highest = record_sequence;
               window.bits = 0;
            }
         }
      }

   private:
      struct Replay_Window final {
            uint64_t highest = 0;
            uint64_t bits = 0;
      };

      std::map<uint16_t, uint64_t> m_write_seqs;
      std::map<uint16_t, Replay_Window> m_read_windows;
      uint16_t m_write_epoch = 0;
      uint16_t m_read_epoch = 0;
};

}  // namespace Botan::TLS

#endif
