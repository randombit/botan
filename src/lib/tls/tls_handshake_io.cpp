/*
* TLS Handshake IO
* (C) 2012,2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_record.h>
#include <botan/internal/tls_seq_numbers.h>
#include <botan/tls_messages.h>
#include <botan/exceptn.h>
#include <botan/loadstor.h>
#include <chrono>

namespace Botan {

namespace TLS {

namespace {

inline size_t load_be24(const uint8_t q[3])
   {
   return make_uint32(0,
                      q[0],
                      q[1],
                      q[2]);
   }

void store_be24(uint8_t out[3], size_t val)
   {
   out[0] = get_byte(1, static_cast<uint32_t>(val));
   out[1] = get_byte(2, static_cast<uint32_t>(val));
   out[2] = get_byte(3, static_cast<uint32_t>(val));
   }

uint64_t steady_clock_ms()
   {
   return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count();
   }

}

Protocol_Version Stream_Handshake_IO::initial_record_version() const
   {
   return Protocol_Version::TLS_V10;
   }

void Stream_Handshake_IO::add_record(const uint8_t record[],
                                     size_t record_len,
                                     Record_Type record_type, uint64_t)
   {
   if(record_type == HANDSHAKE)
      {
      m_queue.insert(m_queue.end(), record, record + record_len);
      }
   else if(record_type == CHANGE_CIPHER_SPEC)
      {
      if(record_len != 1 || record[0] != 1)
         throw Decoding_Error("Invalid ChangeCipherSpec");

      // Pretend it's a regular handshake message of zero length
      const uint8_t ccs_hs[] = { HANDSHAKE_CCS, 0, 0, 0 };
      m_queue.insert(m_queue.end(), ccs_hs, ccs_hs + sizeof(ccs_hs));
      }
   else
      throw Decoding_Error("Unknown message type " + std::to_string(record_type) + " in handshake processing");
   }

std::pair<Handshake_Type, std::vector<uint8_t>>
Stream_Handshake_IO::get_next_record(bool)
   {
   if(m_queue.size() >= 4)
      {
      const size_t length = 4 + make_uint32(0, m_queue[1], m_queue[2], m_queue[3]);

      if(m_queue.size() >= length)
         {
         Handshake_Type type = static_cast<Handshake_Type>(m_queue[0]);

         if(type == HANDSHAKE_NONE)
            throw Decoding_Error("Invalid handshake message type");

         std::vector<uint8_t> contents(m_queue.begin() + 4,
                                       m_queue.begin() + length);

         m_queue.erase(m_queue.begin(), m_queue.begin() + length);

         return std::make_pair(type, contents);
         }
      }

   return std::make_pair(HANDSHAKE_NONE, std::vector<uint8_t>());
   }

std::vector<uint8_t>
Stream_Handshake_IO::format(const std::vector<uint8_t>& msg,
                            Handshake_Type type) const
   {
   std::vector<uint8_t> send_buf(4 + msg.size());

   const size_t buf_size = msg.size();

   send_buf[0] = static_cast<uint8_t>(type);

   store_be24(&send_buf[1], buf_size);

   if (msg.size() > 0)
      {
      copy_mem(&send_buf[4], msg.data(), msg.size());
      }

   return send_buf;
   }

std::vector<uint8_t> Stream_Handshake_IO::send_under_epoch(const Handshake_Message& /*msg*/, uint16_t /*epoch*/)
   {
   throw Invalid_State("Not possible to send under arbitrary epoch with stream based TLS");
   }

std::vector<uint8_t> Stream_Handshake_IO::send(const Handshake_Message& msg)
   {
   const std::vector<uint8_t> msg_bits = msg.serialize();

   if(msg.type() == HANDSHAKE_CCS)
      {
      m_send_hs(CHANGE_CIPHER_SPEC, msg_bits);
      return std::vector<uint8_t>(); // not included in handshake hashes
      }

   const std::vector<uint8_t> buf = format(msg_bits, msg.type());
   m_send_hs(HANDSHAKE, buf);
   return buf;
   }

Protocol_Version Datagram_Handshake_IO::initial_record_version() const
   {
   return Protocol_Version::DTLS_V10;
   }

void Datagram_Handshake_IO::retransmit_last_flight()
   {
   const size_t flight_idx = (m_flights.size() == 1) ? 0 : (m_flights.size() - 2);
   retransmit_flight(flight_idx);
   }

void Datagram_Handshake_IO::retransmit_flight(size_t flight_idx)
   {
   const std::vector<uint16_t>& flight = m_flights.at(flight_idx);

   BOTAN_ASSERT(flight.size() > 0, "Nonempty flight to retransmit");

   uint16_t epoch = m_flight_data[flight[0]].epoch;

   for(auto msg_seq : flight)
      {
      auto& msg = m_flight_data[msg_seq];

      if(msg.epoch != epoch)
         {
         // Epoch gap: insert the CCS
         std::vector<uint8_t> ccs(1, 1);
         m_send_hs(epoch, CHANGE_CIPHER_SPEC, ccs);
         }

      send_message(msg_seq, msg.epoch, msg.msg_type, msg.msg_bits);
      epoch = msg.epoch;
      }
   }

bool Datagram_Handshake_IO::timeout_check()
   {
   if(m_last_write == 0 || (m_flights.size() > 1 && !m_flights.rbegin()->empty()))
      {
      /*
      If we haven't written anything yet obviously no timeout.
      Also no timeout possible if we are mid-flight,
      */
      return false;
      }

   const uint64_t ms_since_write = steady_clock_ms() - m_last_write;

   if(ms_since_write < m_next_timeout)
      return false;

   retransmit_last_flight();

   m_next_timeout = std::min(2 * m_next_timeout, m_max_timeout);
   return true;
   }

void Datagram_Handshake_IO::add_record(const uint8_t record[],
                                       size_t record_len,
                                       Record_Type record_type,
                                       uint64_t record_sequence)
   {
   const uint16_t epoch = static_cast<uint16_t>(record_sequence >> 48);

   if(record_type == CHANGE_CIPHER_SPEC)
      {
      if(record_len != 1 || record[0] != 1)
         throw Decoding_Error("Invalid ChangeCipherSpec");

      // TODO: check this is otherwise empty
      m_ccs_epochs.insert(epoch);
      return;
      }

   const size_t DTLS_HANDSHAKE_HEADER_LEN = 12;

   while(record_len)
      {
      if(record_len < DTLS_HANDSHAKE_HEADER_LEN)
         return; // completely bogus? at least degenerate/weird

      const uint8_t msg_type = record[0];
      const size_t msg_len = load_be24(&record[1]);
      const uint16_t message_seq = load_be<uint16_t>(&record[4], 0);
      const size_t fragment_offset = load_be24(&record[6]);
      const size_t fragment_length = load_be24(&record[9]);

      const size_t total_size = DTLS_HANDSHAKE_HEADER_LEN + fragment_length;

      if(record_len < total_size)
         throw Decoding_Error("Bad lengths in DTLS header");

      if(message_seq >= m_in_message_seq)
         {
         m_messages[message_seq].add_fragment(&record[DTLS_HANDSHAKE_HEADER_LEN],
                                              fragment_length,
                                              fragment_offset,
                                              epoch,
                                              msg_type,
                                              msg_len);
         }
      else
         {
         // TODO: detect retransmitted flight
         }

      record += total_size;
      record_len -= total_size;
      }
   }

std::pair<Handshake_Type, std::vector<uint8_t>>
Datagram_Handshake_IO::get_next_record(bool expecting_ccs)
   {
   // Expecting a message means the last flight is concluded
   if(!m_flights.rbegin()->empty())
      m_flights.push_back(std::vector<uint16_t>());

   if(expecting_ccs)
      {
      if(!m_messages.empty())
         {
         const uint16_t current_epoch = m_messages.begin()->second.epoch();

         if(m_ccs_epochs.count(current_epoch))
            return std::make_pair(HANDSHAKE_CCS, std::vector<uint8_t>());
         }
      return std::make_pair(HANDSHAKE_NONE, std::vector<uint8_t>());
      }

   auto i = m_messages.find(m_in_message_seq);

   if(i == m_messages.end() || !i->second.complete())
      {
      return std::make_pair(HANDSHAKE_NONE, std::vector<uint8_t>());
      }

   m_in_message_seq += 1;

   return i->second.message();
   }

void Datagram_Handshake_IO::Handshake_Reassembly::add_fragment(
   const uint8_t fragment[],
   size_t fragment_length,
   size_t fragment_offset,
   uint16_t epoch,
   uint8_t msg_type,
   size_t msg_length)
   {
   if(complete())
      return; // already have entire message, ignore this

   if(m_msg_type == HANDSHAKE_NONE)
      {
      m_epoch = epoch;
      m_msg_type = msg_type;
      m_msg_length = msg_length;
      }

   if(msg_type != m_msg_type || msg_length != m_msg_length || epoch != m_epoch)
      throw Decoding_Error("Inconsistent values in fragmented DTLS handshake header");

   if(fragment_offset > m_msg_length)
      throw Decoding_Error("Fragment offset past end of message");

   if(fragment_offset + fragment_length > m_msg_length)
      throw Decoding_Error("Fragment overlaps past end of message");

   if(fragment_offset == 0 && fragment_length == m_msg_length)
      {
      m_fragments.clear();
      m_message.assign(fragment, fragment+fragment_length);
      }
   else
      {
      /*
      * FIXME. This is a pretty lame way to do defragmentation, huge
      * overhead with a tree node per byte.
      *
      * Also should confirm that all overlaps have no changes,
      * otherwise we expose ourselves to the classic fingerprinting
      * and IDS evasion attacks on IP fragmentation.
      */
      for(size_t i = 0; i != fragment_length; ++i)
         m_fragments[fragment_offset+i] = fragment[i];

      if(m_fragments.size() == m_msg_length)
         {
         m_message.resize(m_msg_length);
         for(size_t i = 0; i != m_msg_length; ++i)
            m_message[i] = m_fragments[i];
         m_fragments.clear();
         }
      }
   }

bool Datagram_Handshake_IO::Handshake_Reassembly::complete() const
   {
   return (m_msg_type != HANDSHAKE_NONE && m_message.size() == m_msg_length);
   }

std::pair<Handshake_Type, std::vector<uint8_t>>
Datagram_Handshake_IO::Handshake_Reassembly::message() const
   {
   if(!complete())
      throw Internal_Error("Datagram_Handshake_IO - message not complete");

   return std::make_pair(static_cast<Handshake_Type>(m_msg_type), m_message);
   }

std::vector<uint8_t>
Datagram_Handshake_IO::format_fragment(const uint8_t fragment[],
                                       size_t frag_len,
                                       uint16_t frag_offset,
                                       uint16_t msg_len,
                                       Handshake_Type type,
                                       uint16_t msg_sequence) const
   {
   std::vector<uint8_t> send_buf(12 + frag_len);

   send_buf[0] = static_cast<uint8_t>(type);

   store_be24(&send_buf[1], msg_len);

   store_be(msg_sequence, &send_buf[4]);

   store_be24(&send_buf[6], frag_offset);
   store_be24(&send_buf[9], frag_len);

   if (frag_len > 0)
      {
      copy_mem(&send_buf[12], fragment, frag_len);
      }

   return send_buf;
   }

std::vector<uint8_t>
Datagram_Handshake_IO::format_w_seq(const std::vector<uint8_t>& msg,
                                    Handshake_Type type,
                                    uint16_t msg_sequence) const
   {
   return format_fragment(msg.data(), msg.size(), 0, static_cast<uint16_t>(msg.size()), type, msg_sequence);
   }

std::vector<uint8_t>
Datagram_Handshake_IO::format(const std::vector<uint8_t>& msg,
                              Handshake_Type type) const
   {
   return format_w_seq(msg, type, m_in_message_seq - 1);
   }

std::vector<uint8_t> Datagram_Handshake_IO::send(const Handshake_Message& msg)
   {
   return this->send_under_epoch(msg, m_seqs.current_write_epoch());
   }

std::vector<uint8_t>
Datagram_Handshake_IO::send_under_epoch(const Handshake_Message& msg, uint16_t epoch)
   {
   const std::vector<uint8_t> msg_bits = msg.serialize();
   const Handshake_Type msg_type = msg.type();

   if(msg_type == HANDSHAKE_CCS)
      {
      m_send_hs(epoch, CHANGE_CIPHER_SPEC, msg_bits);
      return std::vector<uint8_t>(); // not included in handshake hashes
      }
   else if(msg_type == HELLO_VERIFY_REQUEST)
      {
      // This message is not included in the handshake hashes
      send_message(m_out_message_seq, epoch, msg_type, msg_bits);
      m_out_message_seq += 1;
      return std::vector<uint8_t>();
      }

   // Note: not saving CCS, instead we know it was there due to change in epoch
   m_flights.rbegin()->push_back(m_out_message_seq);
   m_flight_data[m_out_message_seq] = Message_Info(epoch, msg_type, msg_bits);

   m_out_message_seq += 1;
   m_last_write = steady_clock_ms();
   m_next_timeout = m_initial_timeout;

   return send_message(m_out_message_seq - 1, epoch, msg_type, msg_bits);
   }

std::vector<uint8_t> Datagram_Handshake_IO::send_message(uint16_t msg_seq,
                                                      uint16_t epoch,
                                                      Handshake_Type msg_type,
                                                      const std::vector<uint8_t>& msg_bits)
   {
   const size_t DTLS_HANDSHAKE_HEADER_LEN = 12;

   const std::vector<uint8_t> no_fragment =
      format_w_seq(msg_bits, msg_type, msg_seq);

   if(no_fragment.size() + DTLS_HEADER_SIZE <= m_mtu)
      {
      m_send_hs(epoch, HANDSHAKE, no_fragment);
      }
   else
      {
      size_t frag_offset = 0;

      /**
      * Largest possible overhead is for SHA-384 CBC ciphers, with 16 byte IV,
      * 16+ for padding and 48 bytes for MAC. 128 is probably a strict
      * over-estimate here. When CBC ciphers are removed this can be reduced
      * since AEAD modes have no padding, at most 16 byte mac, and smaller
      * per-record nonce.
      */
      const size_t ciphersuite_overhead = (epoch > 0) ? 128 : 0;
      const size_t header_overhead = DTLS_HEADER_SIZE + DTLS_HANDSHAKE_HEADER_LEN;

      if(m_mtu <= (header_overhead + ciphersuite_overhead))
         throw Invalid_Argument("DTLS MTU is too small to send headers");

      const size_t max_rec_size = m_mtu - (header_overhead + ciphersuite_overhead);

      while(frag_offset != msg_bits.size())
         {
         const size_t frag_len = std::min<size_t>(msg_bits.size() - frag_offset, max_rec_size);

         const std::vector<uint8_t> frag =
            format_fragment(&msg_bits[frag_offset],
                            frag_len,
                            static_cast<uint16_t>(frag_offset),
                            static_cast<uint16_t>(msg_bits.size()),
                            msg_type,
                            msg_seq);

         m_send_hs(epoch, HANDSHAKE, frag);

         frag_offset += frag_len;
         }
      }

   return no_fragment;
   }

}
}
