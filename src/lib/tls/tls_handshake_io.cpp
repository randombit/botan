/*
* TLS Handshake IO
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_record.h>
#include <botan/internal/tls_seq_numbers.h>
#include <botan/exceptn.h>

namespace Botan {

namespace TLS {

namespace {

inline size_t load_be24(const byte q[3])
   {
   return make_u32bit(0,
                      q[0],
                      q[1],
                      q[2]);
   }

void store_be24(byte out[3], size_t val)
   {
   out[0] = get_byte<u32bit>(1, val);
   out[1] = get_byte<u32bit>(2, val);
   out[2] = get_byte<u32bit>(3, val);
   }

}

Protocol_Version Stream_Handshake_IO::initial_record_version() const
   {
   return Protocol_Version::TLS_V10;
   }

void Stream_Handshake_IO::add_record(const std::vector<byte>& record,
                                     Record_Type record_type, u64bit)
   {
   if(record_type == HANDSHAKE)
      {
      m_queue.insert(m_queue.end(), record.begin(), record.end());
      }
   else if(record_type == CHANGE_CIPHER_SPEC)
      {
      if(record.size() != 1 || record[0] != 1)
         throw Decoding_Error("Invalid ChangeCipherSpec");

      // Pretend it's a regular handshake message of zero length
      const byte ccs_hs[] = { HANDSHAKE_CCS, 0, 0, 0 };
      m_queue.insert(m_queue.end(), ccs_hs, ccs_hs + sizeof(ccs_hs));
      }
   else
      throw Decoding_Error("Unknown message type in handshake processing");
   }

std::pair<Handshake_Type, std::vector<byte>>
Stream_Handshake_IO::get_next_record(bool)
   {
   if(m_queue.size() >= 4)
      {
      const size_t length = make_u32bit(0, m_queue[1], m_queue[2], m_queue[3]);

      if(m_queue.size() >= length + 4)
         {
         Handshake_Type type = static_cast<Handshake_Type>(m_queue[0]);

         std::vector<byte> contents(m_queue.begin() + 4,
                                    m_queue.begin() + 4 + length);

         m_queue.erase(m_queue.begin(), m_queue.begin() + 4 + length);

         return std::make_pair(type, contents);
         }
      }

   return std::make_pair(HANDSHAKE_NONE, std::vector<byte>());
   }

std::vector<byte>
Stream_Handshake_IO::format(const std::vector<byte>& msg,
                            Handshake_Type type) const
   {
   std::vector<byte> send_buf(4 + msg.size());

   const size_t buf_size = msg.size();

   send_buf[0] = type;

   store_be24(&send_buf[1], buf_size);

   copy_mem(&send_buf[4], &msg[0], msg.size());

   return send_buf;
   }

std::vector<byte> Stream_Handshake_IO::send(const Handshake_Message& msg)
   {
   const std::vector<byte> msg_bits = msg.serialize();

   if(msg.type() == HANDSHAKE_CCS)
      {
      m_send_hs(CHANGE_CIPHER_SPEC, msg_bits);
      return std::vector<byte>(); // not included in handshake hashes
      }

   const std::vector<byte> buf = format(msg_bits, msg.type());
   m_send_hs(HANDSHAKE, buf);
   return buf;
   }

Protocol_Version Datagram_Handshake_IO::initial_record_version() const
   {
   return Protocol_Version::DTLS_V10;
   }

void Datagram_Handshake_IO::add_record(const std::vector<byte>& record,
                                       Record_Type record_type,
                                       u64bit record_sequence)
   {
   const u16bit epoch = static_cast<u16bit>(record_sequence >> 48);

   if(record_type == CHANGE_CIPHER_SPEC)
      {
      m_ccs_epochs.insert(epoch);
      return;
      }

   const size_t DTLS_HANDSHAKE_HEADER_LEN = 12;

   const byte* record_bits = &record[0];
   size_t record_size = record.size();

   while(record_size)
      {
      if(record_size < DTLS_HANDSHAKE_HEADER_LEN)
         return; // completely bogus? at least degenerate/weird

      const byte msg_type = record_bits[0];
      const size_t msg_len = load_be24(&record_bits[1]);
      const u16bit message_seq = load_be<u16bit>(&record_bits[4], 0);
      const size_t fragment_offset = load_be24(&record_bits[6]);
      const size_t fragment_length = load_be24(&record_bits[9]);

      const size_t total_size = DTLS_HANDSHAKE_HEADER_LEN + fragment_length;

      if(record_size < total_size)
         throw Decoding_Error("Bad lengths in DTLS header");

      if(message_seq >= m_in_message_seq)
         {
         m_messages[message_seq].add_fragment(&record_bits[DTLS_HANDSHAKE_HEADER_LEN],
                                              fragment_length,
                                              fragment_offset,
                                              epoch,
                                              msg_type,
                                              msg_len);
         }

      record_bits += total_size;
      record_size -= total_size;
      }
   }

std::pair<Handshake_Type, std::vector<byte>>
Datagram_Handshake_IO::get_next_record(bool expecting_ccs)
   {
   if(!m_flights.rbegin()->empty())
      m_flights.push_back(std::vector<u16bit>());

   if(expecting_ccs)
      {
      if(!m_messages.empty())
         {
         const u16bit current_epoch = m_messages.begin()->second.epoch();

         if(m_ccs_epochs.count(current_epoch))
            return std::make_pair(HANDSHAKE_CCS, std::vector<byte>());
         }

      return std::make_pair(HANDSHAKE_NONE, std::vector<byte>());
      }

   auto i = m_messages.find(m_in_message_seq);

   if(i == m_messages.end() || !i->second.complete())
      return std::make_pair(HANDSHAKE_NONE, std::vector<byte>());

   m_in_message_seq += 1;

   return i->second.message();
   }

void Datagram_Handshake_IO::Handshake_Reassembly::add_fragment(
   const byte fragment[],
   size_t fragment_length,
   size_t fragment_offset,
   u16bit epoch,
   byte msg_type,
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
      throw Decoding_Error("Inconsistent values in DTLS handshake header");

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

std::pair<Handshake_Type, std::vector<byte>>
Datagram_Handshake_IO::Handshake_Reassembly::message() const
   {
   if(!complete())
      throw Internal_Error("Datagram_Handshake_IO - message not complete");

   return std::make_pair(static_cast<Handshake_Type>(m_msg_type), m_message);
   }

std::vector<byte>
Datagram_Handshake_IO::format_fragment(const byte fragment[],
                                       size_t frag_len,
                                       u16bit frag_offset,
                                       u16bit msg_len,
                                       Handshake_Type type,
                                       u16bit msg_sequence) const
   {
   std::vector<byte> send_buf(12 + frag_len);

   send_buf[0] = type;

   store_be24(&send_buf[1], msg_len);

   store_be(msg_sequence, &send_buf[4]);

   store_be24(&send_buf[6], frag_offset);
   store_be24(&send_buf[9], frag_len);

   copy_mem(&send_buf[12], &fragment[0], frag_len);

   return send_buf;
   }

std::vector<byte>
Datagram_Handshake_IO::format_w_seq(const std::vector<byte>& msg,
                                    Handshake_Type type,
                                    u16bit msg_sequence) const
   {
   return format_fragment(&msg[0], msg.size(), 0, msg.size(), type, msg_sequence);
   }

std::vector<byte>
Datagram_Handshake_IO::format(const std::vector<byte>& msg,
                              Handshake_Type type) const
   {
   return format_w_seq(msg, type, m_in_message_seq - 1);
   }

namespace {

size_t split_for_mtu(size_t mtu, size_t msg_size)
   {
   const size_t DTLS_HEADERS_SIZE = 25; // DTLS record+handshake headers

   const size_t parts = (msg_size + mtu) / mtu;

   if(parts + DTLS_HEADERS_SIZE > mtu)
      return parts + 1;

   return parts;
   }

}

std::vector<byte>
Datagram_Handshake_IO::send(const Handshake_Message& msg)
   {
   const std::vector<byte> msg_bits = msg.serialize();
   const u16bit epoch = m_seqs.current_write_epoch();
   const Handshake_Type msg_type = msg.type();

   std::tuple<u16bit, byte, std::vector<byte>> msg_info(epoch, msg_type, msg_bits);

   if(msg_type == HANDSHAKE_CCS)
      {
      m_send_hs(epoch, CHANGE_CIPHER_SPEC, msg_bits);
      return std::vector<byte>(); // not included in handshake hashes
      }

   const std::vector<byte> no_fragment =
      format_w_seq(msg_bits, msg_type, m_out_message_seq);

   if(no_fragment.size() + DTLS_HEADER_SIZE <= m_mtu)
      m_send_hs(epoch, HANDSHAKE, no_fragment);
   else
      {
      const size_t parts = split_for_mtu(m_mtu, msg_bits.size());

      const size_t parts_size = (msg_bits.size() + parts) / parts;

      size_t frag_offset = 0;

      while(frag_offset != msg_bits.size())
         {
         const size_t frag_len =
            std::min<size_t>(msg_bits.size() - frag_offset,
                             parts_size);

         m_send_hs(epoch,
                   HANDSHAKE,
                   format_fragment(&msg_bits[frag_offset],
                                   frag_len,
                                   frag_offset,
                                   msg_bits.size(),
                                   msg_type,
                                   m_out_message_seq));

         frag_offset += frag_len;
         }
      }

   // Note: not saving CCS, instead we know it was there due to change in epoch
   m_flights.rbegin()->push_back(m_out_message_seq);
   m_flight_data[m_out_message_seq] = msg_info;

   m_out_message_seq += 1;

   return no_fragment;
   }

}

}
