/*
* TLS Handshake IO
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/tls_messages.h>
#include <botan/tls_record.h>
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

void Stream_Handshake_IO::add_input(const byte rec_type,
                                    const byte record[],
                                    size_t record_size)
   {
   if(rec_type == HANDSHAKE)
      {
      m_queue.insert(m_queue.end(), record, record + record_size);
      }
   else if(rec_type == CHANGE_CIPHER_SPEC)
      {
      if(record_size != 1 || record[0] != 1)
         throw Decoding_Error("Invalid ChangeCipherSpec");

      const byte ccs_hs[] = { HANDSHAKE_CCS, 0, 0, 0 };
      m_queue.insert(m_queue.end(), ccs_hs, ccs_hs + sizeof(ccs_hs));
      }
   else
      throw Decoding_Error("Unknown message type in handshake processing");
   }

bool Stream_Handshake_IO::empty() const
   {
   return m_queue.empty();
   }

bool Stream_Handshake_IO::have_full_record() const
   {
   if(m_queue.size() >= 4)
      {
      const size_t length = load_be24(&m_queue[1]);

      return (m_queue.size() >= length + 4);
      }

   return false;
   }

std::pair<Handshake_Type, std::vector<byte> >
Stream_Handshake_IO::get_next_record()
   {
   if(m_queue.size() >= 4)
      {
      const size_t length = load_be24(&m_queue[1]);

      if(m_queue.size() >= length + 4)
         {
         Handshake_Type type = static_cast<Handshake_Type>(m_queue[0]);

         std::vector<byte> contents(m_queue.begin() + 4,
                                    m_queue.begin() + 4 + length);

         m_queue.erase(m_queue.begin(), m_queue.begin() + 4 + length);

         return std::make_pair(type, contents);
         }
      }

   throw Internal_Error("Stream_Handshake_IO::get_next_record called without a full record");
   }

std::vector<byte>
Stream_Handshake_IO::format(const std::vector<byte>& msg,
                            Handshake_Type type)
   {
   std::vector<byte> send_buf(4 + msg.size());

   const size_t buf_size = msg.size();

   send_buf[0] = type;

   store_be24(&send_buf[1], buf_size);

   copy_mem(&send_buf[4], &msg[0], msg.size());

   return send_buf;
   }

std::vector<byte> Stream_Handshake_IO::send(Handshake_Message& msg)
   {
   const std::vector<byte> buf = format(msg.serialize(), msg.type());

   m_writer.send(HANDSHAKE, &buf[0], buf.size());

   return buf;
   }

void Datagram_Handshake_IO::add_input(const byte rec_type,
                                      const byte record[],
                                      size_t record_size)
   {
   if(rec_type == CHANGE_CIPHER_SPEC)
      {
      const u16bit message_seq = 666; // fixme
      m_messages[message_seq].add_fragment(nullptr, 0, 0, HANDSHAKE_CCS, 0);
      return;
      }

   const size_t DTLS_HANDSHAKE_HEADER_LEN = 12;

   if(record_size < DTLS_HANDSHAKE_HEADER_LEN)
      return; // completely bogus? at least degenerate/weird

   const byte msg_type = record[0];
   const size_t msg_len = load_be24(&record[1]);
   const u16bit message_seq = load_be<u16bit>(&record[4], 0);
   const size_t fragment_offset = load_be24(&record[6]);
   const size_t fragment_length = load_be24(&record[9]);

   if(fragment_length + DTLS_HANDSHAKE_HEADER_LEN != record_size)
      throw Decoding_Error("Bogus DTLS handshake, header sizes do not match");

   m_messages[message_seq].add_fragment(&record[DTLS_HANDSHAKE_HEADER_LEN],
                                        fragment_length,
                                        fragment_offset,
                                        msg_type,
                                        msg_len);
   }

bool Datagram_Handshake_IO::empty() const
   {
   return m_messages.find(m_in_message_seq) == m_messages.end();
   }

bool Datagram_Handshake_IO::have_full_record() const
   {
   auto i = m_messages.find(m_in_message_seq);

   const bool complete = (i != m_messages.end() && i->second.complete());

   return complete;
   }

std::pair<Handshake_Type, std::vector<byte> > Datagram_Handshake_IO::get_next_record()
   {
   auto i = m_messages.find(m_in_message_seq);

   if(i == m_messages.end() || !i->second.complete())
      throw Internal_Error("Datagram_Handshake_IO::get_next_record called without a full record");


   //return i->second.message();
   auto m = i->second.message();

   m_in_message_seq += 1;

   return m;
   }

void Datagram_Handshake_IO::Handshake_Reassembly::add_fragment(
   const byte fragment[],
   size_t fragment_length,
   size_t fragment_offset,
   byte msg_type,
   size_t msg_length)
   {
   if(m_msg_type == HANDSHAKE_NONE)
      {
      m_msg_type = msg_type;
      m_msg_length = msg_length;
#warning DoS should resize as inputs are added (?)
      m_buffer.resize(m_msg_length);
      }

   if(msg_type != m_msg_type || msg_length != m_msg_length)
      throw Decoding_Error("Datagram_Handshake_IO - inconsistent values");

   copy_mem(&m_buffer[fragment_offset], fragment, fragment_length);
   }

bool Datagram_Handshake_IO::Handshake_Reassembly::complete() const
   {
   return true; // fixme!
   }

std::pair<Handshake_Type, std::vector<byte>>
Datagram_Handshake_IO::Handshake_Reassembly::message() const
   {
   if(!complete())
      throw Internal_Error("Datagram_Handshake_IO - message not complete");

   auto msg = std::make_pair(static_cast<Handshake_Type>(m_msg_type), m_buffer);

   return msg;
   }

std::vector<byte>
Datagram_Handshake_IO::format(const std::vector<byte>& msg,
                              Handshake_Type type)
   {
   std::vector<byte> send_buf(12 + msg.size());

   const size_t buf_size = msg.size();

   send_buf[0] = type;

   store_be24(&send_buf[1], buf_size);

   store_be(static_cast<u16bit>(m_in_message_seq - 1), &send_buf[4]);

   store_be24(&send_buf[6], 0); // fragment_offset
   store_be24(&send_buf[9], buf_size); // fragment_length

   copy_mem(&send_buf[12], &msg[0], msg.size());

   return send_buf;
   }

std::vector<byte>
Datagram_Handshake_IO::send(Handshake_Message& msg)
   {
   const std::vector<byte> buf = format(msg.serialize(), msg.type());

   // FIXME: fragment to mtu size
   m_writer.send(HANDSHAKE, &buf[0], buf.size());

   return buf;

   }

}

}
