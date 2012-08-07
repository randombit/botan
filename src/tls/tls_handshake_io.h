/*
* TLS Handshake Serialization
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_HANDSHAKE_IO_H__
#define BOTAN_TLS_HANDSHAKE_IO_H__

#include <botan/tls_magic.h>
#include <botan/tls_version.h>
#include <botan/loadstor.h>
#include <vector>
#include <deque>
#include <map>
#include <set>
#include <utility>

namespace Botan {

namespace TLS {

class Record_Writer;
class Handshake_Message;

/**
* Handshake IO Interface
*/
class Handshake_IO
   {
   public:
      virtual Protocol_Version initial_record_version() const = 0;

      virtual std::vector<byte> send(Handshake_Message& msg) = 0;

      virtual std::vector<byte> format(
         const std::vector<byte>& handshake_msg,
         Handshake_Type handshake_type) = 0;

      virtual void add_input(byte record_type,
                             const byte record[],
                             size_t record_size,
                             u64bit record_number) = 0;

      /**
      * Returns (HANDSHAKE_NONE, std::vector<>()) if no message currently available
      */
      virtual std::pair<Handshake_Type, std::vector<byte> > get_next_record() = 0;

      Handshake_IO() {}

      Handshake_IO(const Handshake_IO&) = delete;

      Handshake_IO& operator=(const Handshake_IO&) = delete;

      virtual ~Handshake_IO() {}
   };

/**
* Handshake IO for stream-based handshakes
*/
class Stream_Handshake_IO : public Handshake_IO
   {
   public:
      Stream_Handshake_IO(Record_Writer& writer) : m_writer(writer) {}

      Protocol_Version initial_record_version() const override;

      std::vector<byte> send(Handshake_Message& msg) override;

      std::vector<byte> format(
         const std::vector<byte>& handshake_msg,
         Handshake_Type handshake_type) override;

      void add_input(byte record_type,
                     const byte record[],
                     size_t record_size,
                     u64bit record_number) override;

      std::pair<Handshake_Type, std::vector<byte> > get_next_record() override;
   private:
      std::deque<byte> m_queue;
      Record_Writer& m_writer;
   };

/**
* Handshake IO for datagram-based handshakes
*/
class Datagram_Handshake_IO : public Handshake_IO
   {
   public:
      Datagram_Handshake_IO(Record_Writer& writer) : m_writer(writer) {}

      Protocol_Version initial_record_version() const override;

      std::vector<byte> send(Handshake_Message& msg) override;

      std::vector<byte> format(
         const std::vector<byte>& handshake_msg,
         Handshake_Type handshake_type) override;

      void add_input(const byte rec_type,
                     const byte record[],
                     size_t record_size,
                     u64bit record_number) override;

      std::pair<Handshake_Type, std::vector<byte>> get_next_record() override;
   private:
      class Handshake_Reassembly
         {
         public:
            void add_fragment(const byte fragment[],
                              size_t fragment_length,
                              size_t fragment_offset,
                              byte msg_type,
                              size_t msg_length);

            bool complete() const;

            std::pair<Handshake_Type, std::vector<byte>> message() const;
         private:
            byte m_msg_type = HANDSHAKE_NONE;
            size_t m_msg_length = 0;

            std::vector<byte> m_buffer;
         };

      std::map<u16bit, Handshake_Reassembly> m_messages;
      std::set<u16bit> m_ccs_epochs;

      u16bit m_in_message_seq = 0;
      u16bit m_out_message_seq = 0;
      Record_Writer& m_writer;
   };

}

}

#endif
