/*
* TLS Handshake Serialization
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_HANDSHAKE_IO_H__
#define BOTAN_TLS_HANDSHAKE_IO_H__

#include <botan/tls_magic.h>
#include <botan/loadstor.h>
#include <vector>
#include <deque>
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
      virtual std::vector<byte> send(Handshake_Message& msg) = 0;

      virtual std::vector<byte> format(
         const std::vector<byte>& handshake_msg,
         Handshake_Type handshake_type) = 0;

      virtual void add_input(byte record_type,
                             const byte record[],
                             size_t record_size) = 0;

      virtual bool empty() const = 0;

      virtual bool have_full_record() const = 0;

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

      std::vector<byte> send(Handshake_Message& msg) override;

      std::vector<byte> format(
         const std::vector<byte>& handshake_msg,
         Handshake_Type handshake_type) override;

      void add_input(byte record_type,
                     const byte record[],
                     size_t record_size) override;

      bool empty() const override;

      bool have_full_record() const override;

      std::pair<Handshake_Type, std::vector<byte> > get_next_record() override;
   private:
      std::deque<byte> m_queue;
      Record_Writer& m_writer;
   };

}

}

#endif
