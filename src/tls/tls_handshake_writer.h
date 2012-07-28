/*
* TLS Handshake Writer
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_HANDSHAKE_WRITER_H__
#define BOTAN_TLS_HANDSHAKE_WRITER_H__

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
* Handshake Writer
*/
class Handshake_Writer
   {
   public:
      virtual std::vector<byte> send(Handshake_Message& msg) = 0;

      virtual std::vector<byte> format(
         const std::vector<byte>& handshake_msg,
         Handshake_Type handshake_type) = 0;

      Handshake_Writer() {}

      Handshake_Writer(const Handshake_Writer&) = delete;

      Handshake_Writer& operator=(const Handshake_Writer&) = delete;

      virtual ~Handshake_Writer() {}
   };

/**
* Stream Handshake Writer
*/
class Stream_Handshake_Writer : public Handshake_Writer
   {
   public:
      Stream_Handshake_Writer(Record_Writer& writer) : m_writer(writer) {}

      std::vector<byte> send(Handshake_Message& msg) override;

      std::vector<byte> format(
         const std::vector<byte>& handshake_msg,
         Handshake_Type handshake_type) override;
   private:
      Record_Writer& m_writer;
   };

}

}

#endif
