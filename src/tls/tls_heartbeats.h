/*
* TLS Heartbeats
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_HEARTBEATS_H__
#define BOTAN_TLS_HEARTBEATS_H__

#include <botan/secmem.h>

namespace Botan {

namespace TLS {

class Heartbeat_Message
   {
   public:
      enum Type { REQUEST = 1, RESPONSE = 2 };

      MemoryVector<byte> contents() const;

      const MemoryRegion<byte>& payload() const { return m_payload; }

      bool is_request() const { return m_type == REQUEST; }

      Heartbeat_Message(const MemoryRegion<byte>& buf);

      Heartbeat_Message(Type type, const byte payload[], size_t payload_len);
   private:
      Type m_type;
      MemoryVector<byte> m_payload;
   };

}

}

#endif
