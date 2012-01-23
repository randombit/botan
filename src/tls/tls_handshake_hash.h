/*
* TLS Handshake Hash
* (C) 2004-2006,2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_HANDSHAKE_HASH_H__
#define BOTAN_TLS_HANDSHAKE_HASH_H__

#include <botan/secmem.h>
#include <botan/tls_version.h>
#include <botan/tls_magic.h>

namespace Botan {

namespace TLS {

using namespace Botan;

/**
* TLS Handshake Hash
*/
class Handshake_Hash
   {
   public:
      void update(const byte in[], size_t length)
         { data += std::make_pair(in, length); }

      void update(const MemoryRegion<byte>& in)
         { data += in; }

      void update(byte in)
         { data.push_back(in); }

      void update(Handshake_Type handshake_type,
                  const MemoryRegion<byte>& handshake_msg);

      SecureVector<byte> final(Protocol_Version version);
      SecureVector<byte> final_ssl3(const MemoryRegion<byte>& master_secret);

      const SecureVector<byte>& get_contents() const
         { return data; }

   private:
      SecureVector<byte> data;
   };

}

}

#endif
