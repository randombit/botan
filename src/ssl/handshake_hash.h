/*
* TLS Handshake Hash
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_HANDSHAKE_HASH_H__
#define BOTAN_TLS_HANDSHAKE_HASH_H__

#include <botan/secmem.h>

namespace Botan {

using namespace Botan;

/**
* TLS Handshake Hash
*/
class BOTAN_DLL HandshakeHash
   {
   public:
      void update(const byte in[], u32bit length)
         { data.append(in, length); }
      void update(const MemoryRegion<byte>& in)
         { update(in.begin(), in.size()); }
      void update(byte in)
         { update(&in, 1); }

      SecureVector<byte> final();
      SecureVector<byte> final_ssl3(const MemoryRegion<byte>&);
   private:
      SecureVector<byte> data;
   };

}

#endif
