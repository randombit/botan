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

      void update(const secure_vector<byte>& in)
         { data += in; }

      void update(const std::vector<byte>& in)
         { data += in; }

      void update(byte in)
         { data.push_back(in); }

      void update(Handshake_Type handshake_type,
                  const std::vector<byte>& handshake_msg);

      secure_vector<byte> final(Protocol_Version version,
                               const std::string& mac_algo);

      secure_vector<byte> final_ssl3(const secure_vector<byte>& master_secret);

      const secure_vector<byte>& get_contents() const
         { return data; }

   private:
      secure_vector<byte> data;
   };

}

}

#endif
