/*
* TLS Handshake Hash
* (C) 2004-2006,2011,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_handshake_hash.h>

#include <botan/hash.h>

namespace Botan::TLS {

/**
* Return a TLS Handshake Hash
*/
secure_vector<uint8_t> Handshake_Hash::final(std::string_view mac_algo) const {
   std::string hash_algo(mac_algo);
   if(hash_algo == "SHA-1") {
      hash_algo = "SHA-256";
   }

   auto hash = HashFunction::create_or_throw(hash_algo);
   hash->update(m_data);
   return hash->final();
}

}  // namespace Botan::TLS
