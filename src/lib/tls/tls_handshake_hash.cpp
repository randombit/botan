/*
* TLS Handshake Hash
* (C) 2004-2006,2011,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_handshake_hash.h>
#include <botan/tls_exceptn.h>
#include <botan/libstate.h>
#include <botan/hash.h>

namespace Botan {

namespace TLS {

/**
* Return a TLS Handshake Hash
*/
secure_vector<byte> Handshake_Hash::final(Protocol_Version version,
                                          const std::string& mac_algo) const
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   std::unique_ptr<HashFunction> hash;

   if(version.supports_ciphersuite_specific_prf())
      {
      if(mac_algo == "MD5" || mac_algo == "SHA-1")
         hash.reset(af.make_hash_function("SHA-256"));
      else
         hash.reset(af.make_hash_function(mac_algo));
      }
   else
      hash.reset(af.make_hash_function("Parallel(MD5,SHA-160)"));

   hash->update(data);
   return hash->final();
   }

}

}
