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

/**
* Return a SSLv3 Handshake Hash
*/
secure_vector<byte> Handshake_Hash::final_ssl3(const secure_vector<byte>& secret) const
   {
   const byte PAD_INNER = 0x36, PAD_OUTER = 0x5C;

   Algorithm_Factory& af = global_state().algorithm_factory();

   std::unique_ptr<HashFunction> md5(af.make_hash_function("MD5"));
   std::unique_ptr<HashFunction> sha1(af.make_hash_function("SHA-1"));

   md5->update(data);
   sha1->update(data);

   md5->update(secret);
   sha1->update(secret);

   for(size_t i = 0; i != 48; ++i)
      md5->update(PAD_INNER);
   for(size_t i = 0; i != 40; ++i)
      sha1->update(PAD_INNER);

   secure_vector<byte> inner_md5 = md5->final(), inner_sha1 = sha1->final();

   md5->update(secret);
   sha1->update(secret);

   for(size_t i = 0; i != 48; ++i)
      md5->update(PAD_OUTER);
   for(size_t i = 0; i != 40; ++i)
      sha1->update(PAD_OUTER);

   md5->update(inner_md5);
   sha1->update(inner_sha1);

   secure_vector<byte> output;
   output += md5->final();
   output += sha1->final();
   return output;
   }

}

}
