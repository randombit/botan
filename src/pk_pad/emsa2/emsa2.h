/*
* EMSA2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EMSA2_H__
#define BOTAN_EMSA2_H__

#include <botan/emsa.h>
#include <botan/hash.h>

namespace Botan {

/**
* EMSA2 from IEEE 1363
* Useful for Rabin-Williams
*/
class BOTAN_DLL EMSA2 : public EMSA
   {
   public:
      /**
      * @param hash the hash object to use
      */
      EMSA2(HashFunction* hash);
      ~EMSA2() { delete hash; }
   private:
      void update(const byte[], size_t);
      secure_vector<byte> raw_data();

      secure_vector<byte> encoding_of(const secure_vector<byte>&, size_t,
                                     RandomNumberGenerator& rng);

      bool verify(const secure_vector<byte>&, const secure_vector<byte>&,
                  size_t);

      secure_vector<byte> empty_hash;
      HashFunction* hash;
      byte hash_id;
   };

}

#endif
