/*
* EMSA4
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EMSA4_H__
#define BOTAN_EMSA4_H__

#include <botan/emsa.h>
#include <botan/hash.h>
#include <memory>

namespace Botan {

/**
* EMSA4 aka PSS-R
*/
class BOTAN_DLL EMSA4 : public EMSA
   {
   public:
      /**
      * @param hash the hash object to use
      */
      EMSA4(HashFunction* hash);

      /**
      * @param hash the hash object to use
      * @param salt_size the size of the salt to use in bytes
      */
      EMSA4(HashFunction* hash, size_t salt_size);
   private:
      void update(const byte input[], size_t length);

      secure_vector<byte> raw_data();

      secure_vector<byte> encoding_of(const secure_vector<byte>& msg,
                                      size_t output_bits,
                                      RandomNumberGenerator& rng);

      bool verify(const secure_vector<byte>& coded,
                  const secure_vector<byte>& raw,
                  size_t key_bits);

      size_t SALT_SIZE;
      std::unique_ptr<HashFunction> hash;
   };

}

#endif
