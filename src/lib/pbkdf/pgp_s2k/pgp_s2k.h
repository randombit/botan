/*
* OpenPGP PBKDF
* (C) 1999-2007,2017 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_OPENPGP_S2K_H__
#define BOTAN_OPENPGP_S2K_H__

#include <botan/pbkdf.h>
#include <botan/hash.h>

namespace Botan {

/**
* OpenPGP's S2K
*
* See RFC 4880 sections 3.7.1.1, 3.7.1.2, and 3.7.1.3
* If the salt is empty and iterations == 1, "simple" S2K is used
* If the salt is non-empty and iterations == 1, "salted" S2K is used
* If the salt is non-empty and iterations > 1, "iterated" S2K is used
*
* If iterations == 0 and msec.count() > 0, "iterated" S2K is assumed,
* and the number of iterations performed is returned.
*
* Note that unlike PBKDF2, OpenPGP S2K's "iterations" are defined as
* the number of bytes hashed.
*/
class BOTAN_DLL OpenPGP_S2K final : public PBKDF
   {
   public:
      /**
      * @param hash_in the hash function to use
      */
      explicit OpenPGP_S2K(HashFunction* hash) : m_hash(hash) {}

      std::string name() const override
         {
         return "OpenPGP-S2K(" + m_hash->name() + ")";
         }

      PBKDF* clone() const
         {
         return new OpenPGP_S2K(m_hash->clone());
         }

      size_t pbkdf(uint8_t output_buf[], size_t output_len,
                   const std::string& passphrase,
                   const uint8_t salt[], size_t salt_len,
                   size_t iterations,
                   std::chrono::milliseconds msec) const override;

      /**
      * RFC 4880 encodes the iteration count to a single-byte value
      */
      static uint8_t encode_count(size_t iterations);

      static size_t decode_count(uint8_t encoded_iter);

   private:
      std::unique_ptr<HashFunction> m_hash;
   };

}

#endif
