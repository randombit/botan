/*
* PBE
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PBE_BASE_H__
#define BOTAN_PBE_BASE_H__

#include <botan/asn1_oid.h>
#include <botan/data_src.h>
#include <botan/filter.h>
#include <botan/rng.h>

namespace Botan {

/**
* Password Based Encryption (PBE) Filter.
*/
class BOTAN_DLL PBE : public Filter
   {
   public:
      /**
      * Set this filter's key.
      * @param pw the password to be used for the encryption
      */
      virtual void set_key(const std::string& pw) = 0;

      /**
      * Create a new random salt value and set the default iterations value.
      * @param rng a random number generator
      */
      virtual void new_params(RandomNumberGenerator& rng) = 0;

      /**
      * DER encode the params (the number of iterations and the salt value)
      * @return encoded params
      */
      virtual MemoryVector<byte> encode_params() const = 0;

      /**
      * Decode params and use them inside this Filter.
      * @param src a data source to read the encoded params from
      */
      virtual void decode_params(DataSource& src) = 0;

      /**
      * Get this PBE's OID.
      * @return object identifier
      */
      virtual OID get_oid() const = 0;
   };

}

#endif
