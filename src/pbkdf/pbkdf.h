/*
* PBKDF
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PBKDF_H__
#define BOTAN_PBKDF_H__

#include <botan/symkey.h>

namespace Botan {

/**
* Base class for PBKDF (password based key derivation function)
* implementations. Converts a password into a key using a salt
* and iterated hashing to make brute force attacks harder.
*/
class BOTAN_DLL PBKDF
   {
   public:

      /**
      * @return new instance of this same algorithm
      */
      virtual PBKDF* clone() const = 0;

      /**
      * Get the algorithm name.
      * @return name of this PBKDF algorithm
      */
      virtual std::string name() const = 0;

      /**
      * Clear this objects internal values.
      */
      virtual void clear() {}

      /**
      * Derive a key from a passphrase
      * @param output_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param iterations the number of iterations to use (use 10K or more)
      */
      virtual OctetString derive_key(u32bit output_len,
                                     const std::string& passphrase,
                                     const byte salt[], u32bit salt_len,
                                     u32bit iterations) const = 0;

      PBKDF() {}
      virtual ~PBKDF() {}

      PBKDF(const PBKDF&) = delete;
      PBKDF& operator=(const PBKDF&) = delete;
   };

/**
* For compatability with 1.8
*/
typedef PBKDF S2K;

}

#endif
