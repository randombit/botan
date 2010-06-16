/*
* Base class for message authentiction codes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_MESSAGE_AUTH_CODE_BASE_H__
#define BOTAN_MESSAGE_AUTH_CODE_BASE_H__

#include <botan/buf_comp.h>
#include <botan/sym_algo.h>
#include <string>

namespace Botan {

/**
* This class represents Message Authentication Code (MAC) objects.
*/
class BOTAN_DLL MessageAuthenticationCode : public BufferedComputation,
                                            public SymmetricAlgorithm
   {
   public:
      /**
      * Verify a MAC.
      * @param in the MAC to verify as a byte array
      * @param length the length of param in
      * @return true if the MAC is valid, false otherwise
      */
      virtual bool verify_mac(const byte in[], u32bit length);

      /**
      * Get a new object representing the same algorithm as *this
      */
      virtual MessageAuthenticationCode* clone() const = 0;

      /**
      * Get the name of this algorithm.
      * @return the name of this algorithm
      */
      virtual std::string name() const = 0;

      /**
      * Reset the internal state of this object.
      */
      virtual void clear() = 0;

      /**
      * @param mac_len the output length of this MAC
      * @param key_min the minimum key size
      * @param key_max the maximum key size
      * @param key_mod the modulo restriction on the key size
      */
      MessageAuthenticationCode(u32bit mac_len,
                                u32bit key_min,
                                u32bit key_max = 0,
                                u32bit key_mod = 1) :
         BufferedComputation(mac_len),
         SymmetricAlgorithm(key_min, key_max, key_mod) {}

      virtual ~MessageAuthenticationCode() {}
   };

}

#endif
