/*
* PK Operation Types
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PK_OPERATIONS_H__
#define BOTAN_PK_OPERATIONS_H__

#include <botan/secmem.h>
#include <botan/rng.h>

namespace Botan {

namespace PK_Ops {

class Signature_Operation
   {
   public:
      /**
      * Find out the number of message parts supported by this scheme.
      * @return the number of message parts
      */
      virtual u32bit message_parts() const { return 1; }

      /**
      * Find out the message part size supported by this scheme/key.
      * @return the size of the message parts
      */
      virtual u32bit message_part_size() const { return 0; }

      /**
      * Get the maximum message size in bits supported by this public key.
      * @return the maximum message in bits
      */
      virtual u32bit max_input_bits() const = 0;

      /*
      * Perform a signature operation
      * @param msg the message
      * @param msg_len the length of msg in bytes
      * @param rng a random number generator
      */
      virtual SecureVector<byte> sign(const byte msg[],
                                      u32bit msg_len,
                                      RandomNumberGenerator& rng) = 0;

      virtual ~Signature_Operation() {}
   };

/*
* A generic Key Agreement Operation (eg DH or ECDH)
*/
class BOTAN_DLL KA_Operation
   {
   public:
      /*
      * Perform a key agreement operation
      * @param w the other key value
      * @param w_len the length of w in bytes
      * @returns the agreed key
      */
      virtual SecureVector<byte> agree(const byte w[], u32bit w_len) const = 0;

      virtual ~KA_Operation() {}
   };

}

}

#endif
