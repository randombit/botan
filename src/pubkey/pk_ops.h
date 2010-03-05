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

class BOTAN_DLL Encryption
   {
   public:
      virtual u32bit max_input_bits() const = 0;

      virtual SecureVector<byte> encrypt(const byte msg[], u32bit msg_len,
                                         RandomNumberGenerator& rng) const = 0;

      virtual ~Encryption() {}
   };

class BOTAN_DLL Decryption
   {
   public:
      virtual u32bit max_input_bits() const = 0;

      virtual SecureVector<byte> decrypt(const byte msg[],
                                         u32bit msg_len) const = 0;

      virtual ~Decryption() {}
   };

class BOTAN_DLL Signature
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
      virtual SecureVector<byte>
         sign(const byte msg[], u32bit msg_len,
              RandomNumberGenerator& rng) const = 0;

      virtual ~Signature() {}
   };

class BOTAN_DLL Verification
   {
   public:
      /**
      * Get the maximum message size in bits supported by this public key.
      * @return the maximum message in bits
      */
      virtual u32bit max_input_bits() const = 0;

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
      * @return boolean specifying if this key type supports message
      * recovery and thus if you need to call verify() or verify_mr()
      */
      virtual bool with_recovery() const = 0;

      /*
      * Perform a signature check operation
      * @param msg the message
      * @param msg_len the length of msg in bytes
      * @param sig the signature
      * @param sig_len the length of sig in bytes
      * @returns if signature is a valid one for message
      */
      virtual bool verify(const byte msg[], u32bit msg_len,
                          const byte sig[], u32bit sig_len) const
         {
         throw Invalid_State("Message recovery required");
         }

      /*
      * Perform a signature operation (with message recovery)
      * Only call this if with_recovery() returns true
      * @param msg the message
      * @param msg_len the length of msg in bytes
      * @returns recovered message
      */
      virtual SecureVector<byte> verify_mr(const byte msg[],
                                           u32bit msg_len) const
         {
         throw Invalid_State("Message recovery not supported");
         }

      virtual ~Verification() {}
   };

/*
* A generic Key Agreement Operation (eg DH or ECDH)
*/
class BOTAN_DLL Key_Agreement
   {
   public:
      /*
      * Perform a key agreement operation
      * @param w the other key value
      * @param w_len the length of w in bytes
      * @returns the agreed key
      */
      virtual SecureVector<byte> agree(const byte w[], u32bit w_len) const = 0;

      virtual ~Key_Agreement() {}
   };

}

}

#endif
