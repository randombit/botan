/*
* PK Operation Types
* (C) 2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PK_OPERATIONS_H__
#define BOTAN_PK_OPERATIONS_H__

#include <botan/pk_keys.h>
#include <botan/secmem.h>
#include <botan/rng.h>

namespace Botan {

class EME;
class KDF;
class EMSA;

namespace PK_Ops {

/**
* Public key encryption interface
*/
class BOTAN_DLL Encryption
   {
   public:
      virtual size_t max_input_bits() const = 0;

      virtual secure_vector<byte> encrypt(const byte msg[],
                                          size_t msg_len,
                                          RandomNumberGenerator& rng) = 0;

      virtual ~Encryption() {}
   };

/**
* Public key decryption interface
*/
class BOTAN_DLL Decryption
   {
   public:
      virtual size_t max_input_bits() const = 0;

      virtual secure_vector<byte> decrypt(byte& valid_mask,
                                          const byte ciphertext[],
                                          size_t ciphertext_len) = 0;

      virtual ~Decryption() {}
   };

/**
* Public key signature verification interface
*/
class BOTAN_DLL Verification
   {
   public:
      /*
      * Add more data to the message currently being signed
      * @param msg the message
      * @param msg_len the length of msg in bytes
      */
      virtual void update(const byte msg[], size_t msg_len) = 0;

      /*
      * Perform a verification operation
      * @param rng a random number generator
      */
      virtual bool is_valid_signature(const byte sig[], size_t sig_len) = 0;

      /**
      * Get the maximum message size in bits supported by this public key.
      * @return maximum message in bits
      */
      virtual size_t max_input_bits() const = 0;

      /**
      * Find out the number of message parts supported by this scheme.
      * @return number of message parts
      */
      virtual size_t message_parts() const { return 1; }

      /**
      * Find out the message part size supported by this scheme/key.
      * @return size of the message parts
      */
      virtual size_t message_part_size() const { return 0; }

      virtual ~Verification() {}
   };

/**
* Public key signature creation interface
*/
class BOTAN_DLL Signature
   {
   public:
      /**
      * Find out the number of message parts supported by this scheme.
      * @return number of message parts
      */
      virtual size_t message_parts() const { return 1; }

      /**
      * Find out the message part size supported by this scheme/key.
      * @return size of the message parts
      */
      virtual size_t message_part_size() const { return 0; }

      /*
      * Add more data to the message currently being signed
      * @param msg the message
      * @param msg_len the length of msg in bytes
      */
      virtual void update(const byte msg[], size_t msg_len) = 0;

      /*
      * Perform a signature operation
      * @param rng a random number generator
      */
      virtual secure_vector<byte> sign(RandomNumberGenerator& rng) = 0;

      virtual ~Signature() {}
   };

/**
* A generic key agreement operation (eg DH or ECDH)
*/
class BOTAN_DLL Key_Agreement
   {
   public:
      virtual secure_vector<byte> agree(size_t key_len,
                                        const byte other_key[], size_t other_key_len,
                                        const byte salt[], size_t salt_len) = 0;

      virtual ~Key_Agreement() {}
   };

/**
* KEM (key encapsulation)
*/
class BOTAN_DLL KEM_Encryption
   {
   public:
      virtual void kem_encrypt(secure_vector<byte>& out_encapsulated_key,
                               secure_vector<byte>& out_shared_key,
                               size_t desired_shared_key_len,
                               Botan::RandomNumberGenerator& rng,
                               const uint8_t salt[],
                               size_t salt_len) = 0;

      virtual ~KEM_Encryption() {}
   };

class BOTAN_DLL KEM_Decryption
   {
   public:
      virtual secure_vector<byte> kem_decrypt(const byte encap_key[],
                                              size_t len,
                                              size_t desired_shared_key_len,
                                              const uint8_t salt[],
                                              size_t salt_len) = 0;

      virtual ~KEM_Decryption() {}
   };

}

}

#endif
