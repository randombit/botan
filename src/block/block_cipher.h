/**
* Block Cipher Base Class
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BLOCK_CIPHER_H__
#define BOTAN_BLOCK_CIPHER_H__

#include <botan/sym_algo.h>

namespace Botan {

/**
* This class represents a block cipher object.
*/
class BOTAN_DLL BlockCipher : public SymmetricAlgorithm
   {
   public:
      /**
      * The block size of this algorithm.
      */
      const u32bit BLOCK_SIZE;

      /**
      * Encrypt a block.
      * @param in The plaintext block to be encrypted as a byte array.
      * Must be of length BLOCK_SIZE.
      * @param out The byte array designated to hold the encrypted block.
      * Must be of length BLOCK_SIZE.
      */
      void encrypt(const byte in[], byte out[]) const
         { encrypt_n(in, out, 1); }

      /**
      * Decrypt a block.
      * @param in The ciphertext block to be decypted as a byte array.
      * Must be of length BLOCK_SIZE.
      * @param out The byte array designated to hold the decrypted block.
      * Must be of length BLOCK_SIZE.
      */
      void decrypt(const byte in[], byte out[]) const
         { decrypt_n(in, out, 1); }

      /**
      * Encrypt a block.
      * @param in The plaintext block to be encrypted as a byte array.
      * Must be of length BLOCK_SIZE. Will hold the result when the function
      * has finished.
      */
      void encrypt(byte block[]) const { encrypt_n(block, block, 1); }

      /**
      * Decrypt a block.
      * @param in The ciphertext block to be decrypted as a byte array.
      * Must be of length BLOCK_SIZE. Will hold the result when the function
      * has finished.
      */
      void decrypt(byte block[]) const { decrypt_n(block, block, 1); }

      virtual void encrypt_n(const byte in[], byte out[],
                             u32bit blocks) const = 0;
      virtual void decrypt_n(const byte in[], byte out[],
                             u32bit blocks) const = 0;

      /**
      * Get a new object representing the same algorithm as *this
      */
      virtual BlockCipher* clone() const = 0;

      /**
      * Zeroize internal state
      */
      virtual void clear() = 0;

      BlockCipher(u32bit block_size,
                  u32bit key_min,
                  u32bit key_max = 0,
                  u32bit key_mod = 1) :
         SymmetricAlgorithm(key_min, key_max, key_mod),
         BLOCK_SIZE(block_size) {}

      virtual ~BlockCipher() {}
   };

}

#endif
