/**
* Block Cipher Base Class
* (C) 1999-2007 Jack Lloyd
*/

#ifndef BOTAN_BLOCK_CIPHER__
#define BOTAN_BLOCK_CIPHER__

#include <botan/exceptn.h>
#include <botan/symkey.h>
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
      void encrypt(const byte in[], byte out[]) const { enc(in, out); }

      /**
      * Decrypt a block.
      * @param in The ciphertext block to be decypted as a byte array.
      * Must be of length BLOCK_SIZE.
      * @param out The byte array designated to hold the decrypted block.
      * Must be of length BLOCK_SIZE.
      */
      void decrypt(const byte in[], byte out[]) const { dec(in, out); }

      /**
      * Encrypt a block.
      * @param in The plaintext block to be encrypted as a byte array.
      * Must be of length BLOCK_SIZE. Will hold the result when the function
      * has finished.
      */
      void encrypt(byte block[]) const { enc(block, block); }

      /**
      * Decrypt a block.
      * @param in The ciphertext block to be decrypted as a byte array.
      * Must be of length BLOCK_SIZE. Will hold the result when the function
      * has finished.
      */
      void decrypt(byte block[]) const { dec(block, block); }

      /**
      * Get a new object representing the same algorithm as *this
      */
      virtual BlockCipher* clone() const = 0;

      /**
      * Zeroize internal state
      */
      virtual void clear() throw() = 0;

      BlockCipher(u32bit block_size,
                  u32bit key_min,
                  u32bit key_max = 0,
                  u32bit key_mod = 1) :
         SymmetricAlgorithm(key_min, key_max, key_mod),
         BLOCK_SIZE(block_size) {}

      virtual ~BlockCipher() {}
   private:
      virtual void enc(const byte[], byte[]) const = 0;
      virtual void dec(const byte[], byte[]) const = 0;
   };

}

#endif
