/*************************************************
* Base Classes Header File                       *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_BASE_H__
#define BOTAN_BASE_H__

#include <botan/exceptn.h>
#include <botan/symkey.h>

namespace Botan {

/*************************************************
* Constants                                      *
*************************************************/
static const u32bit DEFAULT_BUFFERSIZE = BOTAN_DEFAULT_BUFFER_SIZE;

/**
* This class represents a symmetric algorithm object.
*/
class BOTAN_DLL SymmetricAlgorithm
   {
   public:

      /**
      * The maximum allowed key length.
      */
      const u32bit MAXIMUM_KEYLENGTH;

      /**
      * The minimal allowed key length.
      */
      const u32bit MINIMUM_KEYLENGTH;

      /**
      * A valid keylength is a multiple of this value.
      */
      const u32bit KEYLENGTH_MULTIPLE;

      /**
      * The name of the algorithm.
      * @return the name of the algorithm
      */
      virtual std::string name() const = 0;

      /**
      * Set the symmetric key of this object.
      * @param key the SymmetricKey to be set.
      */
      void set_key(const SymmetricKey& key) throw(Invalid_Key_Length);

      /**
      * Set the symmetric key of this object.
      * @param key the to be set as a byte array.
      * @param the length of the byte array.
      */
      void set_key(const byte key[], u32bit length) throw(Invalid_Key_Length);

      /**
      * Check whether a given key length is valid for this algorithm.
      * @param length the key length to be checked.
      * @return true if the key length is valid.
      */
      bool valid_keylength(u32bit length) const;

      /**
      * Construct a SymmetricAlgorithm.
      * @param key_min the minimum allowed key length
      * @param key_max the maximum allowed key length
      * @param key_mod any valid key length must be a multiple of this value
      */
      SymmetricAlgorithm(u32bit key_min, u32bit key_max, u32bit key_mod);

      virtual ~SymmetricAlgorithm() {}
   private:
      virtual void key(const byte[], u32bit) = 0;
   };

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

      BlockCipher(u32bit, u32bit, u32bit = 0, u32bit = 1);
      virtual ~BlockCipher() {}
   private:
      virtual void enc(const byte[], byte[]) const = 0;
      virtual void dec(const byte[], byte[]) const = 0;
   };

/*************************************************
* Stream Cipher                                  *
*************************************************/
class BOTAN_DLL StreamCipher : public SymmetricAlgorithm
   {
   public:
      const u32bit IV_LENGTH;

      /**
      * Encrypt a message.
      * @param i the plaintext
      * @param o the byte array to hold the output, i.e. the ciphertext
      * @param len the length of both i and o
      */
      void encrypt(const byte i[], byte o[], u32bit len) { cipher(i, o, len); }

      /**
      * Decrypt a message.
      * @param i the ciphertext to decrypt
      * @param o the byte array to hold the output, i.e. the plaintext
      * @param len the length of both i and o
      */
      void decrypt(const byte i[], byte o[], u32bit len) { cipher(i, o, len); }

      /**
      * Encrypt a message.
      * @param in the plaintext as input, after the function has
      * returned it will hold the ciphertext

      * @param len the length of in
      */
      void encrypt(byte in[], u32bit len) { cipher(in, in, len); }

      /**
      * Decrypt a message.
      * @param in the ciphertext as input, after the function has
      * returned it will hold the plaintext
      * @param len the length of in
      */
      void decrypt(byte in[], u32bit len) { cipher(in, in, len); }

      /**
      * Resync the cipher using the IV
      * @param iv the initialization vector
      * @param iv_len the length of the IV in bytes
      */
      virtual void resync(const byte iv[], u32bit iv_len);

      /**
      * Seek ahead in the stream.
      * @param len the length to seek ahead.
      */
      virtual void seek(u32bit len);

      /**
      * Get a new object representing the same algorithm as *this
      */
      virtual StreamCipher* clone() const = 0;

      /**
      * Zeroize internal state
      */
      virtual void clear() throw() = 0;

      StreamCipher(u32bit, u32bit = 0, u32bit = 1, u32bit = 0);
      virtual ~StreamCipher() {}
   private:
      virtual void cipher(const byte[], byte[], u32bit) = 0;
   };

/**
* This class represents any kind of computation which
* uses an internal state,
* such as hash functions.
*/
class BOTAN_DLL BufferedComputation
   {
   public:

      /**
      * The length of the output of this function in bytes.
      */
      const u32bit OUTPUT_LENGTH;

      /**
      * Add new input to process.
      * @param in the input to process as a byte array
      * @param the length of the byte array
      */
      void update(const byte in[], u32bit length);

      /**
      * Add new input to process.
      * @param in the input to process as a MemoryRegion
      */
      void update(const MemoryRegion<byte>& in);

      /**
      * Add new input to process.
      * @param in the input to process as a std::string. Will be interpreted
      * as a byte array based on
      * the strings encoding.
      */
      void update(const std::string&);

      /**
      * Process a single byte.
      * @param in the byte to process
      */
      void update(byte in);

      /**
      * Complete the computation and retrieve the
      * final result.
      * @param out The byte array to be filled with the result.
      * Must be of length OUTPUT_LENGTH.
      */
      void final(byte out[]) { final_result(out); }

      /**
      * Complete the computation and retrieve the
      * final result.
      * @return a SecureVector holding the result
      */
      SecureVector<byte> final();

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process as a byte array
      * @param length the length of the byte array
      * @result the result of the call to final()
      */
      SecureVector<byte> process(const byte in[], u32bit length);

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process
      * @result the result of the call to final()
      */
      SecureVector<byte> process(const MemoryRegion<byte>& in);

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process as a string
      * @result the result of the call to final()
      */
      SecureVector<byte> process(const std::string& in);

      BufferedComputation(u32bit);
      virtual ~BufferedComputation() {}
   private:
      BufferedComputation& operator=(const BufferedComputation&);
      virtual void add_data(const byte[], u32bit) = 0;
      virtual void final_result(byte[]) = 0;
   };

}

#endif
