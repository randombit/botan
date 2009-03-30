/**
* Stream Cipher
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_STREAM_CIPHER_H__
#define BOTAN_STREAM_CIPHER_H__

#include <botan/sym_algo.h>

namespace Botan {

/*
* Stream Cipher
*/
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

      StreamCipher(u32bit key_min, u32bit key_max = 0,
                   u32bit key_mod = 1,
                   u32bit iv_len = 0) :
         SymmetricAlgorithm(key_min, key_max, key_mod),
         IV_LENGTH(iv_len) {}

      virtual ~StreamCipher() {}
   private:
      virtual void cipher(const byte[], byte[], u32bit) = 0;
   };

}

#endif
