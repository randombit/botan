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
      /**
      * Encrypt or decrypt a message
      * @param in the plaintext
      * @param out the byte array to hold the output, i.e. the ciphertext
      * @param len the length of both in and out in bytes
      */
      virtual void cipher(const byte in[], byte out[], u32bit len) = 0;

      /**
      * Encrypt or decrypt a message
      * @param buf the plaintext / ciphertext
      * @param len the length of buf in bytes
      */
      void cipher1(byte buf[], u32bit len)
         { cipher(buf, buf, len); }

      /**
      * Resync the cipher using the IV
      * @param iv the initialization vector
      * @param iv_len the length of the IV in bytes
      */
      virtual void set_iv(const byte[], u32bit iv_len)
         {
         if(iv_len)
            throw Exception("The stream cipher " + name() +
                            " does not support resyncronization");
         }

      /**
      * @param iv_len the length of the IV in bytes
      * @return if the length is valid for this algorithm
      */
      virtual bool valid_iv_length(u32bit iv_len) const
         { return (iv_len == 0); }

      /**
      * Get a new object representing the same algorithm as *this
      */
      virtual StreamCipher* clone() const = 0;

      /**
      * Zeroize internal state
      */
      virtual void clear() throw() = 0;

      /**
      * StreamCipher constructor
      */
      StreamCipher(u32bit key_min,
                   u32bit key_max = 0,
                   u32bit key_mod = 1) :
         SymmetricAlgorithm(key_min, key_max, key_mod) {}

      virtual ~StreamCipher() {}
   };

}

#endif
