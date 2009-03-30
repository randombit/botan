/**
* Symmetric Algorithm Base Class
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SYMMETRIC_ALGORITHM_H__
#define BOTAN_SYMMETRIC_ALGORITHM_H__

#include <botan/types.h>
#include <botan/exceptn.h>
#include <botan/symkey.h>

namespace Botan {

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
      void set_key(const SymmetricKey& key) throw(Invalid_Key_Length)
         { set_key(key.begin(), key.length()); }

      /**
      * Set the symmetric key of this object.
      * @param key the to be set as a byte array.
      * @param the length of the byte array.
      */
      void set_key(const byte key[], u32bit length) throw(Invalid_Key_Length)
         {
         if(!valid_keylength(length))
            throw Invalid_Key_Length(name(), length);
         key_schedule(key, length);
         }

      /**
      * Check whether a given key length is valid for this algorithm.
      * @param length the key length to be checked.
      * @return true if the key length is valid.
      */
      bool valid_keylength(u32bit length) const
         {
         return ((length >= MINIMUM_KEYLENGTH) &&
                 (length <= MAXIMUM_KEYLENGTH) &&
                 (length % KEYLENGTH_MULTIPLE == 0));
         }

      /**
      * Construct a SymmetricAlgorithm.
      * @param key_min the minimum allowed key length
      * @param key_max the maximum allowed key length
      * @param key_mod any valid key length must be a multiple of this value
      */
      SymmetricAlgorithm(u32bit key_min, u32bit key_max, u32bit key_mod) :
         MAXIMUM_KEYLENGTH(key_max ? key_max : key_min),
         MINIMUM_KEYLENGTH(key_min),
         KEYLENGTH_MULTIPLE(key_mod)
            {}

      virtual ~SymmetricAlgorithm() {}
   private:
      virtual void key_schedule(const byte[], u32bit) = 0;
   };

/**
* The two possible directions for cipher filters, determining whether they
* actually perform encryption or decryption.
*/
enum Cipher_Dir { ENCRYPTION, DECRYPTION };

}

#endif
