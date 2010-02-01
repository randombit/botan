/*
* S2K
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_S2K_H__
#define BOTAN_S2K_H__

#include <botan/symkey.h>

namespace Botan {

/*
* S2K Interface
*/
class BOTAN_DLL S2K
   {
   public:
      /**
      * Create a copy of this object.
      * @return an auto_ptr to a copy of this object
      */
      virtual S2K* clone() const = 0;

      /**
      * Get the algorithm name.
      * @return the name of this S2K algorithm
      */
      virtual std::string name() const = 0;

      /**
      * Clear this objects internal values.
      */
      virtual void clear() {}

      /**
      * Derive a key from a passphrase with this S2K object. It will use
      * the salt value and number of iterations configured in this object.
      * @param output_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt the randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param iterations the number of iterations to use (use 10K or more)
      */
      virtual OctetString derive_key(u32bit output_len,
                                     const std::string& passphrase,
                                     const byte salt[], u32bit salt_len,
                                     u32bit iterations) const = 0;

      S2K() {}
      virtual ~S2K() {}
   private:
      S2K(const S2K&) {}
      S2K& operator=(const S2K&) { return (*this); }
   };

}

#endif
