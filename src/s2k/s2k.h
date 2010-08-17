/*
* S2K
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_S2K_H__
#define BOTAN_S2K_H__

#include <botan/symkey.h>
#include <botan/rng.h>

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
      * @param key_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      */
      OctetString derive_key(u32bit key_len,
                             const std::string& passphrase) const;


      /**
      * Derive a key from a passphrase
      * @param output_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param iterations the number of iterations to use (use 10K or more)
      */
      OctetString derive_key(u32bit output_len,
                             const std::string& passphrase,
                             const byte salt[], u32bit salt_len,
                             u32bit iterations);

      /**
      * Set the number of iterations for the one-way function during
      * key generation.
      * @param n the desired number of iterations
      */
      void set_iterations(u32bit n);

      /**
      * Set a new salt value.
      * @param new_salt a byte array defining the new salt value
      * @param len the length of the above byte array
      */
      void change_salt(const byte new_salt[], u32bit len);

      /**
      * Set a new salt value.
      * @param new_salt the new salt value
      */
      void change_salt(const MemoryRegion<byte>& new_salt);

      /**
      * Create a new random salt value using the rng
      * @param rng the random number generator to use
      * @param len the desired length of the new salt value
      */
      void new_random_salt(RandomNumberGenerator& rng, u32bit len);

      /**
      * Get the number of iterations for the key derivation currently
      * configured in this S2K object.
      * @return the current number of iterations
      */
      u32bit iterations() const { return iter; }

      /**
      * Get the currently configured salt value of this S2K object.
      * @return the current salt value
      */
      SecureVector<byte> current_salt() const { return salt; }

      S2K() { iter = 0; }
      virtual ~S2K() {}
   private:
      S2K(const S2K&) {}
      S2K& operator=(const S2K&) { return (*this); }

      virtual OctetString derive(u32bit, const std::string&,
                                 const byte[], u32bit, u32bit) const = 0;
      SecureVector<byte> salt;
      u32bit iter;
   };

// More conventional name for this algorithm
typedef S2K PBKDF;

}

#endif
