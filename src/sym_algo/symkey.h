/*
* OctetString
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SYMKEY_H__
#define BOTAN_SYMKEY_H__

#include <botan/secmem.h>
#include <string>

namespace Botan {

/**
* Octet String
*/
class BOTAN_DLL OctetString
   {
   public:
      /**
      * @return size of this octet string in bytes
      */
      u32bit length() const { return bits.size(); }

      /**
      * @return this object as a SecureVector<byte>
      */
      SecureVector<byte> bits_of() const { return bits; }

      /**
      * @return start of this string
      */
      const byte* begin() const { return bits.begin(); }

      /**
      * @return end of this string
      */
      const byte* end() const   { return bits.end(); }

      /**
      * @return this encoded as hex
      */
      std::string as_string() const;

      /**
      * XOR the contents of another octet string into this one
      * @param other octet string
      * @return reference to this
      */
      OctetString& operator^=(const OctetString& other);

      /**
      * Force to have odd parity
      */
      void set_odd_parity();

      /**
      * Change the contents of this octet string
      * @param hex_string a hex encoded bytestring
      */
      void change(const std::string& hex_string);

      /**
      * Change the contents of this octet string
      * @param in the input
      * @param length of in in bytes
      */
      void change(const byte in[], u32bit length);

      /**
      * Change the contents of this octet string
      * @param in the input
      */
      void change(const MemoryRegion<byte>& in) { bits = in; }

      /**
      * Create a new random OctetString
      * @param rng is a random number generator
      * @param len is the desired length in bytes
      */
      OctetString(class RandomNumberGenerator& rng, u32bit len);

      /**
      * Create a new OctetString
      * @param str is a hex encoded string
      */
      OctetString(const std::string& str = "") { change(str); }

      /**
      * Create a new OctetString
      * @param in is an array
      * @param len is the length of in in bytes
      */
      OctetString(const byte in[], u32bit len) { change(in, len); }

      /**
      * Create a new OctetString
      * @param in a bytestring
      */
      OctetString(const MemoryRegion<byte>& in) { change(in); }
   private:
      SecureVector<byte> bits;
   };

/**
* Compare two strings
* @param x an octet string
* @param y an octet string
* @return if x is equal to y
*/
BOTAN_DLL bool operator==(const OctetString& x,
                          const OctetString& y);

/**
* Compare two strings
* @param x an octet string
* @param y an octet string
* @return if x is not equal to y
*/
BOTAN_DLL bool operator!=(const OctetString& x,
                          const OctetString& y);

/**
* Concatenate two strings
* @param x an octet string
* @param y an octet string
* @return x concatenated with y
*/
BOTAN_DLL OctetString operator+(const OctetString& x,
                                const OctetString& y);

/**
* XOR two strings
* @param x an octet string
* @param y an octet string
* @return x XORed with y
*/
BOTAN_DLL OctetString operator^(const OctetString& x,
                                const OctetString& y);

/*
* Alternate Names
*/
typedef OctetString SymmetricKey;
typedef OctetString InitializationVector;

}

#endif
