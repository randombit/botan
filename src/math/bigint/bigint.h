/*
* BigInt
* (C) 1999-2008 Jack Lloyd
*     2007 FlexSecure
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BIGINT_H__
#define BOTAN_BIGINT_H__

#include <botan/rng.h>
#include <botan/secmem.h>
#include <botan/mp_types.h>
#include <iosfwd>

namespace Botan {

/**
 * Big Integer representation.  This class defines an integer type,
 * that can be very big. Additionally some helper functions are
 * defined to work more comfortably.

 */
class BOTAN_DLL BigInt
   {
   public:
      /**
       * Base-Enumerator (currently 8,10,16 and 256 are defined)
       */
      enum Base { Octal = 8, Decimal = 10, Hexadecimal = 16, Binary = 256 };

      /**
       * Sign symbol definitions for positive and negative numbers
       */
      enum Sign { Negative = 0, Positive = 1 };

      /**
       * Number types (Powers of 2)
       */
      enum NumberType { Power2 };

      /**
       * DivideByZero Exception
       */
      struct DivideByZero : public Exception
         { DivideByZero() : Exception("BigInt divide by zero") {} };

      /*************
      * operators
      *************/

      /**
       * += Operator
       * @param y the BigInt to add to the local value
       */
      BigInt& operator+=(const BigInt& y);

      /**
       * -= Operator
       * @param y the BigInt to subtract from the local value
       */
      BigInt& operator-=(const BigInt& y);

      /**
       * *= Operator
       * @param y the BigInt to multiply with the local value
       */
      BigInt& operator*=(const BigInt& y);

      /**
       * /= Operator
       * @param y the BigInt to divide the local value by
       */
      BigInt& operator/=(const BigInt& y);

      /**
       * %= Operator, modulo operator.
       * @param y the modulus to reduce the local value by
       */
      BigInt& operator%=(const BigInt& y);

      /**
       * %= Operator
       * @param y the modulus (word) to reduce the local value by
       */
      word    operator%=(word y);

      /**
       * <<= Operator
       * @param y the amount of bits to shift the local value left
       */
      BigInt& operator<<=(u32bit y);

      /**
       * >>= Operator
       * @param y the amount of bits to shift the local value right
       */
      BigInt& operator>>=(u32bit y);

      /**
       * ++ Operator
       */
      BigInt& operator++() { return (*this += 1); }

      /**
       * -- Operator
       */
      BigInt& operator--() { return (*this -= 1); }

      /**
       * ++ Operator (postfix)
       */
      BigInt  operator++(int) { BigInt x = (*this); ++(*this); return x; }

      /**
       * -- Operator (postfix)
       */
      BigInt  operator--(int) { BigInt x = (*this); --(*this); return x; }

      /**
       * - Operator
       */
      BigInt operator-() const;

      /**
       * ! Operator
       */
      bool operator !() const { return (!is_nonzero()); }

      /**
       * [] Operator (array access)
       */
      word& operator[](u32bit i) { return reg[i]; }

      /**
       * [] Operator (array access)
       */
      word operator[](u32bit i) const { return reg[i]; }

      /**
       * Zeroize the BigInt
      */
      void clear() { get_reg().clear(); }

      /*************
      * functions
      ************/

      /**
       * Compare *this to another BigInt.
       * @param n the BigInt value to compare to the local value.
       * @param check_signs Include sign in comparison?
       * @result if (this<n) return -1, if (this>n) return 1, if both
       * values are identical return 0.
       */
      s32bit cmp(const BigInt& n, bool check_signs = true) const;

      /**
       * Test if the integer has an even value
       * @result true, if the integer an even value, false otherwise
       */
      bool is_even() const { return (get_bit(0) == 0); }

      /**
       * Test if the integer has an odd value
       * @result true, if the integer an odd value, false otherwise
       */
      bool is_odd()  const { return (get_bit(0) == 1); }

      /**
       * Test if the integer is not zero.
       * @result true, if the integer has a non-zero value, false otherwise
       */
      bool is_nonzero() const { return (!is_zero()); }

      /**
       * Test if the integer is zero.
       * @result true, if the integer has the value zero, false otherwise
       */
      bool is_zero() const
         {
         const u32bit sw = sig_words();

         for(u32bit i = 0; i != sw; ++i)
            if(reg[i])
               return false;
         return true;
         }

      /**
       * Set bit at specified position
       * @param n bit position to set
       */
      void set_bit(u32bit n);

      /**
      * Clear bit at specified position
       * @param n bit position to clear
      */
      void clear_bit(u32bit n);

      /**
       * Clear all but the lowest n bits
       * @param n amount of bits to keep
       */
      void mask_bits(u32bit n);

      /**
       * Return bit value at specified position
       * @param n the bit offset to test
       * @result true, if the bit at position n is set, false otherwise
       */
      bool get_bit(u32bit n) const;

      /**
       * Return (a maximum of) 32 bits of the complete value
       * @param offset the offset to start extracting
       * @param length amount of bits to extract (starting at offset)
       * @result the integer extracted from the register starting at
       * offset with specified length
       */
      u32bit get_substring(u32bit offset, u32bit length) const;

      byte byte_at(u32bit) const;

      /**
       * Return the word at a specified position of the internal register
       * @param n position in the register
       * @return the value at position n
       */
      word word_at(u32bit n) const
         { return ((n < size()) ? reg[n] : 0); }

      /**
       * Return the integer as an unsigned 32bit-integer-value. If the
       * value is negative OR to big to be stored in 32bits, this
       * function will throw an exception.
       * @result a 32bit-integer
       */
      u32bit to_u32bit() const;

      /**
       * Tests if the sign of the integer is negative.
       * @result true, if the integer has a negative sign,
       */
      bool is_negative() const { return (sign() == Negative); }

      /**
       * Tests if the sign of the integer is positive.
       * @result true, if the integer has a positive sign,
       */
      bool is_positive() const { return (sign() == Positive); }

      /**
       * Return the sign of the integer
       * @result the sign of the integer
       */
      Sign sign() const        { return (signedness); }

      /**
       * Return the opposite sign of the represented integer value
       * @result the opposite sign of the represented integer value
       */
      Sign reverse_sign() const;

      /**
       * Flip (change!) the sign of the integer to its opposite value
       */
      void flip_sign();

      /**
       * Set sign of the integer
       * @param sign new Sign to set
       */
      void set_sign(Sign sign);

      /**
       * Give absolute (positive) value of the integer
       * @result absolute (positive) value of the integer
       */
      BigInt abs() const;

      /**
       * Give size of internal register
       * @result size of internal register in words
       */
      u32bit size() const { return get_reg().size(); }

      /**
       * Give significant words of the represented integer value
       * @result significant words of the represented integer value
       */
      u32bit sig_words() const
         {
         const word* x = reg.begin();
         u32bit sig = reg.size();

         while(sig && (x[sig-1] == 0))
            sig--;
         return sig;
         }

      /**
       * Give byte-length of the integer
       * @result byte-length of the represented integer value
       */
      u32bit bytes() const;

      /**
       * Get the bit-length of the integer.
       * @result bit-length of the represented integer value
       */
      u32bit bits() const;

      /**
       * Return a pointer to the big integer word register.
       * @result a pointer to the start of the internal register of
       * the integer value
       */
      const word* data() const { return reg.begin(); }

      /**
       * return a reference to the internal register containing the value
       * @result a reference to the word-array (SecureVector<word>)
       * with the internal register value (containing the integer
       * value)
       */
      SecureVector<word>& get_reg() { return reg; }

      /**
       * return a const reference to the internal register containing the value
       * @result a const reference to the word-array (SecureVector<word>)
       * with the internal register value (containing the integer
       * value)
       */
      const SecureVector<word>& get_reg() const { return reg; }

      /**
       * Increase internal register buffer by n words
       * @param n increase by n words
       */
      void grow_reg(u32bit n);

      void grow_to(u32bit n);

      /**
       * Fill BigInt with a random number with size of bitsize
       * @param rng the random number generator to use
       * @param bitsize number of bits the created random value should have
       */
      void randomize(RandomNumberGenerator& rng, u32bit bitsize = 0);

      /**
       * Store BigInt-value in a given byte array
       * @param buf destination byte array for the integer value
       */
      void binary_encode(byte buf[]) const;

      /**
       * Read integer value from a byte array with given size
       * @param buf byte array buffer containing the integer
       * @param length size of buf
       */
      void binary_decode(const byte buf[], u32bit length);

      /**
       * Read integer value from a byte array (MemoryRegion<byte>)
       * @param buf the BigInt value to compare to the local value.
       */
      void binary_decode(const MemoryRegion<byte>& buf);

      u32bit encoded_size(Base = Binary) const;

      /**
        @param rng a random number generator
        @result a random integer between min and max
      */
      static BigInt random_integer(RandomNumberGenerator& rng,
                                   const BigInt& min, const BigInt& max);

      /**
       * Encode the integer value from a BigInt to a SecureVector of bytes
       * @param n the BigInt to use as integer source
       * @param base number-base of resulting byte array representation
       * @result SecureVector of bytes containing the integer with given base
       */
      static SecureVector<byte> encode(const BigInt& n, Base base = Binary);

      /**
       * Encode the integer value from a BigInt to a byte array
       * @param buf destination byte array for the encoded integer
       * value with given base
       * @param n the BigInt to use as integer source
       * @param base number-base of resulting byte array representation
       */
      static void encode(byte buf[], const BigInt& n, Base base = Binary);

      /**
       * Create a BigInt from an integer in a byte array
       * @param buf the BigInt value to compare to the local value.
       * @param length size of buf
       * @param base number-base of the integer in buf
       * @result BigInt-representing the given integer read from the byte array
       */
      static BigInt decode(const byte buf[], u32bit length,
                           Base base = Binary);

      static BigInt decode(const MemoryRegion<byte>&, Base = Binary);

      /**
       * Encode a Big Integer to a byte array according to IEEE1363.
       * @param n the Big Integer to encode
       * @param bytes the length of the resulting SecureVector<byte>
       * @result a SecureVector<byte> containing the encoded Big Integer
       */
      static SecureVector<byte> encode_1363(const BigInt& n, u32bit bytes);

      /**
       * Swap BigInt-value with given BigInt.
       * @param bigint the BigInt to swap values with
       */
      void swap(BigInt& bigint);

      /**
      * constructors
      */

      /**
       * Create empty BigInt
       */
      BigInt() { signedness = Positive; }

      /**
       * Create BigInt from 64bit-Integer value
       * @param n 64bit-integer
       */
      BigInt(u64bit n);

      /**
       * Copy-Constructor: clone given BigInt
       * @param bigint the BigInt to clone
       */
      BigInt(const BigInt& bigint);

      /**
       * Create BigInt from a string.
       * If the string starts with 0x the rest of the string will be
       * interpreted as hexadecimal digits.
       * If the string starts with 0 and the second character is NOT
       * an 'x' the string will be interpreted as octal digits.
       * If the string starts with non-zero digit, it will be
       * interpreted as a decimal number.
       * @param str the string to parse for an integer value
       */
      BigInt(const std::string& str);

      /**
       * Create a BigInt from an integer in a byte array
       * @param buf the BigInt value to compare to the local value.
       * @param length size of buf
       * @param base number-base of the integer in buf
       */
      BigInt(const byte buf[], u32bit length, Base base = Binary);

      /**
       * Create a random BigInt of the specified size
       * @param rng random number generator
       * @param bits size in bits
       */
      BigInt(RandomNumberGenerator& rng, u32bit bits);

      /**
       * Create BigInt from unsigned 32 bit integer value and an
       * also specify the sign of the value
       * @param n integer value
       */
      BigInt(Sign, u32bit n);

      /**
       * Create a number of the specified type and size
       * @param type the type of number to create
       * @param n the size
       */
      BigInt(NumberType type, u32bit n);

   private:
      SecureVector<word> reg;
      Sign signedness;
   };

/*
* Arithmetic Operators
*/
BigInt BOTAN_DLL operator+(const BigInt&, const BigInt&);
BigInt BOTAN_DLL operator-(const BigInt&, const BigInt&);
BigInt BOTAN_DLL operator*(const BigInt&, const BigInt&);
BigInt BOTAN_DLL operator/(const BigInt&, const BigInt&);
BigInt BOTAN_DLL operator%(const BigInt&, const BigInt&);
word   BOTAN_DLL operator%(const BigInt&, word);
BigInt BOTAN_DLL operator<<(const BigInt&, u32bit);
BigInt BOTAN_DLL operator>>(const BigInt&, u32bit);

/*
* Comparison Operators
*/
inline bool operator==(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) == 0); }
inline bool operator!=(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) != 0); }
inline bool operator<=(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) <= 0); }
inline bool operator>=(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) >= 0); }
inline bool operator<(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) < 0); }
inline bool operator>(const BigInt& a, const BigInt& b)
   { return (a.cmp(b) > 0); }

/*
* I/O Operators
*/
BOTAN_DLL std::ostream& operator<<(std::ostream&, const BigInt&);
BOTAN_DLL std::istream& operator>>(std::istream&, BigInt&);

}

namespace std {

inline void swap(Botan::BigInt& a, Botan::BigInt& b) { a.swap(b); }

}

#endif
