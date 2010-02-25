/*
* Arithmetic for prime fields GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2009-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_GFP_ELEMENT_H__
#define BOTAN_GFP_ELEMENT_H__

#include <botan/bigint.h>

namespace Botan {

/**
 * This class represents one element in GF(p). Enables the convenient,
 * transparent use of the montgomery multiplication.
 */
class BOTAN_DLL GFpElement
   {
   public:

      /** construct an element of GF(p) with the given value.
      * use_montg defaults to false and determines wether Montgomery
      * multiplications will be use when applying operators *, *=
      * @param p the prime number of the field
      * @param value the element value
      */
      GFpElement(const BigInt& p, const BigInt& value) :
         mod_p(p), m_value(value % p) {}

      // GFpElement(const GFpElement& other) = default;
      // const GFpElement& operator=(const GFpElement& other) = default;

      /**
      * += Operator
      * @param rhs the GFpElement to add to the local value
      * @result *this
      */
      GFpElement& operator+=(const GFpElement& rhs);

      /**
      * -= Operator
      * @param rhs the GFpElement to subtract from the local value
      * @result *this
      */
      GFpElement& operator-=(const GFpElement& rhs);

      /**
      * *= Operator
      * @param rhs the GFpElement to multiply with the local value
      * @result *this
      */
      GFpElement& operator*=(const GFpElement& rhs);
      /**
      * /= Operator
      * @param rhs the GFpElement to divide the local value by
      * @result *this
      */
      GFpElement& operator/=(const GFpElement& rhs);

      /**
      * *= Operator
      * @param rhs the value to multiply with the local value
      * @result *this
      */
      GFpElement& operator*=(u32bit rhs);

      /**
      * Negate internal value(*this *= -1 )
      * @return *this
      */
      GFpElement& negate();

      /**
      * Assigns the inverse of *this to *this, i.e.
      * *this = (*this)^(-1)
      * @result *this
      */
      GFpElement& inverse_in_place();

      /**
      * checks whether the value is zero (without provoking
      * a backtransformation to the ordinary-residue)
      * @result true, if the value is zero, false otherwise.
      */
      bool is_zero() const { return m_value.is_zero(); }

      /**
      * return prime number of GF(p)
      * @result a prime number
      */
      const BigInt& get_p() const { return mod_p; }

      /**
      * Return the represented value in GF(p)
      * @result The value in GF(p)
      */
      const BigInt& get_value() const { return m_value; }

      /**
      * swaps the states of *this and other, does not throw!
      * @param other The value to swap with
      */
      void swap(GFpElement& other);
   private:
      BigInt mod_p; // modulus
      BigInt m_value;
   };

// relational operators
bool BOTAN_DLL operator==(const GFpElement& lhs, const GFpElement& rhs);
inline bool operator!=(const GFpElement& lhs, const GFpElement& rhs )
   {
   return !operator==(lhs, rhs);
   }

// arithmetic operators
GFpElement BOTAN_DLL operator+(const GFpElement& lhs, const GFpElement& rhs);
GFpElement BOTAN_DLL operator-(const GFpElement& lhs, const GFpElement& rhs);
GFpElement BOTAN_DLL operator-(const GFpElement& lhs);

GFpElement BOTAN_DLL operator*(const GFpElement& lhs, const GFpElement& rhs);
GFpElement BOTAN_DLL operator/(const GFpElement& lhs, const GFpElement& rhs);
GFpElement BOTAN_DLL operator*(const GFpElement& lhs, u32bit rhs);
GFpElement BOTAN_DLL operator*(u32bit rhs, const GFpElement& lhs);

// return (*this)^(-1)
GFpElement BOTAN_DLL inverse(const GFpElement& elem);

// encoding and decoding
SecureVector<byte> BOTAN_DLL FE2OSP(const GFpElement& elem);
GFpElement BOTAN_DLL OS2FEP(MemoryRegion<byte> const& os, BigInt p);

inline void swap(GFpElement& x, GFpElement& y)
   {
   x.swap(y);
   }

}

namespace std {

template<> inline
void swap<Botan::GFpElement>(Botan::GFpElement& x,
                             Botan::GFpElement& y)
   {
   x.swap(y);
   }

}

#endif
