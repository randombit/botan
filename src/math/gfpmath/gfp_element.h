/*
* Arithmetic for prime fields GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_GFP_ELEMENT_H__
#define BOTAN_GFP_ELEMENT_H__

#include <botan/bigint.h>
#include <botan/numthry.h>

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
      GFpElement& operator+=(const GFpElement& rhs)
         {
         m_value += rhs.m_value;
         if(m_value >= mod_p)
            m_value -= mod_p;

         return *this;
         }

      /**
      * -= Operator
      * @param rhs the GFpElement to subtract from the local value
      * @result *this
      */
      GFpElement& operator-=(const GFpElement& rhs)
         {
         m_value -= rhs.m_value;
         if(m_value.is_negative())
            m_value += mod_p;

         return *this;
         }

      /**
      * *= Operator
      * @param rhs the value to multiply with the local value
      * @result *this
      */
      GFpElement& operator*=(u32bit rhs)
         {
         m_value *= rhs;
         m_value %= mod_p;
         return *this;
         }

      /**
      * *= Operator
      * @param rhs the GFpElement to multiply with the local value
      * @result *this
      */
      GFpElement& operator*=(const GFpElement& rhs)
         {
         m_value *= rhs.m_value;
         m_value %= mod_p;
         return *this;
         }

      /**
      * /= Operator
      * @param rhs the GFpElement to divide the local value by
      * @result *this
      */
      GFpElement& operator/=(const GFpElement& rhs)
         {
         GFpElement inv_rhs(rhs);
         inv_rhs.inverse_in_place();
         *this *= inv_rhs;
         return *this;
         }

      /**
      * Negate internal value(*this *= -1 )
      * @return *this
      */
      GFpElement& negate()
         {
         m_value = mod_p - m_value;
         return *this;
         }

      /**
      * Assigns the inverse of *this to *this, i.e.
      * *this = (*this)^(-1)
      * @result *this
      */
      GFpElement& inverse_in_place()
         {
         m_value = inverse_mod(m_value, mod_p);
         return *this;
         }

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
      void swap(GFpElement& other)
         {
         std::swap(m_value, other.m_value);
         std::swap(mod_p, other.mod_p);
         }

      bool operator==(const GFpElement& other) const
         {
         return (m_value == other.m_value && mod_p == other.mod_p);
         }

   private:
      BigInt mod_p; // modulus
      BigInt m_value;
   };

inline bool operator!=(const GFpElement& lhs, const GFpElement& rhs )
   {
   return !(lhs == rhs);
   }

// arithmetic operators
inline GFpElement operator+(const GFpElement& lhs, const GFpElement& rhs)
   {
   GFpElement result(lhs);
   result += rhs;
   return result;
   }

inline GFpElement operator-(const GFpElement& lhs, const GFpElement& rhs)
   {
   GFpElement result(lhs);
   result -= rhs;
   return result;
   }

inline GFpElement operator-(const GFpElement& lhs)
   {
   return(GFpElement(lhs)).negate();
   }

inline GFpElement operator*(const GFpElement& lhs, u32bit rhs)
   {
   GFpElement result(lhs);
   result *= rhs;
   return result;
   }

inline GFpElement operator*(const GFpElement& lhs, const GFpElement& rhs)
   {
   GFpElement result(lhs);
   result *= rhs;
   return result;
   }

inline GFpElement operator*(u32bit rhs, const GFpElement& lhs)
   {
   return rhs*lhs;
   }

inline GFpElement operator/(const GFpElement& lhs, const GFpElement& rhs)
   {
   GFpElement result (lhs);
   result /= rhs;
   return result;
   }

// return (*this)^(-1)
inline GFpElement inverse(const GFpElement& elem)
   {
   return GFpElement(elem).inverse_in_place();
   }

// encoding and decoding
inline SecureVector<byte> FE2OSP(const GFpElement& elem)
   {
   return BigInt::encode_1363(elem.get_value(), elem.get_p().bytes());
   }

inline GFpElement OS2FEP(const MemoryRegion<byte>& os, const BigInt& p)
   {
   return GFpElement(p, BigInt::decode(os.begin(), os.size()));
   }

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
