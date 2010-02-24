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
#include <botan/gfp_modulus.h>
#include <iosfwd>

namespace Botan {

struct BOTAN_DLL Illegal_Transformation : public Exception
   {
   Illegal_Transformation(const std::string& err =
                          "Requested transformation is not possible") :
      Exception(err) {}
   };

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
      * @param use_montgm whether this object will use Montgomery multiplication
      */
      GFpElement(const BigInt& p, const BigInt& value, bool use_montgm = true);

      // GFpElement(const GFpElement& other) = default;

      // const GFpElement& operator=(const GFpElement& other) = default;

      /**
      * Switch Montgomery multiplcation optimizations ON
      */
      void turn_on_sp_red_mul();

      /**
      * Switch Montgomery multiplcation optimizations OFF
      */
      void turn_off_sp_red_mul();

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
      bool is_zero();

      /**
      * return prime number of GF(p)
      * @result a prime number
      */
      const BigInt& get_p() const;

      /**
      * Return the represented value in GF(p)
      * @result The value in GF(p)
      */
      const BigInt& get_value() const;

      /**
      * Tells whether this GFpElement is currently transformed to an m-residue,
      * i.e. in the form x_bar = x * r mod m.
      * @result true if it is currently transformed to its m-residue.
      */
      bool is_trf_to_mres() const;

      /**
      * Transforms this to x_bar = x * r mod m
      * @result return the value x_bar.
      */
      const BigInt& get_mres() const;

      /**
      * Check, if montgomery multiplication is used.
      * @result true, if montgomery multiplication is used, false otherwise
      */
      bool is_use_montgm() const
         {
         return m_use_montgm;
         }

      /**
      * Transforms the arguments in such way that either both
      * are in m-residue representation (returns true) or both are
      * in ordinary residue representation (returns false).
      * m-residue is prefered in case of ambiguity.
      * does not toggle m_use_montgm of the arguments.
      * Don't be confused about the constness of the arguments:
      * the transformation between normal residue and m-residue is
      * considered as leaving the object const.
      * @param lhs the first operand to be aligned
      * @param rhs the second operand to be aligned
      * @result true if both are transformed to their m-residue,
      * false it both are transformed to their normal residue.
      */
      static bool align_operands_res(const GFpElement& lhs, const GFpElement& rhs);

      /**
      * swaps the states of *this and other, does not throw!
      * @param other The value to swap with
      */
      void swap(GFpElement& other);
   private:
      void ensure_montgm_precomp();
      void trf_to_mres() const;
      void trf_to_ordres() const;

      GFpModulus modulus;
      mutable BigInt m_value; // ordinary residue or m-residue respectively

      // data members for montgomery multiplication
      bool m_use_montgm;
      mutable bool m_is_trf; // if m_value is montgomery
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


/**
* write a GFpElement to an output stream.
* @param output the output stream to write to
* @param elem the object to write
* @result the output stream
*/
BOTAN_DLL std::ostream& operator<<(std::ostream& output, const GFpElement& elem);

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
