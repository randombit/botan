/******
 * Arithmetic for prime fields GF(p) (header file)
 *
 * (C) 2007 Martin Doering
 *          doering@cdc.informatik.tu-darmstadt.de
 *          Christoph Ludwig
 *          ludwig@fh-worms.de
 *          Falko Strenzke
 *          strenzke@flexsecure.de
 ******/

#ifndef BOTAN_GFP_ELEMENT_H__
#define BOTAN_GFP_ELEMENT_H__

#include <botan/bigint.h>
#include <botan/gfp_modulus.h>
#include <iosfwd>

#if defined(BOTAN_USE_STD_TR1)
  #include <tr1/memory>
#elif defined(BOTAN_USE_BOOST_TR1)
  #include <boost/tr1/memory.hpp>
#else
  #error "Please choose a TR1 implementation in build.h"
#endif

namespace Botan {

struct Illegal_Transformation : public Exception
   {
   Illegal_Transformation(const std::string& err =
                          "Requested transformation is not possible")
      : Exception(err) {}
   };

/**
 * This class represents one element in GF(p). Enables the convenient,
 * transparent use of the montgomery multiplication.
 */
class BOTAN_DLL GFpElement
   {
   private:
      std::tr1::shared_ptr<GFpModulus> mp_mod;
      mutable BigInt m_value; // ordinary residue or m-residue respectively
      mutable BigInt workspace;

      // *****************************************
      // data members for montgomery multiplication
      mutable bool m_use_montgm;
      //mutable BigInt m_mres;
      // this bool tells use whether the m_mres carries
      // the actual value (in this case mValue doesn´t)
      mutable bool m_is_trf;

      void ensure_montgm_precomp() const;
      void trf_to_mres() const;
      void trf_to_ordres() const;

   public:

      /** construct an element of GF(p) with the given value.
      * use_montg defaults to false and determines wether Montgomery
      * multiplications will be use when applying operators *, *=
      * @param p the prime number of the field
      * @param value the element value
      * @param use_montgm whether this object will use Montgomery multiplication
      */
      explicit GFpElement (const BigInt& p, const BigInt& value, bool use_montgm = false);


      /** construct an element of GF(p) with the given value (defaults
      * to 0).  use_montg defaults to false and determines wether
      * montgomery multiplications will be use when applying operators
      * '*' , '*='.  Use this constructor for efficient use of
      * Montgomery multiplication in a context with a fixed a modulus.
      * Warning: do not use this function unless you know in detail
      * about the implications of using the shared GFpModulus objects!
      * @param mod shared pointer to the GFpModulus to be shared
      * @param value the element value
      * @param use_montgm whether this object will use Montgomery multiplication
      */
      explicit GFpElement(std::tr1::shared_ptr<GFpModulus> const mod,
                          const BigInt& value, bool use_mongm = false);

      /**
      * Copy constructor
      * @param other The element to clone
      */
      GFpElement(const GFpElement& other);

      /**
      * Assignment operator.
      * makes *this a totally independent object
      * (gives *this independent modulus specific values).

      * @param other The element to assign to our object
      */
      const GFpElement& operator=(const GFpElement& other);

      /**
      * Works like the assignment operator, but lets
      * *this share the modulus dependend value with other.
      * Warning: do not use this function unless you know in detail about
      * the implications of using
      * the shared GFpModulus objects!
      * @param other The element to assign to our object
      */
      void share_assign(const GFpElement& other);

      /**
      * Switch Montgomery multiplcation optimizations ON
      */
      void turn_on_sp_red_mul() const;

      /**
      * Switch Montgomery multiplcation optimizations OFF
      */
      void turn_off_sp_red_mul() const;

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
      GFpElement& operator*= (u32bit rhs);

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
      * Returns the shared pointer to the GFpModulus of *this.
      * Warning: do not use this function unless you know in detail about
      * the implications of using
      * the shared GFpModulus objects!
      * @result the shared pointer to the GFpModulus of *this
      */
      inline std::tr1::shared_ptr<GFpModulus> const get_ptr_mod() const
         {
         return mp_mod;
         }


      /**
      * Sets the shared pointer to the GFpModulus of *this.
      * Warning: do not use this function unless you know in detail about
      * the implications of using
      * the shared GFpModulus objects!
      * @param mod a shared pointer to a GFpModulus that will be held in *this
      */
      void set_shrd_mod(std::tr1::shared_ptr<GFpModulus> const mod);

      /**
      * Tells whether this GFpElement is currently transformed to it´ m-residue,
      * i.e. in the form x_bar = x * r mod m.
      * @result true if it is currently transformed to it´s m-residue.
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
      * Don´t be confused about the constness of the arguments:
      * the transformation between normal residue and m-residue is
      * considered as leaving the object const.
      * @param lhs the first operand to be aligned
      * @param rhs the second operand to be aligned
      * @result true if both are transformed to their m-residue,
      * false it both are transformed to their normal residue.
      */
      static bool align_operands_res(const GFpElement& lhs, const GFpElement& rhs);

      //friend declarations for non-member functions

      /**
      * write a GFpElement to an output stream.
      * @param output the output stream to write to
      * @param elem the object to write
      * @result the output stream
      */
      friend std::ostream& operator<<(std::ostream& output, const GFpElement& elem);

      friend class Point_Coords_GFp;

      /**
      * swaps the states of *this and other, does not throw!
      * @param other The value to swap with
      */
      void swap(GFpElement& other);

   };

// relational operators
bool operator==(const GFpElement& lhs, const GFpElement& rhs);
inline bool operator!=(const GFpElement& lhs, const GFpElement& rhs )
   {
   return !operator==(lhs, rhs);
   }

// arithmetic operators
GFpElement operator+(const GFpElement& lhs, const GFpElement& rhs);
GFpElement operator-(const GFpElement& lhs, const GFpElement& rhs);
GFpElement operator-(const GFpElement& lhs);

GFpElement operator*(const GFpElement& lhs, const GFpElement& rhs);
GFpElement operator/(const GFpElement& lhs, const GFpElement& rhs);
GFpElement operator* (const GFpElement& lhs, u32bit rhs);
GFpElement operator* (u32bit rhs, const GFpElement& lhs);

// io operators
std::ostream& operator<<(std::ostream& output, const GFpElement& elem);

// return (*this)^(-1)
GFpElement inverse(const GFpElement& elem);

// encoding and decoding
SecureVector<byte> FE2OSP(const GFpElement& elem);
GFpElement OS2FEP(MemoryRegion<byte> const& os, BigInt p);

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
