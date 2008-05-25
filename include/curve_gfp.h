/******************************************************
 * Elliptic curves over GF(p) (header file)           *
 *                                                    *
 * (C) 2007 Martin Doering                             *
 *          doering@cdc.informatik.tu-darmstadt.de    *
 *          Christoph Ludwig                          *
 *          ludwig@fh-worms.de                        *
 *          Falko Strenzke                            *
 *          strenzke@flexsecure.de                    *
 ******************************************************/

#ifndef BOTAN_MATH_EC_CURVE_GFP_H_GUARD_
#define BOTAN_MATH_EC_CURVE_GFP_H_GUARD_

#include <botan/gfp_element.h>
#include <botan/bigint.h>
#include <botan/freestore.h>

namespace Botan {

/**
* This class represents an elliptic curve over GF(p)
*/
class CurveGFp {

public:
   /**
   * Construct the elliptic curve E: y^2 = x^3 + ax + b over GF(p)
   * @param a first coefficient
   * @param b second coefficient
   * @param p prime number of the field
   */
   CurveGFp(GFpElement const& a, GFpElement const& b,
            BigInt const& p);

   /**
   * Copy constructor
   * @param other The curve to clone
   */
   CurveGFp(CurveGFp const& other);

   /**
   * Assignment operator
   * @param other The curve to use as source for the assignment
   */
   CurveGFp const& operator=(CurveGFp const& other);

   /**
   * Set the shared GFpModulus object.
   * Warning: do not use this function unless you know in detail how
   * the sharing of values
   * in the various EC related objects works.
   * Do NOT spread pointers to a GFpModulus over different threads!
   * @param mod a shared pointer to a GFpModulus object suitable for
   * *this.
   */
   void set_shrd_mod(SharedPtrConverter<Botan::math::GFpModulus> const mod);

   // getters

   /**
   * Get coefficient a
   * @result coefficient a
   */
   GFpElement const get_a() const;

   /**
   * Get coefficient b
   * @result coefficient b
   */
   GFpElement const get_b() const;

   /**
   * Get the GFpElement coefficient a  transformed
   * to it´s m-residue. This can be used for efficency reasons: the curve
   * stores the transformed version after the first invocation of this
   * function.
   * @result the coefficient a, transformed to it´s m-residue
   */
   GFpElement const get_mres_a() const;

   /**
   * Get the GFpElement coefficient b transformed
   * to it´s m-residue. This can be used for efficency reasons: the curve
   * stores the transformed version after the first invocation of this
   * function.
   * @result the coefficient b, transformed to it´s m-residue
   */
   GFpElement const get_mres_b() const;


   /**
   * Get the GFpElement 1  transformed
   * to it´s m-residue. This can be used for efficency reasons: the curve
   * stores the transformed version after the first invocation of this
   * function.
   * @result the GFpElement 1, transformed to it´s m-residue
   */
   std::tr1::shared_ptr<GFpElement const> const get_mres_one() const;

   /**
   * Get prime modulus of the field of the curve
   * @result prime modulus of the field of the curve
   */
   BigInt const get_p() const;
   /*inline std::tr1::shared_ptr<BigInt> const get_ptr_p() const
   {
   return mp_p;
   }*/

   /**
   * Retrieve a shared pointer to the curves GFpModulus object for efficient storage
   * and computation of montgomery multiplication related data members and functions.
   * Warning: do not use this function unless you know in detail how the sharing of values
   * in the various EC related objects works.
   * Do NOT spread pointers to a GFpModulus over different threads!
   * @result a shared pointer to a GFpModulus object
   */
   inline std::tr1::shared_ptr<Botan::math::GFpModulus> const get_ptr_mod() const
      {
      return mp_mod;
      }

   /**
   * swaps the states of *this and other, does not throw
   * @param other The curve to swap values with
   */
   void swap(CurveGFp& other);

private:
   std::tr1::shared_ptr<Botan::math::GFpModulus> mp_mod;
   GFpElement mA;
   GFpElement mB;
   mutable std::tr1::shared_ptr<GFpElement> mp_mres_a;
   mutable std::tr1::shared_ptr<GFpElement> mp_mres_b;
   mutable std::tr1::shared_ptr<GFpElement> mp_mres_one;

   };

// relational operators
bool operator==(CurveGFp const& lhs, CurveGFp const& rhs);
inline bool operator!=(CurveGFp const& lhs, CurveGFp const& rhs) {
return !operator==(lhs, rhs);
}

// io operators
std::ostream& operator<<(std::ostream& output, const CurveGFp& elem);

// swaps the states of curve1 and curve2, does not throw!
// cf. Meyers, Item 25
inline
void swap(CurveGFp& curve1, CurveGFp& curve2) {
curve1.swap(curve2);
}

}

namespace std {

template<> inline void swap<::Botan::math::ec::CurveGFp>(
   ::Botan::math::ec::CurveGFp& curve1,
   ::Botan::math::ec::CurveGFp& curve2)
   {
   curve1.swap(curve2);
   }

#endif
