/*
* Arithmetic over GF(p)
*
* (C) 2007 Martin Doering
*          Christoph Ludwig
*          Falko Strenzke
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_POINT_GFP_H__
#define BOTAN_POINT_GFP_H__

#include <botan/curve_gfp.h>
#include <botan/gfp_element.h>
#include <botan/bigint.h>
#include <botan/exceptn.h>
#include <vector>

namespace Botan {

struct Illegal_Point : public Exception
   {
   Illegal_Point(const std::string& err = "") : Exception(err) {}
   };

/**
* This class represents one point on a curve of GF(p).
*/
class BOTAN_DLL PointGFp
   {
   public:
      /**
      * uncompressed encoding byte value
      */
      static const int UNCOMPRESSED = 0;

      /**
      * compressed encoding byte value
      */
      static const int COMPRESSED = 1;

      /**
      * hybrid encoding byte value
      */
      static const int HYBRID = 2;

      /**
      * Construct the point O
      * @param curve The base curve
      */
      explicit PointGFp(const CurveGFp& curve);

      /**
      * Construct a point given its affine coordinates
      * @param curve the base curve
      * @param x affine x coordinate
      * @param y affine y coordinate
      */
      explicit PointGFp(const CurveGFp& curve, GFpElement const& x,
                          GFpElement const& y);

      /**
      * Construct a point given its jacobian projective coordinates
      * @param curve the base curve
      * @param x jacobian projective x coordinate
      * @param y jacobian projective y coordinate
      * @param z jacobian projective y coordinate
      */
      explicit PointGFp(const CurveGFp& curve, GFpElement const& x,
                          GFpElement const& y, GFpElement const& z);

      /**
      * copy constructor
      * @param other the value to clone
      */
      PointGFp(const PointGFp& other);

      /**
      * assignment operator
      * @param other The point to use as source for the assignment
      */
      const PointGFp& operator=(const PointGFp& other);

      /**
      * assign another point which is on the same curve as *this
      * @param other The point to use as source for the assignment
      */
      const PointGFp& assign_within_same_curve(const PointGFp& other);



      /**
      * += Operator
      * @param rhs the PointGFp to add to the local value
      * @result resulting PointGFp
      */
      PointGFp& operator+=(const PointGFp& rhs);

      /**
      * -= Operator
      * @param rhs the PointGFp to subtract from the local value
      * @result resulting PointGFp
      */
      PointGFp& operator-=(const PointGFp& rhs);

      /**
      * *= Operator
      * This function turns on the the special reduction multiplication
      * itself for fast computation, turns it off again when finished.
      * @param scalar the PointGFp to multiply with *this
      * @result resulting PointGFp
      */
      PointGFp& operator*=(const BigInt& scalar);

      /**
      * the equivalent to operator*= with countermeasures against
      * sidechannel attacks, using the randomized exponent
      * and add-and-double-always
      * countermeasures (suitable for ECDSA and ECKAEG)
      * @param scalar the scalar to multiply the point with
      * @param point_order a multiple of the order of the point
      *(= n * k in the general case; k is the cofactor)
      * @param max_secr the maximal size of the scalar
      * (will usually be  n-1 )
      * @result resulting PointGFp
      */
      PointGFp& mult_this_secure(const BigInt& scalar,
                                 const BigInt& point_order,
                                 const BigInt& max_secr
        );

      /**
      * Negate internal value(*this *= -1 )
      * @return *this
      */
      PointGFp& negate();

      /**
      * Multiply the point by two(*this *= 2 )
      * @return *this
      */
      PointGFp& mult2_in_place();

      /**
      * Set z coordinate to one.
      * @return *this
      */
      const PointGFp& set_z_to_one() const;

      /**
      * Turn on the special reduction multiplication (i.e. the
      * Montgomery multiplication in the current implementation) for
      * the coordinates. This enables fast execution of mult2_in_place()
      * and operator+=().
      */
      void turn_on_sp_red_mul() const;

      /**
      * Return a point
      * where the coordinates are transformed
      * so that z equals one,
      * thus x and y have just the affine values.
      * @result *this
      */
      PointGFp const get_z_to_one() const;

      /**
      * Return base curve of this point
      * @result the curve over GF(p) of this point
      */
      CurveGFp const get_curve() const;

      /**
      * get affine x coordinate
      * @result affine x coordinate
      */
      GFpElement const get_affine_x() const;

      /**
      * get affine y coordinate
      * @result affine y coordinate
      */
      GFpElement const get_affine_y() const;

      /**
      * get the jacobian projective x coordinate
      * @result jacobian projective x coordinate
      */
      GFpElement const get_jac_proj_x() const;

      /**
      * get the jacobian projective y coordinate
      * @result jacobian projective y coordinate
      */
      GFpElement const get_jac_proj_y() const;

      /**
      * get the jacobian projective z coordinate
      * @result jacobian projective z coordinate
      */
      GFpElement const get_jac_proj_z() const;

      /**
      * Is this the point at infinity?
      * @result true, if this point is at infinity, false otherwise.
      */
      bool is_zero() const;

      /**
      *  Checks whether the point is to be found on the underlying curve.
      *  Throws an Invalid_Point exception in case of detecting that the point
      *  does not satisfy the curve equation.
      *  To be used to ensure against fault attacks.
      */
      void check_invariants() const;


      /**
      *  swaps the states of *this and other, does not throw!
      * @param other the object to swap values with
      */
      void swap(PointGFp& other);

      /**
      * Sets the shared pointer to the GFpModulus that will be
      * held in *this, specifically the various members of *this.
      * Warning: do not use this function unless you know in detail about
      * the implications of using
      * the shared GFpModulus objects!
      * Do NOT spread a shared pointer to GFpModulus over different
      * threads!
      * @param mod a shared pointer to a GFpModulus that will
      * be held in the members *this
      */
      void set_shrd_mod(std::tr1::shared_ptr<GFpModulus> p_mod);

      static GFpElement decompress(bool yMod2, GFpElement const& x, const CurveGFp& curve);

   private:
      static const u32bit GFPEL_WKSP_SIZE = 9;
      void ensure_worksp() const;

      inline std::tr1::shared_ptr<PointGFp> mult_loop(int l, const BigInt& m,
                                                      std::tr1::shared_ptr<PointGFp> H,
                                                      std::tr1::shared_ptr<PointGFp> tmp,
                                                      const PointGFp& P);

      CurveGFp mC;
      mutable GFpElement mX;  // NOTE: these values must be mutable (affine<->proj)
      mutable GFpElement mY;
      mutable GFpElement mZ;
      mutable GFpElement mZpow2;  // mZ^2
      mutable GFpElement mZpow3;   // mZ^3
      mutable GFpElement mAZpow4;  // mA*mZ^4
      mutable bool mZpow2_set;
      mutable bool mZpow3_set;
      mutable bool mAZpow4_set;
      mutable std::tr1::shared_ptr<std::vector<GFpElement> > mp_worksp_gfp_el;

   };

// relational operators
bool operator==(const PointGFp& lhs, const PointGFp& rhs);
inline bool operator!=(const PointGFp& lhs, const PointGFp& rhs )
   {
   return !operator==(lhs, rhs);
   }

// arithmetic operators
PointGFp operator+(const PointGFp& lhs, const PointGFp& rhs);
PointGFp operator-(const PointGFp& lhs, const PointGFp& rhs);
PointGFp operator-(const PointGFp& lhs);

PointGFp operator*(const BigInt& scalar, const PointGFp& point);
PointGFp operator*(const PointGFp& point, const BigInt& scalar);
PointGFp mult_point_secure(const PointGFp& point,
                           const BigInt& scalar,
                           const BigInt& point_order,
                           const BigInt& max_secret);

PointGFp const mult2(const PointGFp& point);

PointGFp const create_random_point(RandomNumberGenerator& rng,
                                   const CurveGFp& curve);

// encoding and decoding
SecureVector<byte> EC2OSP(const PointGFp& point, byte format);
PointGFp OS2ECP(MemoryRegion<byte> const& os, const CurveGFp& curve);

SecureVector<byte> encode_uncompressed(const PointGFp& point); // maybe make private
SecureVector<byte> encode_hybrid(const PointGFp& point); // maybe make private
SecureVector<byte> encode_compressed(const PointGFp& point); // maybe make private

// swaps the states of point1 and point2, does not throw!
// cf. Meyers, Item 25
inline
void swap(PointGFp& point1, PointGFp& point2 )
   {
   point1.swap(point2);
   }

} // namespace Botan

namespace std {

// swaps the states of point1 and point2, does not throw!
// cf. Meyers, Item 25
template<> inline void
swap<Botan::PointGFp>(Botan::PointGFp& x, Botan::PointGFp& y) { x.swap(y); }

} // namespace std

#endif
