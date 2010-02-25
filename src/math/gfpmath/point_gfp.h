/*
* Arithmetic for point groups of elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_POINT_GFP_H__
#define BOTAN_POINT_GFP_H__

#include <botan/curve_gfp.h>
#include <vector>

namespace Botan {

struct BOTAN_DLL Illegal_Point : public Exception
   {
   Illegal_Point(const std::string& err = "") : Exception(err) {}
   };

/**
* This class represents one point on a curve of GF(p)
*/
class BOTAN_DLL PointGFp
   {
   public:
      enum Compression_Type {
         UNCOMPRESSED = 0,
         COMPRESSED   = 1,
         HYBRID       = 2
      };

      /**
      * Construct the point O
      * @param curve The base curve
      */
      PointGFp(const CurveGFp& curve);

      /**
      * Construct a point given its affine coordinates
      * @param curve the base curve
      * @param x affine x coordinate
      * @param y affine y coordinate
      */
      PointGFp(const CurveGFp& curve, const BigInt& x, const BigInt& y);

      /**
      * Construct a point given its jacobian projective coordinates
      * @param curve the base curve
      * @param x jacobian projective x coordinate
      * @param y jacobian projective y coordinate
      * @param z jacobian projective y coordinate
      */
      PointGFp(const CurveGFp& curve,
               const GFpElement& x,
               const GFpElement& y,
               const GFpElement& z);

      //PointGFp(const PointGFp& other) = default;
      //PointGFp& operator=(const PointGFp& other) = default;

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
      * Negate this point
      * @return *this
      */
      PointGFp& negate();

      /**
      * Multiply the point by two
      * @return *this
      */
      PointGFp& mult2_in_place();

      /**
      * Set z coordinate to one.
      * @return *this
      */
      const PointGFp& set_z_to_one();

      /**
      * Return a point
      * where the coordinates are transformed
      * so that z equals one,
      * thus x and y have just the affine values.
      * @result *this
      */
      PointGFp get_z_to_one();

      /**
      * Return base curve of this point
      * @result the curve over GF(p) of this point
      */
      const CurveGFp& get_curve() const { return mC; }

      /**
      * get affine x coordinate
      * @result affine x coordinate
      */
      BigInt get_affine_x() const;

      /**
      * get affine y coordinate
      * @result affine y coordinate
      */
      BigInt get_affine_y() const;

      /**
      * get the jacobian projective x coordinate
      * @result jacobian projective x coordinate
      */
      const GFpElement& get_jac_proj_x() const { return mX; }

      /**
      * get the jacobian projective y coordinate
      * @result jacobian projective y coordinate
      */
      const GFpElement& get_jac_proj_y() const { return mY; }

      /**
      * get the jacobian projective z coordinate
      * @result jacobian projective z coordinate
      */
      const GFpElement& get_jac_proj_z() const { return mZ; }

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
      * swaps the states of *this and other, does not throw!
      * @param other the object to swap values with
      */
      void swap(PointGFp& other);

      /**
      * Equality operator
      */
      bool operator==(const PointGFp& other) const;
   private:
      CurveGFp mC;
      GFpElement mX;
      GFpElement mY;
      GFpElement mZ;
   };

// relational operators
inline bool operator!=(const PointGFp& lhs, const PointGFp& rhs)
   {
   return !(rhs == lhs);
   }

// arithmetic operators
PointGFp BOTAN_DLL operator+(const PointGFp& lhs, const PointGFp& rhs);
PointGFp BOTAN_DLL operator-(const PointGFp& lhs, const PointGFp& rhs);
PointGFp BOTAN_DLL operator-(const PointGFp& lhs);

PointGFp BOTAN_DLL operator*(const BigInt& scalar, const PointGFp& point);
PointGFp BOTAN_DLL operator*(const PointGFp& point, const BigInt& scalar);

PointGFp BOTAN_DLL create_random_point(RandomNumberGenerator& rng,
                                       const CurveGFp& curve);

// encoding and decoding
SecureVector<byte> BOTAN_DLL EC2OSP(const PointGFp& point, byte format);
PointGFp BOTAN_DLL OS2ECP(MemoryRegion<byte> const& os, const CurveGFp& curve);

/* Should these be private? */
SecureVector<byte> BOTAN_DLL encode_uncompressed(const PointGFp& point);
SecureVector<byte> BOTAN_DLL encode_hybrid(const PointGFp& point);
SecureVector<byte> BOTAN_DLL encode_compressed(const PointGFp& point);

// swaps the states of point1 and point2, does not throw!
// cf. Meyers, Item 25
inline
void swap(PointGFp& point1, PointGFp& point2)
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
