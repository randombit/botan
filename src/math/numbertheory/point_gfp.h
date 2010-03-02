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

struct BOTAN_DLL Illegal_Transformation : public Exception
   {
   Illegal_Transformation(const std::string& err =
                          "Requested transformation is not possible") :
      Exception(err) {}
   };

struct BOTAN_DLL Illegal_Point : public Exception
   {
   Illegal_Point(const std::string& err = "Malformed ECP point detected") :
      Exception(err) {}
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
      * Construct an uninitialized PointGFp
      */
      PointGFp() {}

      /**
      * Construct the point O
      * @param curve The base curve
      */
      PointGFp(const CurveGFp& curve) :
         curve(curve), coord_x(0), coord_y(1), coord_z(0) {}

      /**
      * Construct a point given its affine coordinates
      * @param curve the base curve
      * @param x affine x coordinate
      * @param y affine y coordinate
      */
      PointGFp(const CurveGFp& curve,
               const BigInt& x, const BigInt& y) :
         curve(curve), coord_x(x), coord_y(y), coord_z(1) {}

      /**
      * Construct a point given its jacobian projective coordinates
      * @param curve the base curve
      * @param x jacobian projective x coordinate
      * @param y jacobian projective y coordinate
      * @param z jacobian projective z coordinate
      */
      PointGFp(const CurveGFp& curve,
               const BigInt& x, const BigInt& y, const BigInt& z) :
         curve(curve), coord_x(x), coord_y(y), coord_z(z) {}

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
      * Return base curve of this point
      * @result the curve over GF(p) of this point
      */
      const CurveGFp& get_curve() const { return curve; }

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
      const BigInt& get_x() const { return coord_x; }

      /**
      * get the jacobian projective y coordinate
      * @result jacobian projective y coordinate
      */
      const BigInt& get_y() const { return coord_y; }

      /**
      * get the jacobian projective z coordinate
      * @result jacobian projective z coordinate
      */
      const BigInt& get_z() const { return coord_z; }

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
      /**
      * Point doubling
      */
      void mult2();

      CurveGFp curve;
      BigInt coord_x, coord_y, coord_z;
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

// encoding and decoding
SecureVector<byte> BOTAN_DLL EC2OSP(const PointGFp& point, byte format);
PointGFp BOTAN_DLL OS2ECP(const MemoryRegion<byte>& os, const CurveGFp& curve);

}

namespace std {

template<>
inline void swap<Botan::PointGFp>(Botan::PointGFp& x, Botan::PointGFp& y)
   { x.swap(y); }

}

#endif
