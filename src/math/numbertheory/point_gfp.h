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

/**
* Exception thrown if you try to convert a zero point to an affine
* coordinate
*/
struct BOTAN_DLL Illegal_Transformation : public Exception
   {
   Illegal_Transformation(const std::string& err =
                          "Requested transformation is not possible") :
      Exception(err) {}
   };

/**
* Exception thrown if some form of illegal point is decoded
*/
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
      * Construct the zero point
      * @param curve The base curve
      */
      PointGFp(const CurveGFp& curve);

      /**
      * Construct a point from its affine coordinates
      * @param curve the base curve
      * @param x affine x coordinate
      * @param y affine y coordinate
      */
      PointGFp(const CurveGFp& curve, const BigInt& x, const BigInt& y);

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
      * @param scalar the PointGFp to multiply with *this
      * @result resulting PointGFp
      */
      PointGFp& operator*=(const BigInt& scalar);

      /**
      * Multiplication Operator
      * @param scalar the scalar value
      * @param point the point value
      * @return scalar*point on the curve
      */
      friend BOTAN_DLL PointGFp operator*(const BigInt& scalar, const PointGFp& point);

      /**
      * Negate this point
      * @return *this
      */
      PointGFp& negate()
         {
         if(!is_zero())
            coord_y = curve.get_p() - coord_y;
         return *this;
         }

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
      * Is this the point at infinity?
      * @result true, if this point is at infinity, false otherwise.
      */
      bool is_zero() const
         { return (coord_x.is_zero() && coord_z.is_zero()); }

      /**
      * Checks whether the point is to be found on the underlying
      * curve; used to prevent fault attacks.
      * @return if the point is on the curve
      */
      bool on_the_curve() const;

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

      class Workspace
         {
         public:
            Workspace(size_t p_words) :
               ws_monty(2*(p_words+2)), ws_bn(12) {}

            SecureVector<word> ws_monty;
            std::vector<BigInt> ws_bn;
         };

      /**
      * Montgomery multiplication/reduction
      * @param x first multiplicand
      * @param y second multiplicand
      * @param workspace temp space
      */
      BigInt monty_mult(const BigInt& x, const BigInt& y,
                        MemoryRegion<word>& workspace) const
         {
         BigInt result;
         monty_mult(result, x, y, workspace);
         return result;
         }

      /**
      * Montgomery multiplication/reduction
      * @warning z cannot alias x or y
      * @param z output
      * @param x first multiplicand
      * @param y second multiplicand
      * @param workspace temp space
      */
      void monty_mult(BigInt& z,
                      const BigInt& x, const BigInt& y,
                      MemoryRegion<word>& workspace) const;

      /**
      * Montgomery squaring/reduction
      * @param x multiplicand
      * @param workspace temp space
      */
      BigInt monty_sqr(const BigInt& x,
                       MemoryRegion<word>& workspace) const
         {
         BigInt result;
         monty_sqr(result, x, workspace);
         return result;
         }

      /**
      * Montgomery squaring/reduction
      * @warning z cannot alias x
      * @param z output
      * @param x multiplicand
      * @param workspace temp space
      */
      void monty_sqr(BigInt& z, const BigInt& x,
                     MemoryRegion<word>& workspace) const;

      /**
      * Point addition
      */
      void add(const PointGFp& other, Workspace& workspace);

      /**
      * Point doubling
      * @param workspace temp space
      */
      void mult2(Workspace& workspace);

      CurveGFp curve;
      BigInt coord_x, coord_y, coord_z;
   };

// relational operators
inline bool operator!=(const PointGFp& lhs, const PointGFp& rhs)
   {
   return !(rhs == lhs);
   }

// arithmetic operators
inline PointGFp operator-(const PointGFp& lhs)
   {
   return PointGFp(lhs).negate();
   }

inline PointGFp operator+(const PointGFp& lhs, const PointGFp& rhs)
   {
   PointGFp tmp(lhs);
   return tmp += rhs;
   }

inline PointGFp operator-(const PointGFp& lhs, const PointGFp& rhs)
   {
   PointGFp tmp(lhs);
   return tmp -= rhs;
   }

inline PointGFp operator*(const PointGFp& point, const BigInt& scalar)
   {
   return scalar * point;
   }

// encoding and decoding
SecureVector<byte> BOTAN_DLL EC2OSP(const PointGFp& point, byte format);

PointGFp BOTAN_DLL OS2ECP(const byte data[], size_t data_len,
                          const CurveGFp& curve);

inline PointGFp OS2ECP(const MemoryRegion<byte>& data, const CurveGFp& curve)
   { return OS2ECP(&data[0], data.size(), curve); }

}

namespace std {

template<>
inline void swap<Botan::PointGFp>(Botan::PointGFp& x, Botan::PointGFp& y)
   { x.swap(y); }

}

#endif
