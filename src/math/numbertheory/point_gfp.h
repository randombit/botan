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

      class Workspace
         {
         public:
            Workspace(u32bit p_words) :
               ws_monty(2*p_words+1), ws_bn(12) {}

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
                        MemoryRegion<word>& workspace);

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

inline PointGFp operator*(const BigInt& scalar, const PointGFp& point)
   {
   PointGFp result(point);
   return result *= scalar;
   }

inline PointGFp operator*(const PointGFp& point, const BigInt& scalar)
   {
   PointGFp result(point);
   return result *= scalar;
   }

// encoding and decoding
SecureVector<byte> BOTAN_DLL EC2OSP(const PointGFp& point, byte format);

PointGFp BOTAN_DLL OS2ECP(const byte data[], u32bit data_len,
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
