/*
* Point arithmetic on elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2008-2011,2014,2015,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EC_POINT_H_
#define BOTAN_EC_POINT_H_

// TODO(Botan4) delete this header

#include <botan/curve_gfp.h>
#include <botan/ec_point_format.h>
#include <botan/exceptn.h>
#include <vector>

namespace Botan {

/**
* Deprecated elliptic curve type
*
* Use EC_AffinePoint in new code; this type is no longer used internally at all
* except to support very unfortunate (and deprecated) curve types, specifically
* those with a cofactor, or with unreasonable sizes (above 521 bits), which
* cannot be accommodated by the new faster EC library in math/pcurves. For
* normal curves EC_AffinePoint will typically be 2 or 3 times faster.
*
* This type will be completely removed in Botan4
*/
class BOTAN_PUBLIC_API(2, 0) EC_Point final {
   public:
      friend class EC_Point_Var_Point_Precompute;
      friend class EC_Point_Multi_Point_Precompute;
      friend class EC_Point_Base_Point_Precompute;

      typedef EC_Point_Format Compression_Type;
      using enum EC_Point_Format;

      enum : uint8_t /* NOLINT(*-use-enum-class) */ { WORKSPACE_SIZE = 8 };

      /**
      * Construct an uninitialized EC_Point
      */
      EC_Point() = default;

      /**
      * Construct the zero point
      * @param curve The base curve
      */
      BOTAN_DEPRECATED("Deprecated no replacement") explicit EC_Point(const CurveGFp& curve);

      /**
      * Copy constructor
      */
      EC_Point(const EC_Point&) = default;

      /**
      * Move Constructor
      */
      EC_Point(EC_Point&& other) noexcept { this->swap(other); }

      /**
      * Standard Assignment
      */
      EC_Point& operator=(const EC_Point&) = default;

      /**
      * Move Assignment
      */
      EC_Point& operator=(EC_Point&& other) noexcept {
         if(this != &other) {
            this->swap(other);
         }
         return (*this);
      }

      ~EC_Point() = default;

      /**
      * Point multiplication operator
      *
      * Simple unblinded Montgomery ladder
      *
      * Warning: prefer the functions on EC_Group such as
      * blinded_var_point_multiply
      *
      * @param scalar the scalar value
      * @return *this multiplied by the scalar value
      */
      EC_Point mul(const BigInt& scalar) const;

      /**
      * Construct a point from its affine coordinates
      * @param curve the base curve
      * @param x affine x coordinate
      * @param y affine y coordinate
      */
      BOTAN_DEPRECATED("Use EC_AffinePoint::from_bigint_xy") EC_Point(const CurveGFp& curve, BigInt x, BigInt y);

      /**
      * EC2OSP - elliptic curve to octet string primitive
      * @param format which format to encode using
      */
      std::vector<uint8_t> encode(EC_Point_Format format) const;

      /**
      * += Operator
      * @param rhs the EC_Point to add to the local value
      * @result resulting EC_Point
      */
      EC_Point& operator+=(const EC_Point& rhs);

      /**
      * -= Operator
      * @param rhs the EC_Point to subtract from the local value
      * @result resulting EC_Point
      */
      EC_Point& operator-=(const EC_Point& rhs);

      /**
      * *= Operator
      * @param scalar the EC_Point to multiply with *this
      * @result resulting EC_Point
      */
      EC_Point& operator*=(const BigInt& scalar);

      /**
      * Negate this point
      * @return *this
      */
      EC_Point& negate() {
         if(!is_zero()) {
            m_y = m_curve.get_p() - m_y;
         }
         return *this;
      }

      /**
      * Force this point to affine coordinates
      *
      * Convert the point to its equivalent affine coordinates. Throws if this
      * is the point at infinity.
      */
      void force_affine();

      /**
      * Force all points on the list to affine coordinates
      *
      * Force several points to be affine at once. Uses Montgomery's trick to
      * reduce number of inversions required, so this is much faster than
      * calling ``force_affine`` on each point in sequence.
      */
      static void force_all_affine(std::span<EC_Point> points, secure_vector<word>& ws);

      bool is_affine() const;

      /**
      * Is this the point at infinity?
      * @result true, if this point is at infinity, false otherwise.
      */
      bool is_zero() const { return m_z.is_zero(); }

      /**
      * Checks whether the point is to be found on the underlying
      * curve; used to prevent fault attacks.
      * @return if the point is on the curve
      */
      bool on_the_curve() const;

      /**
      * Return the fixed length big endian encoding of x coordinate
      */
      secure_vector<uint8_t> x_bytes() const;

      /**
      * Return the fixed length big endian encoding of y coordinate
      */
      secure_vector<uint8_t> y_bytes() const;

      /**
      * Return the fixed length concatenation of the x and y coordinates
      */
      secure_vector<uint8_t> xy_bytes() const;

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
      * Return the zero (aka infinite) point associated with this curve
      */
      EC_Point zero() const;

      /**
      * Randomize the point representation
      * The actual value (get_affine_x, get_affine_y) does not change
      */
      void randomize_repr(RandomNumberGenerator& rng);

      /**
      * Equality operator
      */
      bool operator==(const EC_Point& other) const;

      bool operator!=(const EC_Point& other) const = default;

      /**
      * swaps the states of *this and other
      * @param other the object to swap values with
      */
      void swap(EC_Point& other) noexcept;

      /**
      * For internal use only
      */
      bool _is_x_eq_to_v_mod_order(const BigInt& v) const;

#if defined(BOTAN_DISABLE_DEPRECATED_FEATURES)

   private:
#endif

      /**
      * Return the internal x coordinate
      *
      * Note this may be in Montgomery form
      */
      BOTAN_DEPRECATED("Use affine coordinates only") const BigInt& get_x() const { return m_x; }

      /**
      * Return the internal y coordinate
      *
      * Note this may be in Montgomery form
      */
      BOTAN_DEPRECATED("Use affine coordinates only") const BigInt& get_y() const { return m_y; }

      /**
      * Return the internal z coordinate
      *
      * Note this may be in Montgomery form
      */
      BOTAN_DEPRECATED("Use affine coordinates only") const BigInt& get_z() const { return m_z; }

      BOTAN_DEPRECATED("Deprecated no replacement")

      void swap_coords(BigInt& new_x, BigInt& new_y, BigInt& new_z) {
         m_x.swap(new_x);
         m_y.swap(new_y);
         m_z.swap(new_z);
      }

      friend void swap(EC_Point& x, EC_Point& y) noexcept { x.swap(y); }

      /**
      * Randomize the point representation
      * The actual value (get_affine_x, get_affine_y) does not change
      */
      void randomize_repr(RandomNumberGenerator& rng, secure_vector<word>& ws);

      /**
      * Point addition
      * @param other the point to add to *this
      * @param workspace temp space, at least WORKSPACE_SIZE elements
      */
      void add(const EC_Point& other, std::vector<BigInt>& workspace);

      /**
      * Point addition. Array version.
      *
      * @param x_words the words of the x coordinate of the other point
      * @param x_size size of x_words
      * @param y_words the words of the y coordinate of the other point
      * @param y_size size of y_words
      * @param z_words the words of the z coordinate of the other point
      * @param z_size size of z_words
      * @param workspace temp space, at least WORKSPACE_SIZE elements
      */
      void add(const word x_words[],
               size_t x_size,
               const word y_words[],
               size_t y_size,
               const word z_words[],
               size_t z_size,
               std::vector<BigInt>& workspace);

      /**
      * Point addition - mixed J+A
      *
      * @warning This function assumes that @p other is affine, if this is not
      *          correct the result will be invalid.
      *
      * @param other affine point to add - assumed to be affine!
      * @param workspace temp space, at least WORKSPACE_SIZE elements
      */
      void add_affine(const EC_Point& other, std::vector<BigInt>& workspace);

      /**
      * Point addition - mixed J+A. Array version.
      *
      * @param x_words the words of the x coordinate of the other point
      * @param x_size size of x_words
      * @param y_words the words of the y coordinate of the other point
      * @param y_size size of y_words
      * @param workspace temp space, at least WORKSPACE_SIZE elements
      */
      void add_affine(
         const word x_words[], size_t x_size, const word y_words[], size_t y_size, std::vector<BigInt>& workspace);

      /**
      * Point doubling
      * @param workspace temp space, at least WORKSPACE_SIZE elements
      */
      void mult2(std::vector<BigInt>& workspace);

      /**
      * Repeated point doubling
      * @param i number of doublings to perform
      * @param workspace temp space, at least WORKSPACE_SIZE elements
      */
      void mult2i(size_t i, std::vector<BigInt>& workspace);

      /**
      * Point addition
      * @param other the point to add to *this
      * @param workspace temp space, at least WORKSPACE_SIZE elements
      * @return other plus *this
      */
      EC_Point plus(const EC_Point& other, std::vector<BigInt>& workspace) const {
         EC_Point x = (*this);
         x.add(other, workspace);
         return x;
      }

      /**
      * Point doubling
      * @param workspace temp space, at least WORKSPACE_SIZE elements
      * @return *this doubled
      */
      EC_Point double_of(std::vector<BigInt>& workspace) const {
         EC_Point x = (*this);
         x.mult2(workspace);
         return x;
      }

      /**
      * Return base curve of this point
      * @result the curve over GF(p) of this point
      *
      * You should not need to use this
      */
      BOTAN_DEPRECATED("Deprecated no replacement") const CurveGFp& get_curve() const { return m_curve; }

   private:
      CurveGFp m_curve;
      BigInt m_x, m_y, m_z;
};

/**
* ECC point multiexponentiation - not constant time!
* @param p1 a point
* @param z1 a scalar
* @param p2 a point
* @param z2 a scalar
* @result (p1 * z1 + p2 * z2)
*/
BOTAN_DEPRECATED("Use EC_AffinePoint::mul_px_qy")
EC_Point BOTAN_PUBLIC_API(2, 0)
   multi_exponentiate(const EC_Point& p1, const BigInt& z1, const EC_Point& p2, const BigInt& z2);

// arithmetic operators
inline EC_Point operator-(const EC_Point& lhs) {
   return EC_Point(lhs).negate();
}

inline EC_Point operator+(const EC_Point& lhs, const EC_Point& rhs) {
   EC_Point tmp(lhs);
   return tmp += rhs;
}

inline EC_Point operator-(const EC_Point& lhs, const EC_Point& rhs) {
   EC_Point tmp(lhs);
   return tmp -= rhs;
}

inline EC_Point operator*(const EC_Point& point, const BigInt& scalar) {
   return point.mul(scalar);
}

inline EC_Point operator*(const BigInt& scalar, const EC_Point& point) {
   return point.mul(scalar);
}

/**
* Perform point decoding
* Use EC_Group::OS2ECP instead
*/
BOTAN_DEPRECATED("Use EC_AffinePoint::deserialize")
EC_Point BOTAN_PUBLIC_API(2, 0) OS2ECP(const uint8_t data[], size_t data_len, const CurveGFp& curve);

/**
* Perform point decoding
*
* This is an internal function which was accidentally made public.
* Do not use it; it will be removed in Botan4.
*
* @param data the encoded point
* @param data_len length of data in bytes
* @param curve_p the curve equation prime
* @param curve_a the curve equation a parameter
* @param curve_b the curve equation b parameter
*/
BOTAN_DEPRECATED("Use EC_AffinePoint::deserialize")
std::pair<BigInt, BigInt> BOTAN_UNSTABLE_API
   OS2ECP(const uint8_t data[], size_t data_len, const BigInt& curve_p, const BigInt& curve_a, const BigInt& curve_b);

BOTAN_DEPRECATED("Use EC_AffinePoint::deserialize")
EC_Point BOTAN_UNSTABLE_API OS2ECP(std::span<const uint8_t> data, const CurveGFp& curve);

// The name used for this type in older versions
typedef EC_Point PointGFp;

}  // namespace Botan

#endif
