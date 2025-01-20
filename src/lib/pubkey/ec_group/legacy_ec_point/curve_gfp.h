/*
* Elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*     2010-2011,2012,2014,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_GFP_CURVE_H_
#define BOTAN_GFP_CURVE_H_

// TODO(Botan4) delete this header

#include <botan/bigint.h>

// Currently exposed in EC_Point
//BOTAN_FUTURE_INTERNAL_HEADER(curve_gfp.h)

namespace Botan {

class EC_Group_Data;

/**
* This is an internal type which is only exposed for accidental
* historical reasons. Do not use it in any way.
*
* This class will be removed in Botan4.
*/
class BOTAN_UNSTABLE_API CurveGFp final {
   public:
      /**
      * @return curve coefficient a
      */
      const BigInt& get_a() const;

      /**
      * @return curve coefficient b
      */
      const BigInt& get_b() const;

      /**
      * Get prime modulus of the field of the curve
      * @return prime modulus of the field of the curve
      */
      const BigInt& get_p() const;

      size_t get_p_words() const;

      CurveGFp(const CurveGFp&) = default;

   private:
      friend class EC_Point;
      friend class EC_Group_Data;

      /**
      * Create an uninitialized CurveGFp
      */
      CurveGFp() = default;

      CurveGFp(const EC_Group_Data* group);

      CurveGFp& operator=(const CurveGFp&) = default;

      void swap(CurveGFp& other) { std::swap(m_group, other.m_group); }

      bool operator==(const CurveGFp& other) const { return (m_group == other.m_group); }

   private:
      const EC_Group_Data& group() const {
         BOTAN_ASSERT_NONNULL(m_group);
         return *m_group;
      }

      /**
      * Raw pointer
      *
      * This EC_Group_Data is not owned because instead the EC_Group_Data
      * owns this CurveGFp, so we can always access it safely. If it was
      * a shared_ptr this would cause a reference cycle.
      */
      const EC_Group_Data* m_group = nullptr;
};

}  // namespace Botan

#endif
