/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BLS12_381_GROUP_H_
#define BOTAN_BLS12_381_GROUP_H_

#include <botan/bls12_381.h>
#include <botan/mem_ops.h>
#include <botan/internal/bls12_381_fields.h>
#include <botan/internal/ct_utils.h>
#include <algorithm>
#include <optional>
#include <span>
#include <vector>

namespace Botan::BLS12_381 {

/**
* The group law, point codec, and affine conversion logic, shared by G1
* and G2. The Group traits provide the point and field element types,
* the coordinate load/store, and the curve constants.
*/
template <typename Group>
class GroupOps final {
   public:
      using Affine = typename Group::Affine;
      using Projective = typename Group::Projective;
      using FE = typename Group::FE;

      static_assert(Affine::BYTES == FE::BYTES);

      static Projective from_affine(const Affine& affine) {
         // z == 0 if the identity element or 1 otherwise
         auto z = FE::one();
         z.conditional_assign(CT::Choice::from_int(affine.m_infinity), FE::zero());
         return Projective(Group::load(affine.m_x), Group::load(affine.m_y), z);
      }

      static Affine to_affine(const Projective& pt) {
         const auto z = Group::load(pt.m_z);
         const auto zinv = z.invert();
         const auto inf = z.is_zero();

         // Canonicalize the identity to (0, 1); otherwise a round trip
         // through from_affine would produce the invalid triple (0, 0, 0),
         // which acts as an absorbing element of the addition formulas
         auto y = Group::load(pt.m_y) * zinv;
         y.conditional_assign(inf, FE::one());

         return Affine(Group::load(pt.m_x) * zinv, y, inf.template into_bitmask<uint32_t>() & 1);
      }

      static std::vector<Affine> to_affine_batch(std::span<const Projective> points) {
         const size_t n = points.size();

         std::vector<Affine> affine;
         affine.reserve(n);

         if(n == 0) {
            return affine;
         }

         /*
         Batch inversion of the z coordinates using Montgomery's trick, with a
         single field inversion plus 3*(n-1) multiplications.

         See Algorithm 2.26 in "Guide to Elliptic Curve Cryptography"
         (Hankerson, Menezes, Vanstone)

         An identity element (z == 0) would zero the running product, so
         identity z's are replaced by one, and the affine identity is instead
         assigned at the end; this handles identities in constant time, rather
         than leaking their presence by falling back to serial conversion.
         */

         auto masked_z = [](const Projective& pt) {
            auto z = Group::load(pt.m_z);
            z.conditional_assign(z.is_zero(), FE::one());
            return z;
         };

         auto affine_from = [](const Projective& pt, const FE& z_inv) {
            const auto inf = Group::load(pt.m_z).is_zero();

            auto x = Group::load(pt.m_x) * z_inv;
            auto y = Group::load(pt.m_y) * z_inv;

            // Canonicalize the identity to (0, 1), as in to_affine
            x.conditional_assign(inf, FE::zero());
            y.conditional_assign(inf, FE::one());

            return Affine(x, y, inf.template into_bitmask<uint32_t>() & 1);
         };

         std::vector<FE> prefix;
         prefix.reserve(n);

         prefix.push_back(masked_z(points[0]));
         for(size_t i = 1; i != n; ++i) {
            prefix.push_back(prefix[i - 1] * masked_z(points[i]));
         }

         auto inv = prefix[n - 1].invert();

         for(size_t i = n; i > 1; --i) {
            const auto& pt = points[i - 1];
            affine.push_back(affine_from(pt, inv * prefix[i - 2]));
            inv = inv * masked_z(pt);
         }
         affine.push_back(affine_from(points[0], inv));

         std::reverse(affine.begin(), affine.end());

         return affine;
      }

      static Projective negate(const Projective& pt) {
         return Projective(Group::load(pt.m_x), Group::load(pt.m_y).negate(), Group::load(pt.m_z));
      }

      static void conditional_negate(Projective& pt, uint32_t negate) {
         auto y = Group::load(pt.m_y);
         y.conditional_assign(CT::Choice::from_int(negate), y.negate());
         pt.m_y = Group::store(y);
      }

      static Projective dbl(const Projective& pt) {
         // Algorithm 9, https://eprint.iacr.org/2015/1060.pdf

         const auto x = Group::load(pt.m_x);
         const auto y = Group::load(pt.m_y);
         const auto z = Group::load(pt.m_z);

         auto t0 = y.square();
         auto z3 = t0 + t0;
         z3 = z3 + z3;
         z3 = z3 + z3;
         auto t1 = y * z;
         auto t2 = z.square();
         t2 = Group::mul_by_3b(t2);
         auto x3 = t2 * z3;
         auto y3 = t0 + t2;
         z3 = t1 * z3;
         t1 = t2 + t2;
         t2 = t1 + t2;
         t0 = t0 - t2;
         y3 = t0 * y3;
         y3 = x3 + y3;
         t1 = x * y;
         x3 = t0 * t1;
         x3 = x3 + x3;

         return Projective(x3, y3, z3);
      }

      static Projective add(const Projective& a, const Projective& b) {
         // Algorithm 7, https://eprint.iacr.org/2015/1060.pdf

         const auto x1 = Group::load(a.m_x);
         const auto y1 = Group::load(a.m_y);
         const auto z1 = Group::load(a.m_z);
         const auto x2 = Group::load(b.m_x);
         const auto y2 = Group::load(b.m_y);
         const auto z2 = Group::load(b.m_z);

         auto t0 = x1 * x2;
         auto t1 = y1 * y2;
         auto t2 = z1 * z2;
         auto t3 = x1 + y1;
         auto t4 = x2 + y2;
         t3 = t3 * t4;
         t4 = t0 + t1;
         t3 = t3 - t4;
         t4 = y1 + z1;
         auto x3 = y2 + z2;
         t4 = t4 * x3;
         x3 = t1 + t2;
         t4 = t4 - x3;
         x3 = x1 + z1;
         auto y3 = x2 + z2;
         x3 = x3 * y3;
         y3 = t0 + t2;
         y3 = x3 - y3;
         x3 = t0 + t0;
         t0 = x3 + t0;
         t2 = Group::mul_by_3b(t2);
         auto z3 = t1 + t2;
         t1 = t1 - t2;
         y3 = Group::mul_by_3b(y3);
         x3 = t4 * y3;
         t2 = t3 * t1;
         x3 = t2 - x3;
         y3 = y3 * t0;
         t1 = t1 * z3;
         y3 = t1 + y3;
         t0 = t0 * t3;
         z3 = z3 * t4;
         z3 = z3 + t0;

         return Projective(x3, y3, z3);
      }

      static Projective add_mixed(const Projective& a, const Affine& other, bool negate_other) {
         // Algorithm 8, https://eprint.iacr.org/2015/1060.pdf
         //
         // The formula assumes other is not the identity; that case is
         // handled by conditional assignment at the end

         const auto x1 = Group::load(a.m_x);
         const auto y1 = Group::load(a.m_y);
         const auto z1 = Group::load(a.m_z);
         const auto x2 = Group::load(other.m_x);
         auto y2 = Group::load(other.m_y);
         if(negate_other) {
            y2 = y2.negate();
         }

         auto t0 = x1 * x2;
         auto t1 = y1 * y2;
         auto t3 = x2 + y2;
         auto t4 = x1 + y1;
         t3 = t3 * t4;
         t4 = t0 + t1;
         t3 = t3 - t4;
         t4 = y2 * z1;
         t4 = t4 + y1;
         auto y3 = x2 * z1;
         y3 = y3 + x1;
         auto x3 = t0 + t0;
         t0 = x3 + t0;
         auto t2 = Group::mul_by_3b(z1);
         auto z3 = t1 + t2;
         t1 = t1 - t2;
         y3 = Group::mul_by_3b(y3);
         x3 = t4 * y3;
         t2 = t3 * t1;
         x3 = t2 - x3;
         y3 = y3 * t0;
         t1 = t1 * z3;
         y3 = t1 + y3;
         t0 = t0 * t3;
         z3 = z3 * t4;
         z3 = z3 + t0;

         auto result = Projective(x3, y3, z3);

         const auto other_is_identity = CT::Choice::from_int(other.m_infinity);
         CT::conditional_assign_mem(other_is_identity, result.m_x.data(), a.m_x.data(), result.m_x.size());
         CT::conditional_assign_mem(other_is_identity, result.m_y.data(), a.m_y.data(), result.m_y.size());
         CT::conditional_assign_mem(other_is_identity, result.m_z.data(), a.m_z.data(), result.m_z.size());

         return result;
      }

      /**
      * Deserialization without the subgroup check, which is group
      * specific and remains the caller's responsibility for any point
      * other than the identity
      */
      static std::optional<Affine> deserialize_unchecked(std::span<const uint8_t> bytes) {
         if(bytes.size() != Affine::BYTES) {
            return {};
         }

         const uint8_t flags = bytes[0];

         // Only the compressed encoding is supported
         if((flags & 0x80) != 0x80) {
            return {};
         }

         const bool is_infinity = (flags & 0x40) == 0x40;
         const bool y_is_largest = (flags & 0x20) == 0x20;

         std::array<uint8_t, Affine::BYTES> x_bytes{};
         copy_mem(x_bytes.data(), bytes.data(), bytes.size());
         x_bytes[0] &= 0x1F;

         if(is_infinity) {
            // The identity is encoded as the infinity flag with all other bits zero
            if(y_is_largest || !CT::all_zeros(x_bytes.data(), x_bytes.size()).as_bool()) {
               return {};
            }
            return Affine::identity();
         }

         const auto x = FE::deserialize(x_bytes);
         if(!x) {
            return {};
         }

         const auto y2 = x->square() * (*x) + Group::curve_b();
         auto y = y2.sqrt().as_optional_vartime();
         if(!y) {
            return {};
         }

         // Choose either y or -y depending on the sign flag
         const auto flip =
            (y->_is_lexicographically_largest() != CT::Choice::from_int(static_cast<word>(flags & 0x20)));
         y->conditional_assign(flip, y->negate());

         return Affine(*x, *y, 0);
      }

      static std::array<uint8_t, Affine::BYTES> serialize(const Affine& pt) {
         auto bytes = Group::load(pt.m_x).serialize();

         // Set the compressed point indicator bit
         bytes[0] |= 0x80;

         const auto identity = CT::Choice::from_int(pt.m_infinity);

         // If the identity element, set the identity bit
         bytes[0] |= (identity.template into_bitmask<uint8_t>() & 0x40);

         // If y is the larger choice *and* not the point at identity, set the large-y bit
         const auto large_y = Group::load(pt.m_y)._is_lexicographically_largest();
         bytes[0] |= ((!identity && large_y).template into_bitmask<uint8_t>() & 0x20);

         return bytes;
      }
};

}  // namespace Botan::BLS12_381

#endif
