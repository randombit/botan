/*
* Ed25519 group operations
* (C) 2017 Ribose Inc
*     2025 Jack Lloyd
*
* Based on the public domain code from SUPERCOP ref10 by
* Peter Schwabe, Daniel J. Bernstein, Niels Duif, Tanja Lange, Bo-Yin Yang
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ed25519_internal.h>

#include <botan/internal/ed25519_fe.h>
#include <array>
#include <memory>
#include <span>

namespace Botan {

namespace {

/**
Here the group is the set of pairs (x,y) of field elements (see ed5519_fe.h)
satisfying -x^2 + y^2 = 1 + d x^2y^2 where d = -121665/121666.

Several different point representations are used in this implementation
*/

constexpr Ed25519_FieldElement ED25519_D = []() consteval {
   // d = -121665/121666
   const auto n = Ed25519_FieldElement::from_word(121665);
   const auto m = Ed25519_FieldElement::from_word(121666);
   return -(n * m.invert());
}();

constexpr Ed25519_FieldElement ED25519_D2 = ED25519_D + ED25519_D;

/*
* sqrt(-1), computed as 2^((p-1)/4); 2 is a nonresidue since p == 5 (mod 8).
* Since (p-1)/4 = 2*((p-5)/8) + 1 this can reuse the (p-5)/8 addition chain.
*/
constexpr Ed25519_FieldElement ED25519_SQRTM1 = []() consteval {
   const auto two = Ed25519_FieldElement::from_word(2);
   return two.pow_22523().sqr() * two;
}();

/**
* Ed25519_Point_Completed
*
* ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
*/
class Ed25519_Point_Completed final {
   public:
      Ed25519_FieldElement X;  // NOLINT(misc-non-private-member-variables-in-classes)
      Ed25519_FieldElement Y;  // NOLINT(misc-non-private-member-variables-in-classes)
      Ed25519_FieldElement Z;  // NOLINT(misc-non-private-member-variables-in-classes)
      Ed25519_FieldElement T;  // NOLINT(misc-non-private-member-variables-in-classes)
};

/**
* Ed25519_Point_Projective
*
* (X:Y:Z) satisfying x=X/Z, y=Y/Z
*/
class Ed25519_Point_Projective final {
   public:
      Ed25519_FieldElement X;  // NOLINT(misc-non-private-member-variables-in-classes)
      Ed25519_FieldElement Y;  // NOLINT(misc-non-private-member-variables-in-classes)
      Ed25519_FieldElement Z;  // NOLINT(misc-non-private-member-variables-in-classes)

      /*
      * Point conversion
      */
      static constexpr Ed25519_Point_Projective from(const Ed25519_Point_Completed& p) {
         Ed25519_Point_Projective r;
         r.X = p.X * p.T;
         r.Y = p.Y * p.Z;
         r.Z = p.Z * p.T;
         return r;
      }

      static constexpr Ed25519_Point_Projective identity() {
         Ed25519_Point_Projective h;
         h.X = Ed25519_FieldElement::zero();
         h.Y = Ed25519_FieldElement::one();
         h.Z = Ed25519_FieldElement::one();
         return h;
      }

      void serialize_to(std::span<uint8_t, 32> s) const {
         auto recip = this->Z.invert();
         auto x = this->X * recip;
         auto y = this->Y * recip;
         y.serialize_to(s);
         s[31] ^= x.is_negative() ? 0x80 : 0x00;
      }

      constexpr Ed25519_Point_Completed dbl() const;
};

constexpr Ed25519_Point_Completed Ed25519_Point_Projective::dbl() const {
   Ed25519_Point_Completed r;
   r.X = X.sqr();        // XX=X1^2
   r.Z = Y.sqr();        // YY=Y1^2
   r.T = Z.sqr2();       // B=2*Z1^2
   r.Y = X + Y;          // A=X1+Y1
   auto t0 = r.Y.sqr();  // AA=A^2
   r.Y = r.Z + r.X;      // Y3=YY+XX
   r.Z = r.Z - r.X;      // Z3=YY-XX
   r.X = t0 - r.Y;       // X3=AA-Y3
   r.T = r.T - r.Z;      // T3=B-Z3
   return r;
}

/**
* Ed25519_Point_Extended
*
* (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
*/
class Ed25519_Point_Extended final {
   public:
      Ed25519_FieldElement X;  // NOLINT(misc-non-private-member-variables-in-classes)
      Ed25519_FieldElement Y;  // NOLINT(misc-non-private-member-variables-in-classes)
      Ed25519_FieldElement Z;  // NOLINT(misc-non-private-member-variables-in-classes)
      Ed25519_FieldElement T;  // NOLINT(misc-non-private-member-variables-in-classes)

      static constexpr Ed25519_Point_Extended identity() {
         Ed25519_Point_Extended h;
         h.X = Ed25519_FieldElement::zero();
         h.Y = Ed25519_FieldElement::one();
         h.Z = Ed25519_FieldElement::one();
         h.T = Ed25519_FieldElement::zero();
         return h;
      }

      constexpr Ed25519_Point_Completed dbl() const {
         Ed25519_Point_Projective q;
         q.X = X;
         q.Y = Y;
         q.Z = Z;
         return q.dbl();
      }

      /**
      * Point conversion
      */
      static constexpr Ed25519_Point_Extended from(const Ed25519_Point_Completed& p) {
         Ed25519_Point_Extended r;
         r.X = p.X * p.T;
         r.Y = p.Y * p.Z;
         r.Z = p.Z * p.T;
         r.T = p.X * p.Y;
         return r;
      }

      void serialize_to(std::span<uint8_t, 32> out) const {
         auto recip = this->Z.invert();
         auto x = this->X * recip;
         auto y = this->Y * recip;
         y.serialize_to(out);
         out[31] ^= x.is_negative() ? 0x80 : 0x00;
      }
};

/**
* Ed25519 Point in "Niels" coordinates
*
* y + x, y - x, 2d * x * y
*
* where d is the Edwards curve constant.
*/
class Ed25519_Point_Niels final {
   public:
      Ed25519_FieldElement yplusx;   // NOLINT(misc-non-private-member-variables-in-classes)
      Ed25519_FieldElement yminusx;  // NOLINT(misc-non-private-member-variables-in-classes)
      Ed25519_FieldElement xy2d;     // NOLINT(misc-non-private-member-variables-in-classes)

      static constexpr Ed25519_Point_Niels identity() {
         Ed25519_Point_Niels h;
         h.yplusx = Ed25519_FieldElement::one();
         h.yminusx = Ed25519_FieldElement::one();
         h.xy2d = Ed25519_FieldElement::zero();
         return h;
      }
};

class Ed25519_Point_Cached final {
   public:
      Ed25519_FieldElement YplusX;   // NOLINT(misc-non-private-member-variables-in-classes)
      Ed25519_FieldElement YminusX;  // NOLINT(misc-non-private-member-variables-in-classes)
      Ed25519_FieldElement Z;        // NOLINT(misc-non-private-member-variables-in-classes)
      Ed25519_FieldElement T2d;      // NOLINT(misc-non-private-member-variables-in-classes)

      /**
      * Point conversion
      */
      static constexpr Ed25519_Point_Cached from(const Ed25519_Point_Extended& p) {
         Ed25519_Point_Cached r;
         r.YplusX = p.Y + p.X;
         r.YminusX = p.Y - p.X;
         r.Z = p.Z;
         r.T2d = p.T * ED25519_D2;
         return r;
      }

      /**
      * Point conversion
      */
      static constexpr Ed25519_Point_Cached from(const Ed25519_Point_Completed& p) {
         return Ed25519_Point_Cached::from(Ed25519_Point_Extended::from(p));
      }
};

/*
* Point addition
*/
inline constexpr Ed25519_Point_Completed operator+(const Ed25519_Point_Extended& p, const Ed25519_Point_Cached& q) {
   Ed25519_Point_Completed r;
   r.X = p.Y + p.X;        // YpX1 = Y1+X1
   r.Y = p.Y - p.X;        // YmX1 = Y1-X1
   r.Z = r.X * q.YplusX;   // A = YpX1*YpX2
   r.Y = r.Y * q.YminusX;  // B = YmX1*YmX2
   r.T = q.T2d * p.T;      // C = T2d2*T1
   r.X = p.Z * q.Z;        // ZZ = Z1*Z2
   auto t0 = r.X + r.X;    // D = 2*ZZ
   r.X = r.Z - r.Y;        // X3 = A-B
   r.Y = r.Z + r.Y;        // Y3 = A+B
   r.Z = t0 + r.T;         // Z3 = D+C
   r.T = t0 - r.T;         // T3 = D-C
   return r;
}

/*
* Point addition
*/
inline constexpr Ed25519_Point_Completed operator+(const Ed25519_Point_Extended& p, const Ed25519_Point_Niels& q) {
   Ed25519_Point_Completed r;
   r.X = p.Y + p.X;        // YpX1 = Y1+X1
   r.Y = p.Y - p.X;        // YmX1 = Y1-X1
   r.Z = r.X * q.yplusx;   // A = YpX1*ypx2
   r.Y = r.Y * q.yminusx;  // B = YmX1*ymx2
   r.T = q.xy2d * p.T;     // C = xy2d2*T1
   auto t0 = p.Z + p.Z;    // D = 2*Z1
   r.X = r.Z - r.Y;        // X3 = A-B
   r.Y = r.Z + r.Y;        // Y3 = A+B
   r.Z = t0 + r.T;         // Z3 = D+C
   r.T = t0 - r.T;         // T3 = D-C
   return r;
}

/*
* Point subtraction
*/
inline constexpr Ed25519_Point_Completed operator-(const Ed25519_Point_Extended& p, const Ed25519_Point_Niels& q) {
   Ed25519_Point_Completed r;
   r.X = p.Y + p.X;        // YpX1 = Y1+X1
   r.Y = p.Y - p.X;        // YmX1 = Y1-X1
   r.Z = r.X * q.yminusx;  // A = YpX1*ymx2
   r.Y = r.Y * q.yplusx;   // B = YmX1*ypx2
   r.T = q.xy2d * p.T;     // C = xy2d2*T1
   auto t0 = p.Z + p.Z;    // D = 2*Z1
   r.X = r.Z - r.Y;        // X3 = A-B
   r.Y = r.Z + r.Y;        // Y3 = A+B
   r.Z = t0 - r.T;         // Z3 = D-C
   r.T = t0 + r.T;         // T3 = D+C
   return r;
}

/*
* Point subtraction
*/
inline constexpr Ed25519_Point_Completed operator-(const Ed25519_Point_Extended& p, const Ed25519_Point_Cached& q) {
   Ed25519_Point_Completed r;
   r.X = p.Y + p.X;        // YpX1 = Y1+X1
   r.Y = p.Y - p.X;        // YmX1 = Y1-X1
   r.Z = r.X * q.YminusX;  // A = YpX1*YmX2
   r.Y = r.Y * q.YplusX;   // B = YmX1*YpX2
   r.T = q.T2d * p.T;      // C = T2d2*T1
   r.X = p.Z * q.Z;        // ZZ = Z1*Z2
   auto t0 = r.X + r.X;    // D = 2*ZZ
   r.X = r.Z - r.Y;        // X3 = A-B
   r.Y = r.Z + r.Y;        // Y3 = A+B
   r.Z = t0 - r.T;         // Z3 = D-C
   r.T = t0 + r.T;         // T3 = D+C
   return r;
}

std::array<int8_t, 256> slide(std::span<const uint8_t, 32> a) {
   std::array<int8_t, 256> r{};
   for(size_t i = 0; i < 256; ++i) {
      r[i] = 1 & (a[i >> 3] >> (i & 7));
   }

   for(size_t i = 0; i < 256; ++i) {
      if(r[i] != 0) {
         for(size_t b = 1; b <= 6 && i + b < 256; ++b) {
            if(r[i + b] != 0) {
               if(r[i] + (r[i + b] << b) <= 15) {
                  r[i] += r[i + b] << b;
                  r[i + b] = 0;
               } else if(r[i] - (r[i + b] << b) >= -15) {
                  r[i] -= r[i + b] << b;
                  for(size_t k = i + b; k < 256; ++k) {
                     if(r[k] == 0) {
                        r[k] = 1;
                        break;
                     }
                     r[k] = 0;
                  }
               } else {
                  break;
               }
            }
         }
      }
   }

   return r;
}

/*
* The base point B = (x, 4/5) with x even (RFC 8032 Section 5.1)
*/
Ed25519_Point_Extended ed25519_derive_basepoint() {
   const auto y = Ed25519_FieldElement::from_word(4) * Ed25519_FieldElement::from_word(5).invert();

   // Recover x = sqrt((y^2-1)/(d*y^2+1)) as in point decoding
   const auto yy = y.sqr();
   const auto u = yy - Ed25519_FieldElement::one();
   const auto v = ED25519_D * yy + Ed25519_FieldElement::one();
   const auto v3 = v.sqr() * v;
   const auto v7 = v3.sqr() * v;
   auto x = (u * v3) * (u * v7).pow_22523();

   if(!(x.sqr() * v - u).is_zero()) {
      x = x * ED25519_SQRTM1;
   }
   if(x.is_negative()) {
      x = -x;
   }

   Ed25519_Point_Extended b;
   b.X = x;
   b.Y = y;
   b.Z = Ed25519_FieldElement::one();
   b.T = x * y;
   return b;
}

const Ed25519_Point_Extended& ed25519_basepoint() {
   static const Ed25519_Point_Extended b = ed25519_derive_basepoint();
   return b;
}

/*
* Compute B_precomp[i][j] = (j+1)*256^i*B in Niels form, sharing a single
* field inversion across the entire table (Montgomery's trick)
*/
std::array<std::array<Ed25519_Point_Niels, 8>, 32> ed25519_base_precomp() {
   constexpr size_t PTS = 32 * 8;

   auto pts_storage = std::make_unique<std::array<Ed25519_Point_Extended, PTS>>();
   auto& pts = *pts_storage;

   auto base = ed25519_basepoint();
   for(size_t i = 0; i != 32; ++i) {
      pts[8 * i] = base;
      const auto base_c = Ed25519_Point_Cached::from(base);
      for(size_t j = 1; j != 8; ++j) {
         pts[8 * i + j] = Ed25519_Point_Extended::from(pts[8 * i + j - 1] + base_c);
      }

      // The next row base is 256*base; the row ends with 8*base already
      base = pts[8 * i + 7];
      for(size_t k = 0; k != 5; ++k) {
         base = Ed25519_Point_Extended::from(base.dbl());
      }
   }

   auto prod_storage = std::make_unique<std::array<Ed25519_FieldElement, PTS>>();
   auto& prod = *prod_storage;

   prod[0] = pts[0].Z;
   for(size_t i = 1; i != PTS; ++i) {
      prod[i] = prod[i - 1] * pts[i].Z;
   }

   auto inv = prod[PTS - 1].invert();

   std::array<std::array<Ed25519_Point_Niels, 8>, 32> table;
   for(size_t i = PTS; i-- > 0;) {
      const auto z_inv = (i == 0) ? inv : inv * prod[i - 1];
      inv = inv * pts[i].Z;

      const auto x = pts[i].X * z_inv;
      const auto y = pts[i].Y * z_inv;
      auto& n = table[i / 8][i % 8];
      n.yplusx = y + x;
      n.yminusx = y - x;
      n.xy2d = ED25519_D2 * (x * y);
   }

   return table;
}

/*
* Compute Bi[i] = (2*i+1)*B in Niels form
*/
std::array<Ed25519_Point_Niels, 8> ed25519_base_odd_multiples() {
   std::array<Ed25519_Point_Extended, 8> m;
   m[0] = ed25519_basepoint();
   const auto base_2 = Ed25519_Point_Cached::from(Ed25519_Point_Extended::from(m[0].dbl()));
   for(size_t i = 1; i != 8; ++i) {
      m[i] = Ed25519_Point_Extended::from(m[i - 1] + base_2);
   }

   std::array<Ed25519_FieldElement, 8> prod;
   prod[0] = m[0].Z;
   for(size_t i = 1; i != 8; ++i) {
      prod[i] = prod[i - 1] * m[i].Z;
   }

   auto inv = prod[7].invert();

   std::array<Ed25519_Point_Niels, 8> r;
   for(size_t i = 8; i-- > 0;) {
      const auto z_inv = (i == 0) ? inv : inv * prod[i - 1];
      inv = inv * m[i].Z;

      const auto x = m[i].X * z_inv;
      const auto y = m[i].Y * z_inv;
      r[i].yplusx = y + x;
      r[i].yminusx = y - x;
      r[i].xy2d = ED25519_D2 * (x * y);
   }
   return r;
}

std::optional<Ed25519_Point_Extended> frombytes_negate_vartime(std::span<const uint8_t, 32> s) {
   // RFC 8032 5.1.3: reject a y coordinate that is not already reduced
   auto y = Ed25519_FieldElement::deserialize(s.data());
   if(!y) {
      return {};
   }

   auto h = Ed25519_Point_Extended::identity();
   h.Y = *y;
   h.Z = Ed25519_FieldElement::one();
   auto u = h.Y.sqr();
   auto v = u * ED25519_D;
   u = u - h.Z; /* u = y^2-1 */
   v = v + h.Z; /* v = dy^2+1 */

   auto v3 = v.sqr() * v;
   h.X = v3.sqr();
   h.X = h.X * v;
   h.X = h.X * u; /* x = uv^7 */

   h.X = h.X.pow_22523();
   h.X = h.X * v3;
   h.X = h.X * u; /* x = uv^3(uv^7)^((q-5)/8) */

   auto vxx = h.X.sqr();
   vxx = vxx * v;
   auto check = vxx - u; /* vx^2-u */
   if(!check.is_zero()) {
      check = vxx + u; /* vx^2+u */
      if(!check.is_zero()) {
         return {};
      }
      h.X = h.X * ED25519_SQRTM1;
   }

   if(h.X.is_negative() == bool(s[31] >> 7)) {
      h.X = -h.X;
   }

   // RFC 8032 Section 5.1.3: "If x = 0, and x_0 = 1, decoding fails."
   // x = 0 is invariant under the negation above, and x_0 is the encoded sign
   // bit s[31] >> 7. This rejects the non-canonical identity encoding
   // {0x01, 0x00 ..., 0x00, 0x80} during decoding, which otherwise decodes to
   // the identity and slips past the canonical-only identity check in
   // ed25519_verify(). (Ed25519_PublicKey::check_key() also relies on this
   // rejection.)
   if(h.X.is_zero() && bool(s[31] >> 7)) {
      return {};
   }

   h.T = h.X * h.Y;
   return h;
}

/*
r = a * A + b * B
where a = a[0]+256*a[1]+...+256^31 a[31].
and b = b[0]+256*b[1]+...+256^31 b[31].
B is the Ed25519 base point (x,4/5) with x positive.
*/

void ge_double_scalarmult_vartime(std::span<uint8_t, 32> out,
                                  const Ed25519_Scalar& a,
                                  const Ed25519_Point_Extended& A,
                                  const Ed25519_Scalar& b) {
   static const std::array<Ed25519_Point_Niels, 8> Bi = ed25519_base_odd_multiples();

   auto aslide = slide(a.to_bytes());
   auto bslide = slide(b.to_bytes());

   Ed25519_Point_Cached Ai[8]; /* A,3A,5A,7A,9A,11A,13A,15A */
   Ai[0] = Ed25519_Point_Cached::from(A);
   const auto A2 = Ed25519_Point_Extended::from(A.dbl());

   for(size_t i = 1; i != 8; ++i) {
      Ai[i] = Ed25519_Point_Cached::from(A2 + Ai[i - 1]);
   }

   auto r = Ed25519_Point_Projective::identity();

   int i = [&]() -> int {
      int w = 255;
      while(w >= 0) {
         if(aslide[w] != 0 || bslide[w] != 0) {
            return w;
         } else {
            w--;
         }
      }
      return 0;
   }();

   for(; i >= 0; --i) {
      auto t = r.dbl();

      if(aslide[i] > 0) {
         t = Ed25519_Point_Extended::from(t) + Ai[aslide[i] >> 1];
      } else if(aslide[i] < 0) {
         t = Ed25519_Point_Extended::from(t) - Ai[(-aslide[i]) >> 1];
      }

      if(bslide[i] > 0) {
         t = Ed25519_Point_Extended::from(t) + Bi[bslide[i] >> 1];
      } else if(bslide[i] < 0) {
         t = Ed25519_Point_Extended::from(t) - Bi[(-bslide[i]) >> 1];
      }

      r = Ed25519_Point_Projective::from(t);
   }

   r.serialize_to(std::span<uint8_t, 32>{out});
}

Ed25519_Point_Niels select(const Ed25519_Point_Niels base[8], int8_t b) {
   const uint8_t bnegative = static_cast<uint8_t>(b) >> 7;
   const uint8_t babs = b - ((-static_cast<int>(bnegative) & b) * 2);

   auto t = Ed25519_Point_Niels::identity();

   for(size_t i = 0; i != 8; ++i) {
      const auto b_is_i1 = CT::Mask<uint8_t>::is_equal(babs, static_cast<uint8_t>(i + 1)).as_choice();
      t.yplusx.conditional_assign(b_is_i1, base[i].yplusx);
      t.yminusx.conditional_assign(b_is_i1, base[i].yminusx);
      t.xy2d.conditional_assign(b_is_i1, base[i].xy2d);
   }

   // If negative have to swap yminusx and yplusx, and negate xy2d
   const auto is_negative = CT::Mask<uint8_t>::expand(bnegative).as_choice();
   Ed25519_FieldElement::conditional_swap(is_negative, t.yplusx, t.yminusx);
   t.xy2d.conditional_assign(is_negative, -t.xy2d);

   return t;
}

}  // namespace

/*
h = a * B
where a = a[0]+256*a[1]+...+256^31 a[31]
B is the Ed25519 base point (x,4/5) with x positive.

Preconditions:
  a[31] <= 127
*/
void ed25519_basepoint_mul(std::span<uint8_t, 32> out, const Ed25519_Scalar& scalar) {
   static const std::array<std::array<Ed25519_Point_Niels, 8>, 32> B_precomp = ed25519_base_precomp();

   const auto a = scalar.to_bytes();

   std::array<int8_t, 64> e{};

   CT::poison(a.data(), a.size());

   // each e[i] is between 0 and 15 except e[63] which is between 0 and 7
   for(size_t i = 0; i != 32; ++i) {
      e[2 * i + 0] = (a[i] >> 0) & 0x0F;
      e[2 * i + 1] = (a[i] >> 4) & 0x0F;
   }

   int8_t carry = 0;
   for(size_t i = 0; i < 63; ++i) {
      e[i] += carry;
      carry = e[i] + 8;
      carry >>= 4;
      e[i] -= carry << 4;
   }
   e[63] += carry;
   /* each e[i] is between -8 and 8 */

   auto h = Ed25519_Point_Extended::identity();
   for(size_t i = 1; i < 64; i += 2) {
      h = Ed25519_Point_Extended::from(h + select(B_precomp[i / 2].data(), e[i]));
   }

   auto s = Ed25519_Point_Projective::from(h.dbl());
   s = Ed25519_Point_Projective::from(s.dbl());
   s = Ed25519_Point_Projective::from(s.dbl());
   h = Ed25519_Point_Extended::from(s.dbl());

   for(size_t i = 0; i != 64; i += 2) {
      h = Ed25519_Point_Extended::from(h + select(B_precomp[i / 2].data(), e[i]));
   }

   h.serialize_to(out);

   CT::unpoison(a.data(), a.size());
   CT::unpoison(out);
}

bool ed25519_check_signature(std::span<const uint8_t, 32> pk,
                             const Ed25519_Scalar& h,
                             const uint8_t r[32],
                             const Ed25519_Scalar& s) {
   if(auto A = frombytes_negate_vartime(pk)) {
      std::array<uint8_t, 32> rcheck{};
      ge_double_scalarmult_vartime(rcheck, h, *A, s);
      return CT::is_equal(rcheck.data(), r, 32).as_bool();
   }
   return false;
}

bool ed25519_valid_public_key_point(std::span<const uint8_t, 32> pk) {
   if(auto A = frombytes_negate_vartime(pk)) {
      // Points with x == 0 are the identity and the point of order 2;
      // neither is a valid public key
      if(A->X.is_zero()) {
         return false;
      }

      /*
      * Check that the point is in the prime order subgroup, ie that
      * [l]A == O, by checking that [l-1]A + A == O, or equivalently that
      * [l-1]A == -A. Since l-1 == -1 (mod l) the scalar is just -1, and
      * since frombytes_negate_vartime returned -A the final comparison is
      * against the encoding of A, ie of the negation of what it returned.
      */
      auto neg_A = *A;
      neg_A.X = -A->X;
      neg_A.T = -A->T;

      std::array<uint8_t, 32> acheck{};
      neg_A.serialize_to(acheck);

      std::array<uint8_t, 32> rcheck{};
      ge_double_scalarmult_vartime(rcheck, -Ed25519_Scalar::one(), *A, Ed25519_Scalar::zero());

      return CT::is_equal(rcheck.data(), acheck.data(), 32).as_bool();
   }
   return false;
}

}  // namespace Botan
