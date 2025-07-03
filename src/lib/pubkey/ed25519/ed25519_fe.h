/*
* Ed25519 field element
* (C) 2017 Ribose Inc
*     2025 Jack Lloyd
*
* Based on the public domain code from SUPERCOP ref10 by
* Peter Schwabe, Daniel J. Bernstein, Niels Duif, Tanja Lange, Bo-Yin Yang
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ED25519_FE_H_
#define BOTAN_ED25519_FE_H_

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/ct_utils.h>
#include <array>

namespace Botan {

/**
* An element of the field \\Z/(2^255-19)
*
* An element t, entries t[0]...t[9], represents the integer
* t[0]+2^26 t[1]+2^51 t[2]+2^77 t[3]+2^102 t[4]+...+2^230 t[9].
* Bounds on each t[i] vary depending on context.
*/
class Ed25519_FieldElement final {
   public:
      /**
      * Default zero initialization
      */
      constexpr Ed25519_FieldElement() : m_fe{} {}

      constexpr static Ed25519_FieldElement zero() { return Ed25519_FieldElement(); }

      constexpr static Ed25519_FieldElement one() {
         auto o = Ed25519_FieldElement();
         o.m_fe[0] = 1;
         return o;
      }

      constexpr explicit Ed25519_FieldElement(std::span<int32_t, 10> fe) { copy_mem(m_fe.data(), fe.data(), 10); }

      constexpr Ed25519_FieldElement(int64_t h0,
                                     int64_t h1,
                                     int64_t h2,
                                     int64_t h3,
                                     int64_t h4,
                                     int64_t h5,
                                     int64_t h6,
                                     int64_t h7,
                                     int64_t h8,
                                     int64_t h9) {
         m_fe[0] = static_cast<int32_t>(h0);
         m_fe[1] = static_cast<int32_t>(h1);
         m_fe[2] = static_cast<int32_t>(h2);
         m_fe[3] = static_cast<int32_t>(h3);
         m_fe[4] = static_cast<int32_t>(h4);
         m_fe[5] = static_cast<int32_t>(h5);
         m_fe[6] = static_cast<int32_t>(h6);
         m_fe[7] = static_cast<int32_t>(h7);
         m_fe[8] = static_cast<int32_t>(h8);
         m_fe[9] = static_cast<int32_t>(h9);
      }

      static Ed25519_FieldElement deserialize(const uint8_t b[32]);

      void serialize_to(std::span<uint8_t, 32> b) const;

      bool is_zero() const {
         std::array<uint8_t, 32> value = {};
         this->serialize_to(value);
         return CT::all_zeros(value.data(), value.size()).as_bool();
      }

      /*
      return 1 if f is in {1,3,5,...,q-2}
      return 0 if f is in {0,2,4,...,q-1}
      */
      bool is_negative() const {
         // TODO could avoid most of the serialize computation here
         std::array<uint8_t, 32> s = {};
         this->serialize_to(s);
         return (s[0] & 0x01) == 0x01;
      }

      static Ed25519_FieldElement add(const Ed25519_FieldElement& a, const Ed25519_FieldElement& b) {
         Ed25519_FieldElement z;
         for(size_t i = 0; i != 10; ++i) {
            z.m_fe[i] = a.m_fe[i] + b.m_fe[i];
         }
         return z;
      }

      static Ed25519_FieldElement sub(const Ed25519_FieldElement& a, const Ed25519_FieldElement& b) {
         Ed25519_FieldElement z;
         for(size_t i = 0; i != 10; ++i) {
            z.m_fe[i] = a.m_fe[i] - b.m_fe[i];
         }
         return z;
      }

      static Ed25519_FieldElement negate(const Ed25519_FieldElement& a) {
         Ed25519_FieldElement z;
         for(size_t i = 0; i != 10; ++i) {
            z.m_fe[i] = -a.m_fe[i];
         }
         return z;
      }

      static Ed25519_FieldElement mul(const Ed25519_FieldElement& a, const Ed25519_FieldElement& b);

      Ed25519_FieldElement sqr_iter(size_t iter) const;

      Ed25519_FieldElement sqr() const { return sqr_iter(1); }

      // Return 2*a^2
      Ed25519_FieldElement sqr2() const;

      Ed25519_FieldElement invert() const;

      Ed25519_FieldElement pow_22523() const;

      // TODO remove
      int32_t operator[](size_t i) const { return m_fe[i]; }

      int32_t& operator[](size_t i) { return m_fe[i]; }

   private:
      std::array<int32_t, 10> m_fe;
};

inline Ed25519_FieldElement operator+(const Ed25519_FieldElement& x, const Ed25519_FieldElement& y) {
   return Ed25519_FieldElement::add(x, y);
}

inline Ed25519_FieldElement operator-(const Ed25519_FieldElement& x, const Ed25519_FieldElement& y) {
   return Ed25519_FieldElement::sub(x, y);
}

inline Ed25519_FieldElement operator*(const Ed25519_FieldElement& x, const Ed25519_FieldElement& y) {
   return Ed25519_FieldElement::mul(x, y);
}

inline Ed25519_FieldElement operator-(const Ed25519_FieldElement& x) {
   return Ed25519_FieldElement::negate(x);
}

}  // namespace Botan

#endif
