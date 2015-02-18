/*
* Scalar emulation of SIMD
* (C) 2009,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SIMD_SCALAR_H__
#define BOTAN_SIMD_SCALAR_H__

#include <botan/loadstor.h>
#include <botan/bswap.h>

namespace Botan {

/**
* Fake SIMD, using plain scalar operations
* Often still faster than iterative on superscalar machines
*/
template<typename T, size_t N>
class SIMD_Scalar
   {
   public:
      static bool enabled() { return true; }

      static size_t size() { return N; }

      SIMD_Scalar() { /* uninitialized */ }

      SIMD_Scalar(const T B[N])
         {
         for(size_t i = 0; i != size(); ++i)
            m_v[i] = B[i];
         }

      SIMD_Scalar(T B)
         {
         for(size_t i = 0; i != size(); ++i)
            m_v[i] = B;
         }

      static SIMD_Scalar<T,N> load_le(const void* in)
         {
         SIMD_Scalar<T,N> out;
         const byte* in_b = static_cast<const byte*>(in);

         for(size_t i = 0; i != size(); ++i)
            out.m_v[i] = Botan::load_le<T>(in_b, i);

         return out;
         }

      static SIMD_Scalar<T,N> load_be(const void* in)
         {
         SIMD_Scalar<T,N> out;
         const byte* in_b = static_cast<const byte*>(in);

         for(size_t i = 0; i != size(); ++i)
            out.m_v[i] = Botan::load_be<T>(in_b, i);

         return out;
         }

      void store_le(byte out[]) const
         {
         for(size_t i = 0; i != size(); ++i)
            Botan::store_le(m_v[i], out + i*sizeof(T));
         }

      void store_be(byte out[]) const
         {
         for(size_t i = 0; i != size(); ++i)
            Botan::store_be(m_v[i], out + i*sizeof(T));
         }

      void rotate_left(size_t rot)
         {
         for(size_t i = 0; i != size(); ++i)
            m_v[i] = Botan::rotate_left(m_v[i], rot);
         }

      void rotate_right(size_t rot)
         {
         for(size_t i = 0; i != size(); ++i)
            m_v[i] = Botan::rotate_right(m_v[i], rot);
         }

      void operator+=(const SIMD_Scalar<T,N>& other)
         {
         for(size_t i = 0; i != size(); ++i)
            m_v[i] += other.m_v[i];
         }

      void operator-=(const SIMD_Scalar<T,N>& other)
         {
         for(size_t i = 0; i != size(); ++i)
            m_v[i] -= other.m_v[i];
         }

      SIMD_Scalar<T,N> operator+(const SIMD_Scalar<T,N>& other) const
         {
         SIMD_Scalar<T,N> out = *this;
         out += other;
         return out;
         }

      SIMD_Scalar<T,N> operator-(const SIMD_Scalar<T,N>& other) const
         {
         SIMD_Scalar<T,N> out = *this;
         out -= other;
         return out;
         }

      void operator^=(const SIMD_Scalar<T,N>& other)
         {
         for(size_t i = 0; i != size(); ++i)
            m_v[i] ^= other.m_v[i];
         }

      SIMD_Scalar<T,N> operator^(const SIMD_Scalar<T,N>& other) const
         {
         SIMD_Scalar<T,N> out = *this;
         out ^= other;
         return out;
         }

      void operator|=(const SIMD_Scalar<T,N>& other)
         {
         for(size_t i = 0; i != size(); ++i)
            m_v[i] |= other.m_v[i];
         }

      void operator&=(const SIMD_Scalar<T,N>& other)
         {
         for(size_t i = 0; i != size(); ++i)
            m_v[i] &= other.m_v[i];
         }

      SIMD_Scalar<T,N> operator&(const SIMD_Scalar<T,N>& other)
         {
         SIMD_Scalar<T,N> out = *this;
         out &= other;
         return out;
         }

      SIMD_Scalar<T,N> operator<<(size_t shift) const
         {
         SIMD_Scalar<T,N> out = *this;
         for(size_t i = 0; i != size(); ++i)
            out.m_v[i] <<= shift;
         return out;
         }

      SIMD_Scalar<T,N> operator>>(size_t shift) const
         {
         SIMD_Scalar<T,N> out = *this;
         for(size_t i = 0; i != size(); ++i)
            out.m_v[i] >>= shift;
         return out;
         }

      SIMD_Scalar<T,N> operator~() const
         {
         SIMD_Scalar<T,N> out = *this;
         for(size_t i = 0; i != size(); ++i)
            out.m_v[i] = ~out.m_v[i];
         return out;
         }

      // (~reg) & other
      SIMD_Scalar<T,N> andc(const SIMD_Scalar<T,N>& other)
         {
         SIMD_Scalar<T,N> out;
         for(size_t i = 0; i != size(); ++i)
            out.m_v[i] = (~m_v[i]) & other.m_v[i];
         return out;
         }

      SIMD_Scalar<T,N> bswap() const
         {
         SIMD_Scalar<T,N> out;
         for(size_t i = 0; i != size(); ++i)
            out.m_v[i] = reverse_bytes(m_v[i]);
         return out;
         }

      static void transpose(SIMD_Scalar<T,N>& B0, SIMD_Scalar<T,N>& B1,
                            SIMD_Scalar<T,N>& B2, SIMD_Scalar<T,N>& B3)
         {
         static_assert(N == 4, "4x4 transpose");
         SIMD_Scalar<T,N> T0({B0.m_v[0], B1.m_v[0], B2.m_v[0], B3.m_v[0]});
         SIMD_Scalar<T,N> T1({B0.m_v[1], B1.m_v[1], B2.m_v[1], B3.m_v[1]});
         SIMD_Scalar<T,N> T2({B0.m_v[2], B1.m_v[2], B2.m_v[2], B3.m_v[2]});
         SIMD_Scalar<T,N> T3({B0.m_v[3], B1.m_v[3], B2.m_v[3], B3.m_v[3]});

         B0 = T0;
         B1 = T1;
         B2 = T2;
         B3 = T3;
         }

   private:
      SIMD_Scalar(std::initializer_list<T> B)
         {
         size_t i = 0;
         for(auto v = B.begin(); v != B.end(); ++v)
            m_v[i++] = *v;
         }

      T m_v[N];
   };

}

#endif
