/*
* Threefish-512
* (C) 2013,2014,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/threefish_512.h>

#include <botan/internal/cpuid.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>

namespace Botan {

namespace Threefish_F {

template <size_t R1, size_t R2, size_t R3, size_t R4>
BOTAN_FORCE_INLINE void e_round(
   uint64_t& X0, uint64_t& X1, uint64_t& X2, uint64_t& X3, uint64_t& X4, uint64_t& X5, uint64_t& X6, uint64_t& X7) {
   X0 += X4;
   X1 += X5;
   X2 += X6;
   X3 += X7;
   X4 = rotl<R1>(X4);
   X5 = rotl<R2>(X5);
   X6 = rotl<R3>(X6);
   X7 = rotl<R4>(X7);
   X4 ^= X0;
   X5 ^= X1;
   X6 ^= X2;
   X7 ^= X3;
}

template <size_t R1, size_t R2, size_t R3, size_t R4>
BOTAN_FORCE_INLINE void d_round(
   uint64_t& X0, uint64_t& X1, uint64_t& X2, uint64_t& X3, uint64_t& X4, uint64_t& X5, uint64_t& X6, uint64_t& X7) {
   X4 ^= X0;
   X5 ^= X1;
   X6 ^= X2;
   X7 ^= X3;
   X4 = rotr<R1>(X4);
   X5 = rotr<R2>(X5);
   X6 = rotr<R3>(X6);
   X7 = rotr<R4>(X7);
   X0 -= X4;
   X1 -= X5;
   X2 -= X6;
   X3 -= X7;
}

class Key_Inserter {
   public:
      Key_Inserter(const uint64_t* K, const uint64_t* T) : m_K(K), m_T(T) {}

      void e_add(size_t R,
                 uint64_t& X0,
                 uint64_t& X1,
                 uint64_t& X2,
                 uint64_t& X3,
                 uint64_t& X4,
                 uint64_t& X5,
                 uint64_t& X6,
                 uint64_t& X7) const {
         X0 += m_K[(R) % 9];
         X1 += m_K[(R + 1) % 9];
         X2 += m_K[(R + 2) % 9];
         X3 += m_K[(R + 3) % 9];
         X4 += m_K[(R + 4) % 9];
         X5 += m_K[(R + 5) % 9] + m_T[(R) % 3];
         X6 += m_K[(R + 6) % 9] + m_T[(R + 1) % 3];
         X7 += m_K[(R + 7) % 9] + R;
      }

      void d_add(size_t R,
                 uint64_t& X0,
                 uint64_t& X1,
                 uint64_t& X2,
                 uint64_t& X3,
                 uint64_t& X4,
                 uint64_t& X5,
                 uint64_t& X6,
                 uint64_t& X7) const {
         X0 -= m_K[(R) % 9];
         X1 -= m_K[(R + 1) % 9];
         X2 -= m_K[(R + 2) % 9];
         X3 -= m_K[(R + 3) % 9];
         X4 -= m_K[(R + 4) % 9];
         X5 -= m_K[(R + 5) % 9] + m_T[(R) % 3];
         X6 -= m_K[(R + 6) % 9] + m_T[(R + 1) % 3];
         X7 -= m_K[(R + 7) % 9] + R;
      }

   private:
      const uint64_t* m_K;
      const uint64_t* m_T;
};

template <size_t R1, size_t R2>
BOTAN_FORCE_INLINE void e8_rounds(uint64_t& X0,
                                  uint64_t& X1,
                                  uint64_t& X2,
                                  uint64_t& X3,
                                  uint64_t& X4,
                                  uint64_t& X5,
                                  uint64_t& X6,
                                  uint64_t& X7,
                                  const Key_Inserter& key) {
   e_round<46, 36, 19, 37>(X0, X2, X4, X6, X1, X3, X5, X7);
   e_round<33, 27, 14, 42>(X2, X4, X6, X0, X1, X7, X5, X3);
   e_round<17, 49, 36, 39>(X4, X6, X0, X2, X1, X3, X5, X7);
   e_round<44, 9, 54, 56>(X6, X0, X2, X4, X1, X7, X5, X3);
   key.e_add(R1, X0, X1, X2, X3, X4, X5, X6, X7);

   e_round<39, 30, 34, 24>(X0, X2, X4, X6, X1, X3, X5, X7);
   e_round<13, 50, 10, 17>(X2, X4, X6, X0, X1, X7, X5, X3);
   e_round<25, 29, 39, 43>(X4, X6, X0, X2, X1, X3, X5, X7);
   e_round<8, 35, 56, 22>(X6, X0, X2, X4, X1, X7, X5, X3);
   key.e_add(R2, X0, X1, X2, X3, X4, X5, X6, X7);
}

template <size_t R1, size_t R2>
BOTAN_FORCE_INLINE void d8_rounds(uint64_t& X0,
                                  uint64_t& X1,
                                  uint64_t& X2,
                                  uint64_t& X3,
                                  uint64_t& X4,
                                  uint64_t& X5,
                                  uint64_t& X6,
                                  uint64_t& X7,
                                  const Key_Inserter& key) {
   d_round<8, 35, 56, 22>(X6, X0, X2, X4, X1, X7, X5, X3);
   d_round<25, 29, 39, 43>(X4, X6, X0, X2, X1, X3, X5, X7);
   d_round<13, 50, 10, 17>(X2, X4, X6, X0, X1, X7, X5, X3);
   d_round<39, 30, 34, 24>(X0, X2, X4, X6, X1, X3, X5, X7);
   key.d_add(R1, X0, X1, X2, X3, X4, X5, X6, X7);

   d_round<44, 9, 54, 56>(X6, X0, X2, X4, X1, X7, X5, X3);
   d_round<17, 49, 36, 39>(X4, X6, X0, X2, X1, X3, X5, X7);
   d_round<33, 27, 14, 42>(X2, X4, X6, X0, X1, X7, X5, X3);
   d_round<46, 36, 19, 37>(X0, X2, X4, X6, X1, X3, X5, X7);
   key.d_add(R2, X0, X1, X2, X3, X4, X5, X6, X7);
}

}  // namespace Threefish_F

void Threefish_512::skein_feedfwd(const secure_vector<uint64_t>& M, const secure_vector<uint64_t>& T) {
   using namespace Threefish_F;

   BOTAN_ASSERT(m_K.size() == 9, "Key was set");
   BOTAN_ASSERT(M.size() == 8, "Single block");

   m_T[0] = T[0];
   m_T[1] = T[1];
   m_T[2] = T[0] ^ T[1];

   const Key_Inserter key(m_K.data(), m_T.data());

   uint64_t X0 = M[0];
   uint64_t X1 = M[1];
   uint64_t X2 = M[2];
   uint64_t X3 = M[3];
   uint64_t X4 = M[4];
   uint64_t X5 = M[5];
   uint64_t X6 = M[6];
   uint64_t X7 = M[7];

   key.e_add(0, X0, X1, X2, X3, X4, X5, X6, X7);

   e8_rounds<1, 2>(X0, X1, X2, X3, X4, X5, X6, X7, key);
   e8_rounds<3, 4>(X0, X1, X2, X3, X4, X5, X6, X7, key);
   e8_rounds<5, 6>(X0, X1, X2, X3, X4, X5, X6, X7, key);
   e8_rounds<7, 8>(X0, X1, X2, X3, X4, X5, X6, X7, key);
   e8_rounds<9, 10>(X0, X1, X2, X3, X4, X5, X6, X7, key);
   e8_rounds<11, 12>(X0, X1, X2, X3, X4, X5, X6, X7, key);
   e8_rounds<13, 14>(X0, X1, X2, X3, X4, X5, X6, X7, key);
   e8_rounds<15, 16>(X0, X1, X2, X3, X4, X5, X6, X7, key);
   e8_rounds<17, 18>(X0, X1, X2, X3, X4, X5, X6, X7, key);

   m_K[0] = M[0] ^ X0;
   m_K[1] = M[1] ^ X1;
   m_K[2] = M[2] ^ X2;
   m_K[3] = M[3] ^ X3;
   m_K[4] = M[4] ^ X4;
   m_K[5] = M[5] ^ X5;
   m_K[6] = M[6] ^ X6;
   m_K[7] = M[7] ^ X7;

   m_K[8] = m_K[0] ^ m_K[1] ^ m_K[2] ^ m_K[3] ^ m_K[4] ^ m_K[5] ^ m_K[6] ^ m_K[7] ^ 0x1BD11BDAA9FC1A22;
}

void Threefish_512::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   using namespace Threefish_F;

   assert_key_material_set();

   const Key_Inserter key(m_K.data(), m_T.data());

   for(size_t i = 0; i < blocks; ++i) {
      uint64_t X0, X1, X2, X3, X4, X5, X6, X7;
      load_le(in + BLOCK_SIZE * i, X0, X1, X2, X3, X4, X5, X6, X7);

      key.e_add(0, X0, X1, X2, X3, X4, X5, X6, X7);

      e8_rounds<1, 2>(X0, X1, X2, X3, X4, X5, X6, X7, key);
      e8_rounds<3, 4>(X0, X1, X2, X3, X4, X5, X6, X7, key);
      e8_rounds<5, 6>(X0, X1, X2, X3, X4, X5, X6, X7, key);
      e8_rounds<7, 8>(X0, X1, X2, X3, X4, X5, X6, X7, key);
      e8_rounds<9, 10>(X0, X1, X2, X3, X4, X5, X6, X7, key);
      e8_rounds<11, 12>(X0, X1, X2, X3, X4, X5, X6, X7, key);
      e8_rounds<13, 14>(X0, X1, X2, X3, X4, X5, X6, X7, key);
      e8_rounds<15, 16>(X0, X1, X2, X3, X4, X5, X6, X7, key);
      e8_rounds<17, 18>(X0, X1, X2, X3, X4, X5, X6, X7, key);

      store_le(out + BLOCK_SIZE * i, X0, X1, X2, X3, X4, X5, X6, X7);
   }
}

void Threefish_512::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   using namespace Threefish_F;

   assert_key_material_set();

   const Key_Inserter key(m_K.data(), m_T.data());

   for(size_t i = 0; i < blocks; ++i) {
      uint64_t X0, X1, X2, X3, X4, X5, X6, X7;
      load_le(in + BLOCK_SIZE * i, X0, X1, X2, X3, X4, X5, X6, X7);

      key.d_add(18, X0, X1, X2, X3, X4, X5, X6, X7);

      d8_rounds<17, 16>(X0, X1, X2, X3, X4, X5, X6, X7, key);
      d8_rounds<15, 14>(X0, X1, X2, X3, X4, X5, X6, X7, key);
      d8_rounds<13, 12>(X0, X1, X2, X3, X4, X5, X6, X7, key);
      d8_rounds<11, 10>(X0, X1, X2, X3, X4, X5, X6, X7, key);
      d8_rounds<9, 8>(X0, X1, X2, X3, X4, X5, X6, X7, key);
      d8_rounds<7, 6>(X0, X1, X2, X3, X4, X5, X6, X7, key);
      d8_rounds<5, 4>(X0, X1, X2, X3, X4, X5, X6, X7, key);
      d8_rounds<3, 2>(X0, X1, X2, X3, X4, X5, X6, X7, key);
      d8_rounds<1, 0>(X0, X1, X2, X3, X4, X5, X6, X7, key);

      store_le(out + BLOCK_SIZE * i, X0, X1, X2, X3, X4, X5, X6, X7);
   }
}

void Threefish_512::set_tweak(const uint8_t tweak[], size_t len) {
   BOTAN_ARG_CHECK(len == 16, "Threefish-512 requires 128 bit tweak");

   m_T.resize(3);
   m_T[0] = load_le<uint64_t>(tweak, 0);
   m_T[1] = load_le<uint64_t>(tweak, 1);
   m_T[2] = m_T[0] ^ m_T[1];
}

bool Threefish_512::has_keying_material() const {
   return !m_K.empty();
}

void Threefish_512::key_schedule(std::span<const uint8_t> key) {
   // todo: define key schedule for smaller keys
   m_K.resize(9);

   for(size_t i = 0; i != 8; ++i) {
      m_K[i] = load_le<uint64_t>(key.data(), i);
   }

   m_K[8] = m_K[0] ^ m_K[1] ^ m_K[2] ^ m_K[3] ^ m_K[4] ^ m_K[5] ^ m_K[6] ^ m_K[7] ^ 0x1BD11BDAA9FC1A22;

   // Reset tweak to all zeros on key reset
   m_T.resize(3);
   zeroise(m_T);
}

void Threefish_512::clear() {
   zap(m_K);
   zap(m_T);
}

}  // namespace Botan
