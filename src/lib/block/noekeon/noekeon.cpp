/*
* Noekeon
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/noekeon.h>
#include <botan/loadstor.h>
#include <botan/cpuid.h>

namespace Botan {

namespace {

/*
* Noekeon's Theta Operation
*/
inline void theta(uint32_t& A0, uint32_t& A1,
                  uint32_t& A2, uint32_t& A3,
                  const uint32_t EK[4]) {
  uint32_t T = A0 ^ A2;
  T ^= rotate_left(T, 8) ^ rotate_right(T, 8);
  A1 ^= T;
  A3 ^= T;

  A0 ^= EK[0];
  A1 ^= EK[1];
  A2 ^= EK[2];
  A3 ^= EK[3];

  T = A1 ^ A3;
  T ^= rotate_left(T, 8) ^ rotate_right(T, 8);
  A0 ^= T;
  A2 ^= T;
}

/*
* Theta With Null Key
*/
inline void theta(uint32_t& A0, uint32_t& A1,
                  uint32_t& A2, uint32_t& A3) {
  uint32_t T = A0 ^ A2;
  T ^= rotate_left(T, 8) ^ rotate_right(T, 8);
  A1 ^= T;
  A3 ^= T;

  T = A1 ^ A3;
  T ^= rotate_left(T, 8) ^ rotate_right(T, 8);
  A0 ^= T;
  A2 ^= T;
}

/*
* Noekeon's Gamma S-Box Layer
*/
inline void gamma(uint32_t& A0, uint32_t& A1, uint32_t& A2, uint32_t& A3) {
  A1 ^= ~A3 & ~A2;
  A0 ^= A2 & A1;

  uint32_t T = A3;
  A3 = A0;
  A0 = T;

  A2 ^= A0 ^ A1 ^ A3;

  A1 ^= ~A3 & ~A2;
  A0 ^= A2 & A1;
}

}

std::string Noekeon::provider() const {
#if defined(BOTAN_HAS_NOEKEON_SIMD)
  if (CPUID::has_simd_32()) {
    return "simd";
  }
#endif

  return "base";
}

/*
* Noekeon Round Constants
*/
const uint8_t Noekeon::RC[] = {
  0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
  0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
  0xD4
};

/*
* Noekeon Encryption
*/
void Noekeon::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
#if defined(BOTAN_HAS_NOEKEON_SIMD)
  if (CPUID::has_simd_32()) {
    while (blocks >= 4) {
      simd_encrypt_4(in, out);
      in += 4 * BLOCK_SIZE;
      out += 4 * BLOCK_SIZE;
      blocks -= 4;
    }
  }
#endif

  for (size_t i = 0; i != blocks; ++i) {
    uint32_t A0 = load_be<uint32_t>(in, 0);
    uint32_t A1 = load_be<uint32_t>(in, 1);
    uint32_t A2 = load_be<uint32_t>(in, 2);
    uint32_t A3 = load_be<uint32_t>(in, 3);

    for (size_t j = 0; j != 16; ++j) {
      A0 ^= RC[j];
      theta(A0, A1, A2, A3, m_EK.data());

      A1 = rotate_left(A1, 1);
      A2 = rotate_left(A2, 5);
      A3 = rotate_left(A3, 2);

      gamma(A0, A1, A2, A3);

      A1 = rotate_right(A1, 1);
      A2 = rotate_right(A2, 5);
      A3 = rotate_right(A3, 2);
    }

    A0 ^= RC[16];
    theta(A0, A1, A2, A3, m_EK.data());

    store_be(out, A0, A1, A2, A3);

    in += BLOCK_SIZE;
    out += BLOCK_SIZE;
  }
}

/*
* Noekeon Encryption
*/
void Noekeon::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
#if defined(BOTAN_HAS_NOEKEON_SIMD)
  if (CPUID::has_simd_32()) {
    /*
    const size_t blocks4 = blocks / 4;
    const size_t blocks_left = blocks % 4;

    in += blocks4 * BLOCK_SIZE;
    out += blocks4 * BLOCK_SIZE;
    blocks = blocks % 4;

    BOTAN_PARALLEL_FOR(size_t i = 0; i < blocks4; ++i)
       {
       simd_encrypt_4(in + i*4*BLOCK_SIZE, out + i*4*BLOCK_SIZE);
       }
    */
    while (blocks >= 4) {
      simd_decrypt_4(in, out);
      in += 4 * BLOCK_SIZE;
      out += 4 * BLOCK_SIZE;
      blocks -= 4;
    }
  }
#endif

  for (size_t i = 0; i != blocks; ++i) {
    uint32_t A0 = load_be<uint32_t>(in, 0);
    uint32_t A1 = load_be<uint32_t>(in, 1);
    uint32_t A2 = load_be<uint32_t>(in, 2);
    uint32_t A3 = load_be<uint32_t>(in, 3);

    for (size_t j = 16; j != 0; --j) {
      theta(A0, A1, A2, A3, m_DK.data());
      A0 ^= RC[j];

      A1 = rotate_left(A1, 1);
      A2 = rotate_left(A2, 5);
      A3 = rotate_left(A3, 2);

      gamma(A0, A1, A2, A3);

      A1 = rotate_right(A1, 1);
      A2 = rotate_right(A2, 5);
      A3 = rotate_right(A3, 2);
    }

    theta(A0, A1, A2, A3, m_DK.data());
    A0 ^= RC[0];

    store_be(out, A0, A1, A2, A3);

    in += BLOCK_SIZE;
    out += BLOCK_SIZE;
  }
}

/*
* Noekeon Key Schedule
*/
void Noekeon::key_schedule(const uint8_t key[], size_t) {
  uint32_t A0 = load_be<uint32_t>(key, 0);
  uint32_t A1 = load_be<uint32_t>(key, 1);
  uint32_t A2 = load_be<uint32_t>(key, 2);
  uint32_t A3 = load_be<uint32_t>(key, 3);

  for (size_t i = 0; i != 16; ++i) {
    A0 ^= RC[i];
    theta(A0, A1, A2, A3);

    A1 = rotate_left(A1, 1);
    A2 = rotate_left(A2, 5);
    A3 = rotate_left(A3, 2);

    gamma(A0, A1, A2, A3);

    A1 = rotate_right(A1, 1);
    A2 = rotate_right(A2, 5);
    A3 = rotate_right(A3, 2);
  }

  A0 ^= RC[16];

  m_DK.resize(4);
  m_DK[0] = A0;
  m_DK[1] = A1;
  m_DK[2] = A2;
  m_DK[3] = A3;

  theta(A0, A1, A2, A3);

  m_EK.resize(4);
  m_EK[0] = A0;
  m_EK[1] = A1;
  m_EK[2] = A2;
  m_EK[3] = A3;
}

/*
* Clear memory of sensitive data
*/
void Noekeon::clear() {
  zap(m_EK);
  zap(m_DK);
}

}
