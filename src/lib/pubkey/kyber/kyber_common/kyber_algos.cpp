/*
 * Crystals Kyber Internal Algorithms
 * Based on the public domain reference implementation by the
 * designers (https://github.com/pq-crystals/kyber)
 *
 * Further changes
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/kyber_algos.h>

#include <botan/internal/kyber_helpers.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/pqcrystals_encoding.h>

namespace Botan::Kyber_Algos {

namespace {

/**
 * NIST FIPS 203 IPD, Algorithm 4 (ByteEncode) for d < 12 in combination with
 * Formula 4.5 (Compress)
 */
template <size_t d>
   requires(d < 12)
void poly_compress_and_encode(BufferStuffer& bs, const KyberPoly& p) {
   CRYSTALS::pack<(1 << d) - 1>(p, bs, compress<d>);
}

/**
 * NIST FIPS 203 IPD, Algorithm 4 (ByteEncode) for d == 12
 */
void byte_encode(BufferStuffer& bs, const KyberPolyNTT& p) {
   CRYSTALS::pack<KyberConstants::Q - 1>(p, bs);
}

/**
 * NIST FIPS 203 IPD, Algorithm 5 (ByteDecode) for d < 12 in combination with
 * Formula 4.6 (Decompress)
 */
template <size_t d>
   requires(d < 12)
void poly_decode_and_decompress(KyberPoly& p, BufferSlicer& bs) {
   CRYSTALS::unpack<(1 << d) - 1>(p, bs, decompress<d>);
}

/**
 * NIST FIPS 203 IPD, Algorithm 5 (ByteDecode) for d == 12
 */
void byte_decode(KyberPolyNTT& p, BufferSlicer& bs) {
   CRYSTALS::unpack<KyberConstants::Q - 1>(p, bs);

   if(!p.ct_validate_value_range(0, KyberConstants::Q - 1)) {
      throw Decoding_Error("Decoded polynomial coefficients out of range");
   }
}

/**
 * NIST FIPS 203 IPD, Algorithm 6 (SampleNTT)
 */
void sample_ntt_uniform(KyberPolyNTT& p, XOF& xof) {
   auto sample = [&xof]() -> std::pair<uint16_t, uint16_t> {
      const auto x = load_le3(xof.output<3>());
      return {static_cast<uint16_t>(x & 0x0FFF), static_cast<uint16_t>(x >> 12)};
   };

   for(size_t count = 0; count < p.size();) {
      const auto [d1, d2] = sample();

      if(d1 < KyberConstants::Q) {
         p[count++] = d1;
      }
      if(count < p.size() && d2 < KyberConstants::Q) {
         p[count++] = d2;
      }
   }
}

/**
 * NIST FIPS 203 IPD, Algorithm 7 (SamplePolyCBD) for eta = 2
 */
void sample_poly_cbd2(KyberPoly& poly, StrongSpan<const KyberSamplingRandomness> randomness) {
   BufferSlicer bs(randomness);

   for(size_t i = 0; i < poly.size() / 8; ++i) {
      const uint32_t t = Botan::load_le(bs.take<4>());

      // SIMD trick: calculate 16 2-bit-sums in parallel
      constexpr uint32_t operand_bitmask = 0b01010101010101010101010101010101;

      // clang-format off
      const uint32_t d = ((t >> 0) & operand_bitmask) +
                         ((t >> 1) & operand_bitmask);
      // clang-format on

      for(size_t j = 0; j < 8; ++j) {
         const int16_t a = (d >> (4 * j + 0)) & 0x3;
         const int16_t b = (d >> (4 * j + 2)) & 0x3;
         poly[8 * i + j] = a - b;
      }
   }

   BOTAN_ASSERT_NOMSG(bs.empty());
}

/**
 * NIST FIPS 203 IPD, Algorithm 7 (SamplePolyCBD) for eta = 2
 */
void sample_poly_cbd3(KyberPoly& poly, StrongSpan<const KyberSamplingRandomness> randomness) {
   BufferSlicer bs(randomness);

   for(size_t i = 0; i < poly.size() / 4; ++i) {
      const uint32_t t = load_le3(bs.take<3>());

      // SIMD trick: calculate 8 3-bit-sums in parallel
      constexpr uint32_t operand_bitmask = 0b00000000001001001001001001001001;

      // clang-format off
      const uint32_t d = ((t >> 0) & operand_bitmask) +
                         ((t >> 1) & operand_bitmask) +
                         ((t >> 2) & operand_bitmask);
      // clang-format on

      for(size_t j = 0; j < 4; ++j) {
         const int16_t a = (d >> (6 * j + 0)) & 0x7;
         const int16_t b = (d >> (6 * j + 3)) & 0x7;
         poly[4 * i + j] = a - b;
      }
   }

   BOTAN_ASSERT_NOMSG(bs.empty());
}

}  // namespace

void encode_polynomial_vector(std::span<uint8_t> out, const KyberPolyVecNTT& vec) {
   BufferStuffer bs(out);
   for(auto& v : vec) {
      byte_encode(bs, v);
   }
   BOTAN_ASSERT_NOMSG(bs.full());
}

KyberPolyVecNTT decode_polynomial_vector(std::span<const uint8_t> a, const KyberConstants& mode) {
   KyberPolyVecNTT vec(mode.k());

   BufferSlicer bs(a);
   for(auto& p : vec) {
      byte_decode(p, bs);
   }
   BOTAN_ASSERT_NOMSG(bs.empty());

   return vec;
}

KyberPoly polynomial_from_message(StrongSpan<const KyberMessage> msg) {
   BOTAN_ASSERT(msg.size() == KyberConstants::N / 8, "message length must be N/8 bytes");
   KyberPoly r;
   BufferSlicer bs(msg);
   poly_decode_and_decompress<1>(r, bs);
   return r;
}

KyberMessage polynomial_to_message(const KyberPoly& p) {
   KyberMessage result(p.size() / 8);
   BufferStuffer bs(result);
   poly_compress_and_encode<1>(bs, p);
   return result;
}

namespace {

template <size_t d>
void polyvec_compress_and_encode(BufferStuffer& sink, const KyberPolyVec& polyvec) {
   for(const auto& p : polyvec) {
      poly_compress_and_encode<d>(sink, p);
   }
}

void compress_polyvec(std::span<uint8_t> out, const KyberPolyVec& pv, const KyberConstants& mode) {
   BufferStuffer bs(out);

   switch(mode.d_u()) {
      case KyberConstants::KyberDu::_10:
         polyvec_compress_and_encode<10>(bs, pv);
         BOTAN_ASSERT_NOMSG(bs.full());
         return;
      case KyberConstants::KyberDu::_11:
         polyvec_compress_and_encode<11>(bs, pv);
         BOTAN_ASSERT_NOMSG(bs.full());
         return;
   }

   BOTAN_ASSERT_UNREACHABLE();
}

void compress_poly(std::span<uint8_t> out, const KyberPoly& p, const KyberConstants& mode) {
   BufferStuffer bs(out);

   switch(mode.d_v()) {
      case KyberConstants::KyberDv::_4:
         poly_compress_and_encode<4>(bs, p);
         BOTAN_ASSERT_NOMSG(bs.full());
         return;
      case KyberConstants::KyberDv::_5:
         poly_compress_and_encode<5>(bs, p);
         BOTAN_ASSERT_NOMSG(bs.full());
         return;
   }

   BOTAN_ASSERT_UNREACHABLE();
}

template <size_t d>
void polyvec_decode_and_decompress(KyberPolyVec& polyvec, BufferSlicer& source) {
   for(auto& p : polyvec) {
      poly_decode_and_decompress<d>(p, source);
   }
}

KyberPolyVec decompress_polynomial_vector(std::span<const uint8_t> buffer, const KyberConstants& mode) {
   BOTAN_ASSERT(buffer.size() == mode.polynomial_vector_compressed_bytes(),
                "unexpected length of compressed polynomial vector");

   KyberPolyVec r(mode.k());
   BufferSlicer bs(buffer);

   switch(mode.d_u()) {
      case KyberConstants::KyberDu::_10:
         polyvec_decode_and_decompress<10>(r, bs);
         BOTAN_ASSERT_NOMSG(bs.empty());
         return r;
      case KyberConstants::KyberDu::_11:
         polyvec_decode_and_decompress<11>(r, bs);
         BOTAN_ASSERT_NOMSG(bs.empty());
         return r;
   }

   BOTAN_ASSERT_UNREACHABLE();
}

KyberPoly decompress_polynomial(std::span<const uint8_t> buffer, const KyberConstants& mode) {
   BOTAN_ASSERT(buffer.size() == mode.polynomial_compressed_bytes(), "unexpected length of compressed polynomial");

   KyberPoly r;
   BufferSlicer bs(buffer);

   switch(mode.d_v()) {
      case KyberConstants::KyberDv::_4:
         poly_decode_and_decompress<4>(r, bs);
         BOTAN_ASSERT_NOMSG(bs.empty());
         return r;
      case KyberConstants::KyberDv::_5:
         poly_decode_and_decompress<5>(r, bs);
         BOTAN_ASSERT_NOMSG(bs.empty());
         return r;
   }

   BOTAN_ASSERT_UNREACHABLE();
}

}  // namespace

void compress_ciphertext(StrongSpan<KyberCompressedCiphertext> out,
                         const KyberPolyVec& u,
                         const KyberPoly& v,
                         const KyberConstants& m_mode) {
   BufferStuffer bs(out);
   compress_polyvec(bs.next(m_mode.polynomial_vector_compressed_bytes()), u, m_mode);
   compress_poly(bs.next(m_mode.polynomial_compressed_bytes()), v, m_mode);
   BOTAN_ASSERT_NOMSG(bs.full());
}

std::pair<KyberPolyVec, KyberPoly> decompress_ciphertext(StrongSpan<const KyberCompressedCiphertext> ct,
                                                         const KyberConstants& mode) {
   const size_t pvb = mode.polynomial_vector_compressed_bytes();
   const size_t pcb = mode.polynomial_compressed_bytes();

   if(ct.size() != pvb + pcb) {
      throw Decoding_Error("Kyber: unexpected ciphertext length");
   }

   BufferSlicer bs(ct);
   auto pv = bs.take(pvb);
   auto p = bs.take(pcb);
   BOTAN_ASSERT_NOMSG(bs.empty());

   return {decompress_polynomial_vector(pv, mode), decompress_polynomial(p, mode)};
}

KyberPolyMat sample_matrix(StrongSpan<const KyberSeedRho> seed, bool transposed, const KyberConstants& mode) {
   BOTAN_ASSERT(seed.size() == KyberConstants::SEED_BYTES, "unexpected seed size");

   KyberPolyMat mat(mode.k(), mode.k());

   for(uint8_t i = 0; i < mode.k(); ++i) {
      for(uint8_t j = 0; j < mode.k(); ++j) {
         const auto pos = (transposed) ? std::tuple(i, j) : std::tuple(j, i);
         sample_ntt_uniform(mat[i][j], mode.symmetric_primitives().XOF(seed, pos));
      }
   }

   return mat;
}

/**
 * NIST FIPS 203 IPD, Algorithm 7 (SamplePolyCBD)
 */
void sample_polynomial_from_cbd(KyberPoly& poly,
                                KyberConstants::KyberEta eta,
                                const KyberSamplingRandomness& randomness) {
   switch(eta) {
      case KyberConstants::KyberEta::_2:
         return sample_poly_cbd2(poly, randomness);
      case KyberConstants::KyberEta::_3:
         return sample_poly_cbd3(poly, randomness);
   }

   BOTAN_ASSERT_UNREACHABLE();
}

}  // namespace Botan::Kyber_Algos
