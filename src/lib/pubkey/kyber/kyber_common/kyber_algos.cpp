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
#include <botan/internal/kyber_keys.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/pqcrystals_encoding.h>
#include <botan/internal/pqcrystals_helpers.h>

#include <utility>

namespace Botan::Kyber_Algos {

namespace {

/**
 * NIST FIPS 203, Algorithm 5 (ByteEncode) for d < 12 in combination with
 * Formula 4.7 (Compress)
 */
template <size_t d>
   requires(d < 12)
void poly_compress_and_encode(BufferStuffer& bs, const KyberPoly& p) {
   CRYSTALS::pack<(1 << d) - 1>(p, bs, compress<d>);
}

/**
 * NIST FIPS 203, Algorithm 5 (ByteEncode) for d == 12
 */
void byte_encode(BufferStuffer& bs, const KyberPolyNTT& p) {
   CRYSTALS::pack<KyberConstants::Q - 1>(p, bs);
}

/**
 * NIST FIPS 203, Algorithm 6 (ByteDecode) for d < 12 in combination with
 * Formula 4.8 (Decompress)
 */
template <size_t d>
   requires(d < 12)
void poly_decode_and_decompress(KyberPoly& p, BufferSlicer& bs) {
   CRYSTALS::unpack<(1 << d) - 1>(p, bs, decompress<d>);
}

/**
 * NIST FIPS 203, Algorithm 6 (ByteDecode) for d == 12
 */
void byte_decode(KyberPolyNTT& p, BufferSlicer& bs) {
   CRYSTALS::unpack<KyberConstants::Q - 1>(p, bs);

   if(!p.ct_validate_value_range(0, KyberConstants::Q - 1)) {
      throw Decoding_Error("Decoded polynomial coefficients out of range");
   }
}

/**
 * NIST FIPS 203, Algorithm 7 (SampleNTT)
 *
 * Note that this assumes that the XOF has been initialized with the correct
 * seed + two bytes of indices prior to invoking this function.
 * See sample_matrix() below.
 */
void sample_ntt_uniform(KyberPolyNTT& p, XOF& xof) {
   // A generator that returns the next coefficient sampled from the XOF. As the
   // sampling uses half-bytes, this keeps track of the additionally sampled
   // coefficient as needed.
   auto sample = [stashed_coeff = std::optional<uint16_t>{},
                  bounded_xof =
                     Bounded_XOF<KyberConstants::SAMPLE_NTT_POLY_FROM_XOF_BOUND>(xof)]() mutable -> uint16_t {
      auto lowerthan_q = [](uint32_t d) -> std::optional<uint16_t> {
         if(d < KyberConstants::Q) {
            return static_cast<uint16_t>(d);
         } else {
            return std::nullopt;
         }
      };

      if(auto stashed = std::exchange(stashed_coeff, std::nullopt)) {
         return *stashed;  // value retained from a previous invocation
      }

      while(true) {
         const auto [d1, d2] = bounded_xof.next<3>([&](const auto bytes) {
            const auto x = load_le3(bytes);
            return std::pair{lowerthan_q(x & 0x0FFF), lowerthan_q(x >> 12)};
         });

         if(d1.has_value()) {
            stashed_coeff = d2;  // keep candidate d2 for the next invocation
            return *d1;
         } else if(d2.has_value()) {
            // d1 was invalid, d2 is valid, nothing to stash
            return *d2;
         }
      }
   };

   for(auto& coeff : p) {
      coeff = sample();
   }
}

/**
 * NIST FIPS 203, Algorithm 8 (SamplePolyCBD)
 *
 * Implementations for eta = 2 and eta = 3 are provided separately as template
 * specializations below.
 */
template <KyberConstants::KyberEta eta>
void sample_poly_cbd(KyberPoly& poly, StrongSpan<const KyberSamplingRandomness> randomness);

/**
 * NIST FIPS 203, Algorithm 8 (SamplePolyCBD) for eta = 2
 */
template <>
void sample_poly_cbd<KyberConstants::KyberEta::_2>(KyberPoly& poly,
                                                   StrongSpan<const KyberSamplingRandomness> randomness) {
   BufferSlicer bs(randomness);

   for(size_t i = 0; i < poly.size() / 8; ++i) {
      const uint32_t t = Botan::load_le(bs.take<4>());

      // SWAR (SIMD within a Register) trick: calculate 16 2-bit-sums in parallel
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
 * NIST FIPS 203, Algorithm 8 (SamplePolyCBD) for eta = 3
 */
template <>
void sample_poly_cbd<KyberConstants::KyberEta::_3>(KyberPoly& poly,
                                                   StrongSpan<const KyberSamplingRandomness> randomness) {
   BufferSlicer bs(randomness);

   for(size_t i = 0; i < poly.size() / 4; ++i) {
      const uint32_t t = load_le3(bs.take<3>());

      // SWAR (SIMD within a Register) trick: calculate 8 3-bit-sums in parallel
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

/**
 * NIST FIPS 203, Algorithms 16 (ML-KEM.KeyGen_internal), and
 *                           13 (K-PKE.KeyGen)
 *
 * In contrast to the specification, the expansion of rho and sigma is inlined
 * with the actual PKE key generation. The sampling loops spelled out in
 * FIPS 203 are hidden in the sample_* functions. The keys are kept in memory
 * without serialization, which is deferred until requested.
 */
KyberInternalKeypair expand_keypair(KyberPrivateKeySeed seed, KyberConstants mode) {
   BOTAN_ARG_CHECK(seed.d.has_value(), "Cannot expand keypair without the full private seed");
   const auto& d = seed.d.value();

   CT::poison(d);
   auto [rho, sigma] = mode.symmetric_primitives().G(d, mode);
   CT::unpoison(rho);  // rho is public (seed for the public matrix A)

   // Algorithm 13 (K-PKE.KeyGen) ----------------

   auto A = Kyber_Algos::sample_matrix(rho, false /* not transposed */, mode);

   // The nonce N is handled internally by the PolynomialSampler
   Kyber_Algos::PolynomialSampler ps(sigma, mode);
   auto s = ntt(ps.sample_polynomial_vector_cbd_eta1());
   const auto e = ntt(ps.sample_polynomial_vector_cbd_eta1());

   auto t = montgomery(A * s);
   t += e;
   t.reduce();

   // End Algorithm 13 ---------------------------

   CT::unpoison_all(d, t, s);

   return {
      std::make_shared<Kyber_PublicKeyInternal>(mode, std::move(t), std::move(rho)),
      std::make_shared<Kyber_PrivateKeyInternal>(std::move(mode), std::move(s), std::move(seed)),
   };
}

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

   // FIPS 203, Section 7.3 check 1 "Ciphertext type check"
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
 * NIST FIPS 203, Algorithm 8 (SamplePolyCBD)
 *
 * The actual implementation is above. This just dispatches to the correct
 * specialization based on the eta of the chosen mode.
 */
void sample_polynomial_from_cbd(KyberPoly& poly,
                                KyberConstants::KyberEta eta,
                                const KyberSamplingRandomness& randomness) {
   switch(eta) {
      case KyberConstants::KyberEta::_2:
         return sample_poly_cbd<KyberConstants::KyberEta::_2>(poly, randomness);
      case KyberConstants::KyberEta::_3:
         return sample_poly_cbd<KyberConstants::KyberEta::_3>(poly, randomness);
   }

   BOTAN_ASSERT_UNREACHABLE();
}

}  // namespace Botan::Kyber_Algos
