/*
 * Crystals Dilithium Internal Algorithms (aka. "Auxiliary Functions")
 *
 * This implements the auxiliary functions of the Crystals Dilithium signature
 * scheme as specified in NIST FIPS 204 IPD, Chapter 8.
 *
 * Some implementations are based on the public domain reference implementation
 * by the designers (https://github.com/pq-crystals/dilithium)
 *
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024 Fabian Albert and René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/dilithium_algos.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/dilithium_symmetric_primitives.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/pqcrystals_encoding.h>
#include <botan/internal/pqcrystals_helpers.h>
#include <botan/internal/stl_util.h>

#include <utility>

namespace Botan::Dilithium_Algos {

namespace {

/**
 * Returns an all-one mask if @p x is negative, otherwise an all-zero mask.
 */
template <std::signed_integral T>
constexpr auto is_negative_mask(T x) {
   using unsigned_T = std::make_unsigned_t<T>;
   return CT::Mask<unsigned_T>::expand_top_bit(static_cast<unsigned_T>(x));
}

template <DilithiumConstants::T b>
constexpr std::make_unsigned_t<DilithiumConstants::T> map_range(DilithiumConstants::T c) {
   // NIST FIPS 204 IPD, Algorithm 11 (BitPack)
   //   c is in range [-a, b] and must be mapped to [0, a + b] as follows:
   BOTAN_DEBUG_ASSERT(b - c >= 0);
   return b - c;
}

template <DilithiumConstants::T b>
constexpr DilithiumConstants::T unmap_range(std::make_unsigned_t<DilithiumConstants::T> c) {
   // NIST FIPS 204 IPD, Algorithm 13 (BitUnpack)
   //   c is in range [0, a + b] and must be mapped to [-a, b] as follows:
   return static_cast<DilithiumConstants::T>(b - c);
}

template <DilithiumConstants::T a, DilithiumConstants::T b, CRYSTALS::crystals_trait PolyTrait, CRYSTALS::Domain D>
constexpr void poly_pack(const CRYSTALS::Polynomial<PolyTrait, D>& p, BufferStuffer& stuffer) {
   if constexpr(a == 0) {
      // If `a` is 0, we assume SimpleBitPack (Algorithm 10) where the
      // coefficients are in the range [0, b].
      CRYSTALS::pack<b>(p, stuffer);
   } else {
      // Otherwise, for BitPack (Algorithm 11), we must map the coefficients to
      // positive values as they are in the range [-a, b].
      CRYSTALS::pack<a + b>(p, stuffer, map_range<b>);
   }
}

template <DilithiumConstants::T a,
          DilithiumConstants::T b,
          CRYSTALS::byte_source ByteSourceT,
          CRYSTALS::crystals_trait PolyTrait,
          CRYSTALS::Domain D>
constexpr void poly_unpack(CRYSTALS::Polynomial<PolyTrait, D>& p, ByteSourceT& get_bytes, bool check_range = false) {
   if constexpr(a == 0) {
      // If `a` is 0, we assume SimpleBitUnpack (Algorithm 12) where the
      // coefficients are in the range [0, b].
      CRYSTALS::unpack<b>(p, get_bytes);
   } else {
      // Otherwise, BitUnpack (Algorithm  13) must map the unpacked coefficients
      // to the range [-a, b].
      CRYSTALS::unpack<a + b>(p, get_bytes, unmap_range<b>);
   }
   if(check_range && !p.ct_validate_value_range(-a, b)) {
      throw Decoding_Error("Decoded polynomial coefficients out of range");
   }
}

/**
 * NIST FIPS 204 IPD, Algorithm 10 (SimpleBitPack)
 * (for a = 2^(bitlen(q-1)-d) - 1)
 */
void poly_pack_t1(const DilithiumPoly& p, BufferStuffer& stuffer) {
   constexpr auto b = (1 << (bitlen(DilithiumConstants::Q - 1) - DilithiumConstants::D)) - 1;
   poly_pack<0, b>(p, stuffer);
}

/**
 * NIST FIPS 204 IPD, Algorithm 10 (SimpleBitPack)
 * (for a = (q-1)/(2*gamma2-1))
 */
void poly_pack_w1(const DilithiumPoly& p, BufferStuffer& stuffer, const DilithiumConstants& mode) {
   using Gamma2 = DilithiumConstants::DilithiumGamma2;
   auto calculate_b = [](auto gamma2) { return ((DilithiumConstants::Q - 1) / (2 * gamma2)) - 1; };
   switch(mode.gamma2()) {
      case Gamma2::Qminus1DevidedBy88:
         return poly_pack<0, calculate_b(Gamma2::Qminus1DevidedBy88)>(p, stuffer);
      case Gamma2::Qminus1DevidedBy32:
         return poly_pack<0, calculate_b(Gamma2::Qminus1DevidedBy32)>(p, stuffer);
   }

   BOTAN_ASSERT_UNREACHABLE();
}

/**
 * NIST FIPS 204 IPD, Algorithm 11 (BitPack)
 * (for a = -gamma1 - 1, b = gamma1)
 */
void poly_pack_gamma1(const DilithiumPoly& p, BufferStuffer& stuffer, const DilithiumConstants& mode) {
   using Gamma1 = DilithiumConstants::DilithiumGamma1;
   switch(mode.gamma1()) {
      case Gamma1::ToThe17th:
         return poly_pack<Gamma1::ToThe17th - 1, Gamma1::ToThe17th>(p, stuffer);
      case Gamma1::ToThe19th:
         return poly_pack<Gamma1::ToThe19th - 1, Gamma1::ToThe19th>(p, stuffer);
   }

   BOTAN_ASSERT_UNREACHABLE();
}

/**
 * NIST FIPS 204 IPD, Algorithm 11 (BitPack)
 * (for a = -eta, b = eta)
 */
void poly_pack_eta(const DilithiumPoly& p, BufferStuffer& stuffer, const DilithiumConstants& mode) {
   using Eta = DilithiumConstants::DilithiumEta;
   switch(mode.eta()) {
      case Eta::_2:
         return poly_pack<Eta::_2, Eta::_2>(p, stuffer);
      case Eta::_4:
         return poly_pack<Eta::_4, Eta::_4>(p, stuffer);
   }

   BOTAN_ASSERT_UNREACHABLE();
}

/**
 * NIST FIPS 204 IPD, Algorithm 11 (BitPack)
 * (for a = -2^(d-1) - 1, b = 2^(d-1))
 */
void poly_pack_t0(const DilithiumPoly& p, BufferStuffer& stuffer) {
   constexpr auto TwoToTheDminus1 = 1 << (DilithiumConstants::D - 1);
   poly_pack<TwoToTheDminus1 - 1, TwoToTheDminus1>(p, stuffer);
}

/**
 * NIST FIPS 204 IPD, Algorithm 12 (SimpleBitUnpack)
 * (for a = 2^(bitlen(q-1)-d) - 1)
 */
void poly_unpack_t1(DilithiumPoly& p, BufferSlicer& slicer) {
   constexpr auto b = (1 << (bitlen(DilithiumConstants::Q - 1) - DilithiumConstants::D)) - 1;
   poly_unpack<0, b>(p, slicer);
}

/**
 * NIST FIPS 204 IPD, Algorithm 13 (BitUnpack)
 * (for a = -gamma1 - 1, b = gamma1)
 */
template <typename ByteSourceT>
void poly_unpack_gamma1(DilithiumPoly& p, ByteSourceT& byte_source, const DilithiumConstants& mode) {
   using Gamma1 = DilithiumConstants::DilithiumGamma1;
   switch(mode.gamma1()) {
      case Gamma1::ToThe17th:
         return poly_unpack<Gamma1::ToThe17th - 1, Gamma1::ToThe17th>(p, byte_source);
      case Gamma1::ToThe19th:
         return poly_unpack<Gamma1::ToThe19th - 1, Gamma1::ToThe19th>(p, byte_source);
   }

   BOTAN_ASSERT_UNREACHABLE();
}

/**
 * NIST FIPS 204 IPD, Algorithm 13 (BitUnpack)
 * (for a = -eta, b = eta)
 */
void poly_unpack_eta(DilithiumPoly& p, BufferSlicer& slicer, const DilithiumConstants& mode, bool check_range = false) {
   using Eta = DilithiumConstants::DilithiumEta;
   switch(mode.eta()) {
      case Eta::_2:
         return poly_unpack<Eta::_2, Eta::_2>(p, slicer, check_range);
      case Eta::_4:
         return poly_unpack<Eta::_4, Eta::_4>(p, slicer, check_range);
   }

   BOTAN_ASSERT_UNREACHABLE();
}

/**
 * NIST FIPS 204 IPD, Algorithm 13 (BitUnpack)
 * (for a = -2^(d-1) - 1, b = 2^(d-1))
 */
void poly_unpack_t0(DilithiumPoly& p, BufferSlicer& slicer) {
   constexpr auto TwoToTheDminus1 = 1 << (DilithiumConstants::D - 1);
   poly_unpack<TwoToTheDminus1 - 1, TwoToTheDminus1>(p, slicer);
}

/**
 * NIST FIPS 204 IPD, Algorithm 14 (HintBitPack)
 */
void hint_pack(const DilithiumPolyVec& h, BufferStuffer& stuffer, const DilithiumConstants& mode) {
   BOTAN_ASSERT_NOMSG(h.size() == mode.k());
   BOTAN_DEBUG_ASSERT(h.ct_validate_value_range(0, 1));

   BufferStuffer bit_positions(stuffer.next(mode.omega()));
   BufferStuffer offsets(stuffer.next(mode.k()));

   uint8_t index = 0;
   for(const auto& p : h) {
      for(size_t i = 0; i < p.size(); ++i) {
         if(p[i] == 1) {
            bit_positions.append(static_cast<uint8_t>(i));
            ++index;
         }
      }
      offsets.append(index);
   }

   // Fill the remaining bit positions with zeros
   bit_positions.append(0, bit_positions.remaining_capacity());
}

/**
 * NIST FIPS 204 IPD, Algorithm 15 (HintBitUnpack)
 */
std::optional<DilithiumPolyVec> hint_unpack(BufferSlicer& slicer, const DilithiumConstants& mode) {
   BufferSlicer bit_positions(slicer.take(mode.omega()));
   BufferSlicer offsets(slicer.take(mode.k()));

   DilithiumPolyVec hint(mode.k());
   uint8_t index = 0;
   for(auto& p : hint) {
      const auto end_index = offsets.take_byte();

      // Check the bounds of the end index for this polynomial
      if(end_index < index || end_index > mode.omega()) {
         return std::nullopt;
      }

      const auto set_bits = bit_positions.take(end_index - index);

      // Check that the set bit positions are ordered (strong unforgeability)
      // TODO: explicitly add a test for this, Whycheproof perhaps?
      for(size_t i = 1; i < set_bits.size(); ++i) {
         if(set_bits[i] <= set_bits[i - 1]) {
            return std::nullopt;
         }
      }

      // Set the specified bits in the polynomial
      for(const auto i : set_bits) {
         p[i] = 1;
      }

      index = end_index;
   }

   // Check that the remaining bit positions are all zero (strong unforgeability)
   const auto remaining = bit_positions.take(bit_positions.remaining());
   if(!std::all_of(remaining.begin(), remaining.end(), [](auto b) { return b == 0; })) {
      return std::nullopt;
   }

   BOTAN_DEBUG_ASSERT(hint.ct_validate_value_range(0, 1));
   return hint;
}

}  // namespace

/**
 * NIST FIPS 204 IPD, Algorithm 16 (pkEncode)
 */
DilithiumSerializedPublicKey encode_public_key(StrongSpan<const DilithiumSeedRho> rho,
                                               const DilithiumPolyVec& t1,
                                               const DilithiumConstants& mode) {
   DilithiumSerializedPublicKey pk(mode.public_key_bytes());
   BufferStuffer stuffer(pk);

   stuffer.append(rho);
   for(const auto& p : t1) {
      poly_pack_t1(p, stuffer);
   }

   BOTAN_ASSERT_NOMSG(stuffer.full());
   return pk;
}

/**
 * NIST FIPS 204 IPD, Algorithm 17 (pkDecode)
 */
std::pair<DilithiumSeedRho, DilithiumPolyVec> decode_public_key(StrongSpan<const DilithiumSerializedPublicKey> pk,
                                                                const DilithiumConstants& mode) {
   if(pk.size() != mode.public_key_bytes()) {
      throw Decoding_Error("Dilithium: Invalid public key length");
   }

   BufferSlicer slicer(pk);
   auto rho = slicer.copy<DilithiumSeedRho>(DilithiumConstants::SEED_RHO_BYTES);

   DilithiumPolyVec t1(mode.k());
   for(auto& p : t1) {
      poly_unpack_t1(p, slicer);
   }
   BOTAN_ASSERT_NOMSG(slicer.empty());

   return {std::move(rho), std::move(t1)};
}

/**
 * NIST FIPS 204 IPD, Algorithm 18 (skEncode)
 */
DilithiumSerializedPrivateKey encode_private_key(StrongSpan<const DilithiumSeedRho> rho,
                                                 StrongSpan<const DilithiumHashedPublicKey> tr,
                                                 StrongSpan<const DilithiumSigningSeedK> key,
                                                 const DilithiumPolyVec& s1,
                                                 const DilithiumPolyVec& s2,
                                                 const DilithiumPolyVec& t0,
                                                 const DilithiumConstants& mode) {
   DilithiumSerializedPrivateKey sk(mode.private_key_bytes());
   BufferStuffer stuffer(sk);

   stuffer.append(rho);
   stuffer.append(key);
   stuffer.append(tr);

   for(const auto& p : s1) {
      poly_pack_eta(p, stuffer, mode);
   }

   for(const auto& p : s2) {
      poly_pack_eta(p, stuffer, mode);
   }

   for(const auto& p : t0) {
      poly_pack_t0(p, stuffer);
   }

   BOTAN_ASSERT_NOMSG(stuffer.full());
   return sk;
}

/**
 * NIST FIPS 204 IPD, Algorithm 19 (skDecode)
 */
std::tuple<DilithiumSeedRho,
           DilithiumSigningSeedK,
           DilithiumHashedPublicKey,
           DilithiumPolyVec,
           DilithiumPolyVec,
           DilithiumPolyVec>
decode_private_key(StrongSpan<const DilithiumSerializedPrivateKey> sk, const DilithiumConstants& mode) {
   if(sk.size() != mode.private_key_bytes()) {
      throw Decoding_Error("Dilithium: Invalid private key length");
   }

   BufferSlicer slicer(sk);

   auto rho = slicer.copy<DilithiumSeedRho>(DilithiumConstants::SEED_RHO_BYTES);
   auto key = slicer.copy<DilithiumSigningSeedK>(DilithiumConstants::SEED_SIGNING_KEY_BYTES);
   auto tr = slicer.copy<DilithiumHashedPublicKey>(DilithiumConstants::PUBLIC_KEY_HASH_BYTES);

   DilithiumPolyVec s1(mode.l());
   for(auto& p : s1) {
      poly_unpack_eta(p, slicer, mode, true /* check decoded value range */);
   }

   DilithiumPolyVec s2(mode.k());
   for(auto& p : s2) {
      poly_unpack_eta(p, slicer, mode, true /* check decoded value range */);
   }

   DilithiumPolyVec t0(mode.k());
   for(auto& p : t0) {
      poly_unpack_t0(p, slicer);
   }

   BOTAN_ASSERT_NOMSG(slicer.empty());
   return {std::move(rho), std::move(key), std::move(tr), std::move(s1), std::move(s2), std::move(t0)};
}

/**
 * NIST FIPS 204 IPD, Algorithm 20 (sigEncode)
 */
DilithiumSerializedSignature encode_signature(StrongSpan<const DilithiumCommitmentHash> c,
                                              const DilithiumPolyVec& response,
                                              const DilithiumPolyVec& hint,
                                              const DilithiumConstants& mode) {
   DilithiumSerializedSignature sig(mode.signature_bytes());
   BufferStuffer stuffer(sig);

   stuffer.append(c);
   for(const auto& p : response) {
      poly_pack_gamma1(p, stuffer, mode);
   }
   hint_pack(hint, stuffer, mode);

   return sig;
}

/**
 * NIST FIPS 204 IPD, Algorithm 21 (sigDecode)
 */
std::optional<std::tuple<DilithiumCommitmentHash, DilithiumPolyVec, DilithiumPolyVec>> decode_signature(
   StrongSpan<const DilithiumSerializedSignature> sig, const DilithiumConstants& mode) {
   BufferSlicer slicer(sig);
   BOTAN_ASSERT_NOMSG(slicer.remaining() == mode.signature_bytes());

   auto commitment_hash = slicer.copy<DilithiumCommitmentHash>(DilithiumConstants::COMMITMENT_HASH_C1_BYTES);

   DilithiumPolyVec response(mode.l());
   for(auto& p : response) {
      poly_unpack_gamma1(p, slicer, mode);
   }
   BOTAN_ASSERT_NOMSG(slicer.remaining() == mode.omega() + mode.k());

   auto hint = hint_unpack(slicer, mode);
   BOTAN_ASSERT_NOMSG(slicer.empty());
   if(!hint.has_value()) {
      return std::nullopt;
   }

   return std::make_tuple(std::move(commitment_hash), std::move(response), std::move(hint.value()));
}

/**
 * NIST FIPS 204 IPD, Algorithm 22 (w1Encode)
 */
DilithiumSerializedCommitment encode_commitment(const DilithiumPolyVec& w1, const DilithiumConstants& mode) {
   DilithiumSerializedCommitment commitment(mode.serialized_commitment_bytes());
   BufferStuffer stuffer(commitment);

   for(const auto& p : w1) {
      poly_pack_w1(p, stuffer, mode);
   }

   return commitment;
}

/**
 * NIST FIPS 204 IPD, Algorithm 23 (SampleInBall)
 */
DilithiumPoly sample_in_ball(StrongSpan<const DilithiumCommitmentHash> seed, const DilithiumConstants& mode) {
   auto xof = mode.symmetric_primitives().H(seed);

   // This generator resembles the while loop in the spec.
   auto next_byte_lower_than = [&xof](size_t i) -> uint8_t {
      while(true) {
         if(const uint8_t b = xof.output_next_byte(); b <= i) {
            return b;
         }
      }
   };

   DilithiumPoly c;
   uint64_t signs = load_le(xof.output<8>());
   for(size_t i = c.size() - mode.tau(); i < c.size(); ++i) {
      const auto j = next_byte_lower_than(i);
      c[i] = c[j];
      c[j] = 1 - 2 * (signs & 1);
      signs >>= 1;
   }

   BOTAN_DEBUG_ASSERT(c.ct_validate_value_range(-1, 1));
   BOTAN_DEBUG_ASSERT(c.hamming_weight() == mode.tau());

   return c;
}

namespace {

/**
 * NIST FIPS 204 IPD, Algorithm 24 (RejNTTPoly)
 */
void sample_ntt_uniform(StrongSpan<const DilithiumSeedRho> rho,
                        DilithiumPolyNTT& p,
                        uint16_t nonce,
                        const DilithiumConstants& mode) {
   /**
    * A generator that returns the next coefficient sampled from the XOF,
    * according to: NIST FIPS 204 IPD, Algorithm 8 (CoeffFromThreeBytes).
    */
   auto next_coeff = [](Botan::XOF& xof) -> uint32_t {
      std::array<uint8_t, 4> bytes = {0};
      std::span<uint8_t, 3> sampling_sink_in_bytes = std::span{bytes}.first<3>();

      while(true) {
         xof.output(sampling_sink_in_bytes);
         const auto z = load_le<uint32_t>(bytes) & 0x7FFFFF;
         if(z < DilithiumConstants::Q) {
            return z;
         }
      }
   };

   auto& xof = mode.symmetric_primitives().H(rho, nonce);
   for(auto& coeff : p) {
      coeff = next_coeff(xof);
   }

   BOTAN_DEBUG_ASSERT(p.ct_validate_value_range(0, DilithiumConstants::Q - 1));
}

/**
 * NIST FIPS 204 IPD, Algorithm 25 (RejBoundedPoly)
 */
void sample_uniform_eta(StrongSpan<const DilithiumSeedRhoPrime> rhoprime,
                        DilithiumPoly& p,
                        uint16_t nonce,
                        const DilithiumConstants& mode) {
   using Eta = DilithiumConstants::DilithiumEta;

   /**
    * NIST FIPS 204 IPD, Algorithm 9 (CoeffFromHalfByte)
    */
   auto coeff_from_halfbyte = [eta = mode.eta()](uint8_t b) -> std::optional<int32_t> {
      BOTAN_DEBUG_ASSERT(b < 16);

      // We are going to perform rejection sampling on the XOF outputs.
      CT::unpoison(b);

      if(eta == Eta::_2 && b < 15) {
         b = b - (205 * b >> 10) * 5;
         return 2 - b;
      }

      if(eta == Eta::_4 && b < 9) {
         return 4 - b;
      }

      return std::nullopt;
   };

   // A generator that returns the next coefficient sampled from the XOF. As the
   // sampling uses half-bytes, this keeps track of the additionally sampled
   // coefficient as needed.
   auto next_coeff = [&, stashed_coeff = std::optional<int32_t>{}](Botan::XOF& xof) mutable -> int32_t {
      if(auto stashed = std::exchange(stashed_coeff, std::nullopt)) {
         return *stashed;
      }

      BOTAN_DEBUG_ASSERT(!stashed_coeff.has_value());
      while(true) {
         const auto b = xof.output_next_byte();
         const auto z0 = coeff_from_halfbyte(b & 0x0F);
         const auto z1 = coeff_from_halfbyte(b >> 4);

         if(z0.has_value()) {
            stashed_coeff = z1;  // keep candidate z1 for the next invocation
            return *z0;
         } else if(z1.has_value()) {
            // z0 was invalid, z1 is valid, nothing to stash
            return *z1;
         }
      }
   };

   auto& xof = mode.symmetric_primitives().H(rhoprime, nonce);
   for(auto& coeff : p) {
      coeff = next_coeff(xof);
   }

   // Rejection sampling is done. Secret polynomial can be repoisoned.
   CT::poison(p);

   BOTAN_DEBUG_ASSERT(p.ct_validate_value_range(-static_cast<int32_t>(mode.eta()), mode.eta()));
}

}  // namespace

/**
 * NIST FIPS 204 IPD, Algorithm 26 (ExpandA)
 */
DilithiumPolyMatNTT expand_A(StrongSpan<const DilithiumSeedRho> rho, const DilithiumConstants& mode) {
   DilithiumPolyMatNTT A(mode.k(), mode.l());
   for(uint8_t r = 0; r < mode.k(); ++r) {
      for(uint8_t s = 0; s < mode.l(); ++s) {
         // In FIPS 204 IPD this is denoted as IntegerToBits(s,8)||IntegerToBits(r,8)
         const uint16_t nonce = make_uint16(r, s);
         sample_ntt_uniform(rho, A[r][s], nonce, mode);
      }
   }
   return A;
}

/**
 * NIST FIPS 204 IPD, Algorithm 27 (ExpandS)
 */
std::pair<DilithiumPolyVec, DilithiumPolyVec> expand_s(StrongSpan<const DilithiumSeedRhoPrime> rhoprime,
                                                       const DilithiumConstants& mode) {
   DilithiumPolyVec s1(mode.l());
   DilithiumPolyVec s2(mode.k());

   uint16_t nonce = 0;
   for(auto& p : s1) {
      sample_uniform_eta(rhoprime, p, nonce++, mode);
   }

   for(auto& p : s2) {
      sample_uniform_eta(rhoprime, p, nonce++, mode);
   }

   return {std::move(s1), std::move(s2)};
}

/**
 * NIST FIPS 204 IPD, Algorithm 28 (ExpandMask)
 */
DilithiumPolyVec expand_mask(StrongSpan<const DilithiumSeedRhoPrime> rhoprime,
                             uint16_t nonce,
                             const DilithiumConstants& mode) {
   DilithiumPolyVec s(mode.l());
   for(auto& p : s) {
      auto& xof = mode.symmetric_primitives().H(rhoprime, nonce++);
      poly_unpack_gamma1(p, xof, mode);
   }
   return s;
}

/**
 * NIST FIPS 204 IPD, Algorithm 29 (Power2Round)
 */
std::pair<DilithiumPolyVec, DilithiumPolyVec> power2round(const DilithiumPolyVec& vec) {
   // This procedure is taken verbatim from Dilithium's reference implementation.
   auto power2round = [d = DilithiumConstants::D](int32_t r) -> std::pair<int32_t, int32_t> {
      const int32_t r1 = (r + (1 << (d - 1)) - 1) >> d;
      const int32_t r0 = r - (r1 << d);
      return {r1, r0};
   };

   auto result = std::make_pair(DilithiumPolyVec(vec.size()), DilithiumPolyVec(vec.size()));

   for(size_t i = 0; i < vec.size(); ++i) {
      for(size_t j = 0; j < vec[i].size(); ++j) {
         std::tie(result.first[i][j], result.second[i][j]) = power2round(vec[i][j]);
      }
   }

   return result;
}

namespace {

auto decompose_fn(const DilithiumConstants& mode) {
   using Gamma2 = DilithiumConstants::DilithiumGamma2;

   // This procedure is taken verbatim from Dilithium's reference implementation.
   return [gamma2 = mode.gamma2(), q = DilithiumConstants::Q](int32_t r) -> std::pair<int32_t, int32_t> {
      int32_t r1 = (r + 127) >> 7;

      switch(gamma2) {
         case Gamma2::Qminus1DevidedBy32:
            r1 = (r1 * 1025 + (1 << 21)) >> 22;
            r1 &= 15;
            break;
         case Gamma2::Qminus1DevidedBy88:
            r1 = (r1 * 11275 + (1 << 23)) >> 24;
            r1 ^= is_negative_mask(43 - r1).if_set_return(r1);
            break;
      }

      int32_t r0 = r - r1 * 2 * gamma2;
      r0 -= is_negative_mask((q - 1) / 2 - r0).if_set_return(q);

      return {r1, r0};
   };
}

}  // namespace

/**
 * NIST FIPS 204 IPD, Algorithm 30 (Decompose)
 *
 * Algorithms 31 (HighBits) and 32 (LowBits) are not implemented explicitly,
 * simply use the first (HighBits) and second (LowBits) element of the result.
 */
std::pair<DilithiumPolyVec, DilithiumPolyVec> decompose(const DilithiumPolyVec& vec, const DilithiumConstants& mode) {
   auto decompose = decompose_fn(mode);
   auto result = std::make_pair(DilithiumPolyVec(vec.size()), DilithiumPolyVec(vec.size()));

   for(size_t i = 0; i < vec.size(); ++i) {
      for(size_t j = 0; j < vec[i].size(); ++j) {
         std::tie(result.first[i][j], result.second[i][j]) = decompose(vec[i][j]);
      }
   }

   return result;
}

/**
 * NIST FIPS 204 IPD, Algorithm 33 (MakeHint)
 */
DilithiumPolyVec make_hint(const DilithiumPolyVec& z, const DilithiumPolyVec& r, const DilithiumConstants& mode) {
   BOTAN_DEBUG_ASSERT(z.size() == r.size());

   auto make_hint = [gamma2 = uint32_t(mode.gamma2()),
                     q_gamma2 = static_cast<uint32_t>(DilithiumConstants::Q) - uint32_t(mode.gamma2())](
                       int32_t c0, int32_t c1) -> CT::Choice {
      BOTAN_DEBUG_ASSERT(c0 >= 0);
      BOTAN_DEBUG_ASSERT(c1 >= 0);

      const uint32_t pc0 = static_cast<uint32_t>(c0);
      const uint32_t pc1 = static_cast<uint32_t>(c1);

      return (CT::Mask<uint32_t>::is_gt(pc0, gamma2) & CT::Mask<uint32_t>::is_lte(pc0, q_gamma2) &
              ~(CT::Mask<uint32_t>::is_equal(pc0, q_gamma2) & CT::Mask<uint32_t>::is_zero(pc1)))
         .as_choice();
   };

   DilithiumPolyVec hint(r.size());

   for(size_t i = 0; i < r.size(); ++i) {
      for(size_t j = 0; j < r[i].size(); ++j) {
         hint[i][j] = make_hint(z[i][j], r[i][j]).as_bool();
      }
   }

   BOTAN_DEBUG_ASSERT(hint.ct_validate_value_range(0, 1));

   return hint;
}

/**
 * NIST FIPS 204 IPD, Algorithm 34 (UseHint)
 */
void use_hint(DilithiumPolyVec& vec, const DilithiumPolyVec& hints, const DilithiumConstants& mode) {
   using Gamma2 = DilithiumConstants::DilithiumGamma2;

   BOTAN_DEBUG_ASSERT(hints.size() == vec.size());
   BOTAN_DEBUG_ASSERT(hints.ct_validate_value_range(0, 1));
   BOTAN_DEBUG_ASSERT(vec.ct_validate_value_range(0, DilithiumConstants::Q - 1));

   auto use_hint = [gamma2 = mode.gamma2(), decompose = decompose_fn(mode)](bool hint, int32_t r) -> int32_t {
      auto [r1, r0] = decompose(r);

      if(!hint) {
         return r1;
      }

      switch(gamma2) {
         case Gamma2::Qminus1DevidedBy32:
            BOTAN_DEBUG_ASSERT(r1 > -16 && r1 < 16);
            return (r0 > 0) ? (r1 + 1) & 15 : (r1 - 1) & 15;
         case Gamma2::Qminus1DevidedBy88:
            BOTAN_DEBUG_ASSERT(r1 > -44 && r1 < 44);
            // NOLINTNEXTLINE(*-avoid-nested-conditional-operator)
            return (r0 > 0) ? ((r1 == 43) ? 0 : r1 + 1) : ((r1 == 0) ? 43 : r1 - 1);
      }

      BOTAN_ASSERT_UNREACHABLE();
   };

   for(size_t i = 0; i < vec.size(); ++i) {
      for(size_t j = 0; j < vec[i].size(); ++j) {
         vec[i][j] = use_hint(hints[i][j], vec[i][j]);
      }
   }

   BOTAN_DEBUG_ASSERT(vec.ct_validate_value_range(0, (DilithiumConstants::Q - 1) / (2 * mode.gamma2())));
}

bool infinity_norm_within_bound(const DilithiumPolyVec& vec, size_t bound) {
   BOTAN_DEBUG_ASSERT(bound <= (DilithiumConstants::Q - 1) / 8);

   // It is ok to leak which coefficient violates the bound as the probability
   // for each coefficient is independent of secret data but we must not leak
   // the sign of the centralized representative.
   for(const auto& p : vec) {
      for(auto c : p) {
         const auto abs_c = c - is_negative_mask(c).if_set_return(2 * c);
         const bool is_within_bound = abs_c < bound;
         CT::unpoison(is_within_bound);
         if(!is_within_bound) {
            return false;
         }
      }
   }

   return true;
}

}  // namespace Botan::Dilithium_Algos
