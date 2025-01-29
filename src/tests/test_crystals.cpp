/*
 * Tests for PQ Crystals
 * (C) 2024 Jack Lloyd
 * (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "tests.h"

#if defined(BOTAN_HAS_PQCRYSTALS)
   #include <botan/hex.h>

   #include <botan/internal/fmt.h>
   #include <botan/internal/pqcrystals.h>
   #include <botan/internal/pqcrystals_encoding.h>
   #include <botan/internal/pqcrystals_helpers.h>
   #include <botan/internal/stl_util.h>

namespace Botan_Tests {

namespace {

template <std::integral T>
consteval T gcd(T x, T y) {
   return Botan::extended_euclidean_algorithm<T>(x, y).gcd;
}

template <std::integral T>
consteval T v(T x, T y) {
   return Botan::extended_euclidean_algorithm<T>(x, y).v;
}

template <std::integral T>
consteval T u(T x, T y) {
   return Botan::extended_euclidean_algorithm<T>(x, y).u;
}

Test::Result test_extended_euclidean_algorithm() {
   Test::Result res("Extended Euclidean Algorithm");

   // The wrapper template functions gcd<>(), v<>() and u<>() are workarounds
   // for an assumed bug in MSVC 19.38.33134 that does not accept the invocation
   // of the consteval function `extended_euclidean_algorithm` as a parameter to
   // `test_is_eq()`.
   //
   // The resulting error is:
   //    error C7595: 'Botan::extended_euclidean_algorithm': call to immediate function is not a constant expression
   //
   // What we'd actually want to write here:
   //    res.test_is_eq<uint32_t>("gcd(350, 294)", Botan::extended_euclidean_algorithm<uint32_t>(350, 294).gcd, 14);
   res.test_is_eq<uint32_t>("gcd(1337, 1337)", gcd<uint32_t>(1337, 1337), 1337);
   res.test_is_eq<uint32_t>("gcd(350, 294)", gcd<uint32_t>(350, 294), 14);
   res.test_is_eq<uint32_t>("gcd(294, 350)", gcd<uint32_t>(294, 350), 14);

   res.test_is_eq<uint16_t>("gcd(1337, 1337)", gcd<uint16_t>(1337, 1337), 1337);
   res.test_is_eq<uint16_t>("gcd(350, 294)", gcd<uint16_t>(350, 294), 14);
   res.test_is_eq<uint16_t>("gcd(294, 350)", gcd<uint16_t>(294, 350), 14);

   res.test_is_eq<uint16_t>("u(1337, 1337)", u<uint16_t>(1337, 1337), 0);
   res.test_is_eq<uint16_t>("v(1337, 1337)", v<uint16_t>(1337, 1337), 1);
   res.test_is_eq<uint16_t>("u(294, 350)", u<uint16_t>(294, 350), 6);

   res.test_is_eq<int16_t>("q^-1(3329) - Kyber::Q", Botan::modular_inverse<int16_t>(3329), -3327);
   res.test_is_eq<int32_t>("q^-1(8380417) - Dilithium::Q", Botan::modular_inverse<int32_t>(8380417), 58728449);

   return res;
}

// Equivalent to Kyber's constants
struct Kyberish_Constants {
      using T = int16_t;
      static constexpr T N = 256;
      static constexpr T Q = 3329;
      static constexpr T F = 3303;
      static constexpr T ROOT_OF_UNITY = 17;
      static constexpr size_t NTT_Degree = 128;
};

// Equivalent to Dilithium's constants
struct Dilithiumish_Constants {
      using T = int32_t;
      static constexpr T N = 256;
      static constexpr T Q = 8380417;
      static constexpr T F = 8347681;
      static constexpr T ROOT_OF_UNITY = 1753;
      static constexpr size_t NTT_Degree = 256;
};

template <typename ConstsT>
class Mock_Trait final : public Botan::CRYSTALS::Trait_Base<ConstsT, Mock_Trait<ConstsT>> {
   public:
      using T = typename Botan::CRYSTALS::Trait_Base<ConstsT, Mock_Trait<ConstsT>>::T;
      using T2 = typename Botan::CRYSTALS::Trait_Base<ConstsT, Mock_Trait<ConstsT>>::T2;
      constexpr static auto N = Botan::CRYSTALS::Trait_Base<ConstsT, Mock_Trait<ConstsT>>::N;

      static T montgomery_reduce_coefficient(T2) {
         throw Botan_Tests::Test_Error("montgomery reduction not implemented");
      }

      static T barrett_reduce_coefficient(T) { throw Botan_Tests::Test_Error("barrett reduction not implemented"); }

      static void ntt(std::span<T, N>) { throw Botan_Tests::Test_Error("NTT not implemented"); }

      static void inverse_ntt(std::span<T, N>) { throw Botan_Tests::Test_Error("inverse NTT not implemented"); }

      static void poly_pointwise_montgomery(std::span<T, N>, std::span<T, N>, std::span<T, N>) {
         throw Botan_Tests::Test_Error("pointwise multiplication not implemented");
      }
};

using Kyberish_Trait = Mock_Trait<Kyberish_Constants>;

using Domain = Botan::CRYSTALS::Domain;

template <Domain D>
using Kyberish_Poly = Botan::CRYSTALS::Polynomial<Kyberish_Trait, D>;

template <Domain D>
using Kyberish_PolyVec = Botan::CRYSTALS::PolynomialVector<Kyberish_Trait, D>;

std::vector<Test::Result> test_polynomial_basics() {
   return {
      CHECK("polynomial owning storage",
            [](Test::Result& res) {
               Kyberish_Poly<Domain::Normal> p;
               res.confirm("default constructed poly owns memory", p.owns_storage());
               for(auto coeff : p) {
                  res.test_is_eq<int16_t>("default constructed poly has 0 coefficients", coeff, 0);
               }

               Kyberish_Poly<Domain::NTT> p_ntt;
               res.confirm("default constructed poly owns memory (NTT)", p_ntt.owns_storage());
               for(auto coeff : p) {
                  res.test_is_eq<int16_t>("default constructed poly (NTT) has 0 coefficients", coeff, 0);
               }
            }),

      CHECK("polynomial vector managing storage",
            [](Test::Result& res) {
               Kyberish_PolyVec<Domain::Normal> polys(4);
               res.test_is_eq<size_t>("requested size", polys.size(), 4);

               for(const auto& poly : polys) {
                  res.confirm("poly embedded in vector does not own memory", !poly.owns_storage());
               }

               Kyberish_PolyVec<Domain::NTT> polys_ntt(4);
               res.test_is_eq<size_t>("requested size (NTT)", polys.size(), 4);

               for(const auto& poly : polys_ntt) {
                  res.confirm("poly (NTT) embedded in vector does not own memory", !poly.owns_storage());
               }
            }),

      CHECK("cloned polynomials always manage their storge",
            [](Test::Result& res) {
               Kyberish_Poly<Domain::Normal> p;
               auto p2 = p.clone();
               res.confirm("cloned poly owns memory", p2.owns_storage());

               Kyberish_PolyVec<Domain::Normal> pv(3);
               for(auto& poly : pv) {
                  res.require("poly in vector does not own memory", !poly.owns_storage());
                  auto pv2 = poly.clone();
                  res.confirm("cloned poly in vector owns memory", pv2.owns_storage());
               }

               auto pv2 = pv.clone();
               for(const auto& poly : pv2) {
                  res.confirm("cloned vector polynomial don't own memory", !poly.owns_storage());
               }

               Kyberish_Poly<Domain::NTT> p_ntt;
               auto p2_ntt = p_ntt.clone();
               res.confirm("cloned poly (NTT) owns memory", p2_ntt.owns_storage());

               Kyberish_PolyVec<Domain::NTT> pv_ntt(3);
               for(auto& poly : pv_ntt) {
                  res.require("poly (NTT) in vector does not own memory", !poly.owns_storage());
                  auto pv2_ntt = poly.clone();
                  res.confirm("cloned poly (NTT) in vector owns memory", pv2_ntt.owns_storage());
               }

               auto pv2_ntt = pv_ntt.clone();
               for(const auto& poly : pv2_ntt) {
                  res.confirm("cloned vector polynomial (NTT) don't own memory", !poly.owns_storage());
               }
            }),

      CHECK("hamming weight of polynomials",
            [](Test::Result& res) {
               Kyberish_Poly<Domain::Normal> p;
               res.test_is_eq<size_t>("hamming weight of 0", p.hamming_weight(), 0);

               p[0] = 1337;
               res.test_is_eq<size_t>("hamming weight of 1", p.hamming_weight(), 1);

               p[1] = 42;
               res.test_is_eq<size_t>("hamming weight of 2", p.hamming_weight(), 2);

               p[2] = 11;
               res.test_is_eq<size_t>("hamming weight of 3", p.hamming_weight(), 3);

               p[3] = 4;
               res.test_is_eq<size_t>("hamming weight of 4", p.hamming_weight(), 4);

               p[3] = 0;
               res.test_is_eq<size_t>("hamming weight of 3", p.hamming_weight(), 3);

               p[2] = 0;
               res.test_is_eq<size_t>("hamming weight of 2", p.hamming_weight(), 2);

               p[1] = 0;
               res.test_is_eq<size_t>("hamming weight of 1", p.hamming_weight(), 1);

               p[0] = 0;
               res.test_is_eq<size_t>("hamming weight of 0", p.hamming_weight(), 0);
            }),

      CHECK("hamming weight of polynomial vectors",
            [](Test::Result& res) {
               Kyberish_PolyVec<Domain::Normal> pv(3);
               res.test_is_eq<size_t>("hamming weight of 0", pv.hamming_weight(), 0);

               pv[0][0] = 1337;
               res.test_is_eq<size_t>("hamming weight of 1", pv.hamming_weight(), 1);

               pv[1][1] = 42;
               res.test_is_eq<size_t>("hamming weight of 2", pv.hamming_weight(), 2);

               pv[2][2] = 11;
               res.test_is_eq<size_t>("hamming weight of 3", pv.hamming_weight(), 3);

               pv[2][2] = 0;
               res.test_is_eq<size_t>("hamming weight of 2", pv.hamming_weight(), 2);

               pv[1][1] = 0;
               res.test_is_eq<size_t>("hamming weight of 1", pv.hamming_weight(), 1);

               pv[0][0] = 0;
               res.test_is_eq<size_t>("hamming weight of 0", pv.hamming_weight(), 0);
            }),

      CHECK("value range validation",
            [](Test::Result& res) {
               Kyberish_Poly<Domain::Normal> p;
               res.confirm("value range validation (all zero)", p.ct_validate_value_range(0, 1));

               p[0] = 1;
               p[32] = 1;
               p[172] = 1;
               res.confirm("value range validation", p.ct_validate_value_range(0, 1));

               p[11] = 2;
               res.confirm("value range validation", !p.ct_validate_value_range(0, 1));

               p[11] = -1;
               res.confirm("value range validation", !p.ct_validate_value_range(0, 1));
            }),

      CHECK("value range validation for polynomial vectors",
            [](Test::Result& res) {
               Kyberish_PolyVec<Domain::Normal> pv(3);
               res.confirm("value range validation (all zero)", pv.ct_validate_value_range(0, 1));

               pv[0][0] = 1;
               pv[1][32] = 1;
               pv[2][172] = 1;
               res.confirm("value range validation", pv.ct_validate_value_range(0, 1));

               pv[0][11] = 2;
               res.confirm("value range validation", !pv.ct_validate_value_range(0, 1));

               pv[0][11] = -1;
               res.confirm("value range validation", !pv.ct_validate_value_range(0, 1));
            }),
   };
}

namespace {

   #if defined(BOTAN_HAS_XOF)

class DeterministicXOF : public Botan::XOF {
   public:
      DeterministicXOF(std::span<const uint8_t> data) : m_data(data) {}

      std::string name() const override { return "DeterministicXOF"; }

      bool accepts_input() const override { return false; }

      std::unique_ptr<XOF> copy_state() const override { throw Botan_Tests::Test_Error("copy_state not implemented"); }

      std::unique_ptr<XOF> new_object() const override { throw Botan_Tests::Test_Error("new_object not implemented"); }

      size_t block_size() const override { return 1; }

      void start_msg(std::span<const uint8_t>, std::span<const uint8_t>) override {
         throw Botan_Tests::Test_Error("start_msg not implemented");
      }

      void add_data(std::span<const uint8_t>) override { throw Botan_Tests::Test_Error("add_data not implemented"); }

      void generate_bytes(std::span<uint8_t> output) override { m_data.copy_into(output); }

      void reset() override {}

   private:
      Botan::BufferSlicer m_data;
};

   #endif

template <Botan::CRYSTALS::crystals_trait Trait, int32_t range>
void random_encoding_roundtrips(Test::Result& res, Botan::RandomNumberGenerator& rng, size_t expected_encoding_bits) {
   using Poly = Botan::CRYSTALS::Polynomial<Trait, Domain::Normal>;
   using T = typename Trait::T;

   auto random_poly = [&rng]() -> Poly {
      Poly p;
      std::array<uint8_t, sizeof(T)> buf;
      for(auto& coeff : p) {
         rng.randomize(buf);
         coeff = static_cast<T>((Botan::load_be(buf) % (range + 1)));
      }
      return p;
   };

   const auto p = random_poly();
   std::vector<uint8_t> buffer((p.size() * expected_encoding_bits + 7) / 8);
   Botan::BufferStuffer stuffer(buffer);
   Botan::CRYSTALS::pack<range>(p, stuffer);
   res.confirm("encoded polynomial fills buffer", stuffer.full());

   Botan::BufferSlicer slicer(buffer);
   Poly p_unpacked;
   Botan::CRYSTALS::unpack<range>(p_unpacked, slicer);
   res.confirm("decoded polynomial reads all bytes", slicer.empty());

   p_unpacked -= p;
   res.test_eq("p = unpack(pack(p))", p_unpacked.hamming_weight(), 0);
}

}  // namespace

std::vector<Test::Result> test_encoding() {
   const auto threebitencoding = Botan::hex_decode(
      "88C61AD158231A6B44638D68AC118D35A2B14634D688C61AD158231A6B44638D68AC118D"
      "35A2B14634D688C61AD158231A6B44638D68AC118D35A2B14634D688C61AD158231A6B44"
      "638D68AC118D35A2B14634D688C61AD158231A6B44638D68");

   const auto eightbitencoding = Botan::hex_decode(
      "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223"
      "2425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F4041424344454647"
      "48494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B"
      "6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F"
      "909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3"
      "B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7"
      "D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFB"
      "FCFDFEFF");

   const auto tenbitencoding = Botan::hex_decode(
      "00084080010828C0800310484081051868C08107208840820928A8C0820B30C840830D38"
      "E8C0830F40084184114828C1841350484185155868C18517608841861968A8C1861B70C8"
      "41871D78E8C1871F80084288218828C2882390484289259868C28927A088428A29A8A8C2"
      "8A2BB0C8428B2DB8E8C28B2FC008438C31C828C38C33D048438D35D868C38D37E088438E"
      "39E8A8C38E3BF0C8438F3DF8E8C38F3F00094490410829C4904310494491451869C49147"
      "208944924928A9C4924B30C944934D38E9C4934F40094594514829C59453504945955558"
      "69C59557608945965968A9C5965B70C945975D78E9C5975F80094698618829C698639049"
      "4699659869C69967A089469A69A8A9C69A6BB0C9469B6DB8E9C69B6FC009479C71C829C7"
      "9C73D049479D75D869C79D77E089479E79E8A9C79E7BF0C9479F7DF8E9C79F7F");

   return {
      CHECK("encode polynomial coefficients into buffer",
            [&](Test::Result& res) {
               // value range is about 3 bits
               Kyberish_Poly<Domain::Normal> p1;
               for(size_t i = 0; i < p1.size(); ++i) {
                  p1[i] = static_cast<Kyberish_Constants::T>(i % 7);
               }

               std::vector<uint8_t> buffer1(96);
               Botan::BufferStuffer stuffer1(buffer1);
               Botan::CRYSTALS::pack<6>(p1, stuffer1);
               res.test_eq("3 bit encoding", buffer1, threebitencoding);

               // value range is exactly one byte
               Kyberish_Poly<Domain::Normal> p2;
               for(size_t i = 0; i < p2.size(); ++i) {
                  p2[i] = static_cast<Kyberish_Constants::T>(i);
               }

               std::vector<uint8_t> buffer2(256);
               Botan::BufferStuffer stuffer2(buffer2);
               Botan::CRYSTALS::pack<255>(p2, stuffer2);
               res.test_eq("8 bit encoding", buffer2, eightbitencoding);

               // value range for 10 bits, with mapping function
               std::vector<uint8_t> buffer3(p2.size() / 8 * 10 /* bits */);
               Botan::BufferStuffer stuffer3(buffer3);
               Botan::CRYSTALS::pack<512>(p2, stuffer3, [](int16_t x) -> uint16_t { return x * 2; });
               res.test_eq("10 bit encoding", buffer3, tenbitencoding);
            }),

      CHECK("decode polynomial coefficients from buffer",
            [&](Test::Result& res) {
               Kyberish_Poly<Domain::Normal> p1;
               Botan::BufferSlicer slicer1(threebitencoding);
               Botan::CRYSTALS::unpack<6>(p1, slicer1);
               res.require("read all bytes from 3-bit encoding", slicer1.empty());
               for(size_t i = 0; i < p1.size(); ++i) {
                  res.test_is_eq<int16_t>("decoded 3-bit coefficient", p1[i], i % 7);
               }

               Kyberish_Poly<Domain::Normal> p2;
               Botan::BufferSlicer slicer2(eightbitencoding);
               Botan::CRYSTALS::unpack<255>(p2, slicer2);
               res.require("read all bytes from 8-bit encoding", slicer2.empty());
               for(size_t i = 0; i < p2.size(); ++i) {
                  res.test_is_eq<size_t>("decoded 8-bit coefficient", p2[i], i);
               }

               Kyberish_Poly<Domain::Normal> p3;
               Botan::BufferSlicer slicer3(tenbitencoding);
               Botan::CRYSTALS::unpack<512>(p3, slicer3, [](uint16_t x) -> int16_t { return x / 2; });
               res.require("read all bytes from 10-bit encoding", slicer3.empty());
               for(size_t i = 0; i < p3.size(); ++i) {
                  res.test_is_eq<size_t>("decoded 10-bit coefficient with mapping", p3[i], i);
               }
            }),

      CHECK("decode polynomial coefficients from XOF",
            [&](Test::Result& res) {
   #if defined(BOTAN_HAS_XOF)
               Kyberish_Poly<Domain::Normal> p1;
               DeterministicXOF xof1(threebitencoding);
               Botan::CRYSTALS::unpack<6>(p1, xof1);
               for(size_t i = 0; i < p1.size(); ++i) {
                  res.test_is_eq<int16_t>("decoded 3-bit coefficient", p1[i], i % 7);
               }

               Kyberish_Poly<Domain::Normal> p2;
               DeterministicXOF xof2(eightbitencoding);
               Botan::CRYSTALS::unpack<255>(p2, xof2);
               for(size_t i = 0; i < p2.size(); ++i) {
                  res.test_is_eq<size_t>("decoded 8-bit coefficient", p2[i], i);
               }

               Kyberish_Poly<Domain::Normal> p3;
               DeterministicXOF xof3(tenbitencoding);
               Botan::CRYSTALS::unpack<512>(p3, xof3, [](int16_t x) -> int16_t { return x / 2; });
               for(size_t i = 0; i < p3.size(); ++i) {
                  res.test_is_eq<size_t>("decoded 10-bit coefficient with mapping", p3[i], i);
               }
   #endif
            }),

      CHECK("random encoding roundtrips (0 to x)",
            [](Test::Result& res) {
               auto rng = Test::new_rng("CRYSTALS encoding roundtrips");
               random_encoding_roundtrips<Kyberish_Trait, 3>(res, *rng, 2);
               random_encoding_roundtrips<Kyberish_Trait, 6>(res, *rng, 3);
               random_encoding_roundtrips<Kyberish_Trait, 12>(res, *rng, 4);
               random_encoding_roundtrips<Kyberish_Trait, 15>(res, *rng, 4);
               random_encoding_roundtrips<Kyberish_Trait, 31>(res, *rng, 5);
               random_encoding_roundtrips<Kyberish_Trait, 42>(res, *rng, 6);
               random_encoding_roundtrips<Kyberish_Trait, 128>(res, *rng, 8);
               random_encoding_roundtrips<Kyberish_Trait, 1337>(res, *rng, 11);
            }),

      CHECK("random encoding roundtrips (Kyber ranges)",
            [](Test::Result& res) {
               auto rng = Test::new_rng("CRYSTALS encoding roundtrips as used in kyber");
               random_encoding_roundtrips<Kyberish_Trait, 1>(res, *rng, 1);
               random_encoding_roundtrips<Kyberish_Trait, (1 << 4) - 1>(res, *rng, 4);
               random_encoding_roundtrips<Kyberish_Trait, (1 << 5) - 1>(res, *rng, 5);
               random_encoding_roundtrips<Kyberish_Trait, (1 << 10) - 1>(res, *rng, 10);
               random_encoding_roundtrips<Kyberish_Trait, (1 << 11) - 1>(res, *rng, 11);
               random_encoding_roundtrips<Kyberish_Trait, Kyberish_Constants::Q - 1>(res, *rng, 12);
            }),

      CHECK("random encoding roundtrips (Dilithium ranges)",
            [](Test::Result& res) {
               using Dilithiumish_Trait = Mock_Trait<Dilithiumish_Constants>;

               auto rng = Test::new_rng("CRYSTALS encoding roundtrips as used in kyber");
               constexpr auto t1 = 1023;
               constexpr auto gamma2_32 = 15;
               constexpr auto gamma2_88 = 43;
               constexpr auto gamma1_17 = 131072;
               constexpr auto gamma1_19 = 524288;
               constexpr auto eta2 = 2;
               constexpr auto eta4 = 4;
               constexpr auto twotothed = 4096;
               random_encoding_roundtrips<Dilithiumish_Trait, t1>(res, *rng, 10);
               random_encoding_roundtrips<Dilithiumish_Trait, gamma2_32>(res, *rng, 4);
               random_encoding_roundtrips<Dilithiumish_Trait, gamma2_88>(res, *rng, 6);
               random_encoding_roundtrips<Dilithiumish_Trait, 2 * gamma1_17 - 1>(res, *rng, 18);
               random_encoding_roundtrips<Dilithiumish_Trait, 2 * gamma1_19 - 1>(res, *rng, 20);
               random_encoding_roundtrips<Dilithiumish_Trait, 2 * eta2>(res, *rng, 3);
               random_encoding_roundtrips<Dilithiumish_Trait, 2 * eta4>(res, *rng, 4);
               random_encoding_roundtrips<Dilithiumish_Trait, 2 * twotothed - 1>(res, *rng, 13);
            }),
   };
}

class MockedXOF {
   public:
      MockedXOF() : m_counter(0) {}

      template <size_t bytes>
      auto output() {
         std::array<uint8_t, bytes> result;
         for(uint8_t& byte : result) {
            byte = static_cast<uint8_t>(m_counter++);
         }
         return result;
      }

   private:
      size_t m_counter;
};

template <size_t bound>
using Mocked_Bounded_XOF = Botan::detail::Bounded_XOF<MockedXOF, bound>;

std::vector<Test::Result> test_bounded_xof() {
   return {
      CHECK("zero bound is reached immediately",
            [](Test::Result& result) {
               Mocked_Bounded_XOF<0> xof;
               result.test_throws<Botan::Internal_Error>("output<1> throws", [&xof]() { xof.next_byte(); });
            }),

      CHECK("bounded XOF with small bound",
            [](Test::Result& result) {
               Mocked_Bounded_XOF<3> xof;
               result.test_is_eq("next_byte() returns 0", xof.next_byte(), uint8_t(0));
               result.test_is_eq("next_byte() returns 1", xof.next_byte(), uint8_t(1));
               result.test_is_eq("next_byte() returns 2", xof.next_byte(), uint8_t(2));
               result.test_throws<Botan::Internal_Error>("next_byte() throws", [&xof]() { xof.next_byte(); });
            }),

      CHECK("filter bytes",
            [](Test::Result& result) {
               auto filter = [](uint8_t byte) {
                  //test
                  return byte % 2 == 1;
               };

               Mocked_Bounded_XOF<5> xof;
               result.test_is_eq("next_byte() returns 1", xof.next_byte(filter), uint8_t(1));
               result.test_is_eq("next_byte() returns 3", xof.next_byte(filter), uint8_t(3));
               result.test_throws<Botan::Internal_Error>("next_byte() throws", [&]() { xof.next_byte(filter); });
            }),

      CHECK("map bytes",
            [](Test::Result& result) {
               auto map = [](auto bytes) { return Botan::load_be(bytes); };

               Mocked_Bounded_XOF<17> xof;
               result.test_is_eq("next returns 0x00010203", xof.next<4>(map), uint32_t(0x00010203));
               result.test_is_eq("next returns 0x04050607", xof.next<4>(map), uint32_t(0x04050607));
               result.test_is_eq("next returns 0x08090A0B", xof.next<4>(map), uint32_t(0x08090A0B));
               result.test_is_eq("next returns 0x0C0D0E0F", xof.next<4>(map), uint32_t(0x0C0D0E0F));
               result.test_throws<Botan::Internal_Error>("next() throws", [&]() { xof.next<4>(map); });
            }),

      CHECK("map and filter bytes",
            [](Test::Result& result) {
               auto map = [](std::array<uint8_t, 3> bytes) -> uint32_t { return bytes[0] + bytes[1] + bytes[2]; };
               auto filter = [](uint32_t number) { return number < 50; };

               Mocked_Bounded_XOF<17> xof;
               result.test_is_eq("next returns 3", xof.next<3>(map, filter), uint32_t(3));
               result.test_is_eq("next returns 12", xof.next<3>(map, filter), uint32_t(12));
               result.test_is_eq("next returns 21", xof.next<3>(map, filter), uint32_t(21));
               result.test_is_eq("next returns 30", xof.next<3>(map, filter), uint32_t(30));
               result.test_is_eq("next returns 39", xof.next<3>(map, filter), uint32_t(39));
               result.test_throws<Botan::Internal_Error>("next() throws", [&]() { xof.next<3>(map, filter); });
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN(
   "pubkey", "crystals", test_extended_euclidean_algorithm, test_polynomial_basics, test_encoding, test_bounded_xof);

}  // namespace Botan_Tests

#endif
