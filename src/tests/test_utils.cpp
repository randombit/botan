/*
* (C) 2015,2018,2024 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
* (C) 2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <botan/version.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/calendar.h>
#include <botan/internal/charset.h>
#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/parsing.h>
#include <botan/internal/rounding.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/target_info.h>
#include <botan/internal/version_info.h>

#include <bit>
#include <ctime>
#include <functional>

#if defined(BOTAN_HAS_CPUID)
   #include <botan/internal/cpuid.h>
#endif

#if defined(BOTAN_HAS_POLY_DBL)
   #include <botan/internal/poly_dbl.h>
#endif

#if defined(BOTAN_HAS_UUID)
   #include <botan/uuid.h>
#endif

namespace Botan_Tests {

namespace {

class Utility_Function_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_checked_add());
         results.push_back(test_checked_mul());
         results.push_back(test_checked_cast());
         results.push_back(test_round_up());
         results.push_back(test_loadstore());
         results.push_back(test_loadstore_ambiguity());
         results.push_back(test_loadstore_fallback());
         results.push_back(test_loadstore_constexpr());
         return Botan::concat(results, test_copy_out_be_le());
      }

   private:
      Test::Result test_checked_add() {
         Test::Result result("checked_add");

         const size_t large = static_cast<size_t>(-5);
         const size_t zero = 0;

         for(int si = -15; si != 15; ++si) {
            const size_t i = static_cast<size_t>(si);
            auto sum1 = Botan::checked_add<size_t>(i, zero, zero, zero, large);
            auto sum2 = Botan::checked_add<size_t>(large, zero, zero, zero, i);

            result.confirm("checked_add looks at all args", sum1 == sum2);

            if(i < 5) {
               result.test_eq("checked_add worked", sum1.value(), i + large);
            } else {
               result.confirm("checked_add did not return a result", !sum1.has_value());
            }
         }

         auto& rng = Test::rng();

         for(size_t i = 0; i != 100; ++i) {
            const uint16_t x = Botan::make_uint16(rng.next_byte(), rng.next_byte());
            const uint16_t y = Botan::make_uint16(rng.next_byte(), rng.next_byte());

            const uint32_t ref = static_cast<uint32_t>(x) + y;

            if(auto z = Botan::checked_add(x, y)) {
               result.test_int_eq("checked_add adds", z.value(), ref);
            } else {
               result.confirm("checked_add checks", (ref >> 16) > 0);
            }
         }

         return result;
      }

      Test::Result test_checked_mul() {
         Test::Result result("checked_mul");

         auto& rng = Test::rng();

         for(size_t i = 0; i != 100; ++i) {
            const uint16_t x = Botan::make_uint16(rng.next_byte(), rng.next_byte());
            const uint16_t y = Botan::make_uint16(rng.next_byte(), rng.next_byte());

            const uint32_t ref = static_cast<uint32_t>(x) * y;

            if(auto z = Botan::checked_mul(x, y)) {
               result.test_int_eq("checked_mul multiplies", z.value(), ref);
            } else {
               result.confirm("checked_mul checks", (ref >> 16) > 0);
            }
         }

         return result;
      }

      Test::Result test_checked_cast() {
         Test::Result result("checked_cast");

         const uint32_t large = static_cast<uint32_t>(-1);
         const uint32_t is_16_bits = 0x8123;
         const uint32_t is_8_bits = 0x89;

         result.test_throws("checked_cast checks", [&] { Botan::checked_cast_to<uint16_t>(large); });
         result.test_throws("checked_cast checks", [&] { Botan::checked_cast_to<uint8_t>(large); });

         result.test_int_eq("checked_cast converts", Botan::checked_cast_to<uint32_t>(large), large);
         result.test_int_eq("checked_cast converts", Botan::checked_cast_to<uint16_t>(is_16_bits), 0x8123);
         result.test_int_eq("checked_cast converts", Botan::checked_cast_to<uint8_t>(is_8_bits), 0x89);

         return result;
      }

      Test::Result test_round_up() {
         Test::Result result("Util round_up");

         // clang-format off
         const std::vector<size_t> inputs = {
            0, 1, 2, 3, 4, 9, 10, 32, 99, 100, 101, 255, 256, 1000, 10000,
            65535, 65536, 65537,
         };

         const std::vector<size_t> alignments = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 32, 50, 64, 100, 512, 521,
            1000, 1023, 1024, 1025, 10000, 65535, 65536
         };
         // clang-format on

         for(size_t i : inputs) {
            for(size_t m : alignments) {
               try {
                  const size_t z = Botan::round_up(i, m);

                  result.confirm("z % m == 0", z % m == 0);
                  result.confirm("z >= i", z >= i);
                  result.confirm("z <= i + m", z <= i + m);
               } catch(Botan::Exception& e) {
                  result.test_failure(Botan::fmt("round_up({},{})", i, m), e.what());
               }
            }
         }

         result.test_throws("Integer overflow is detected", []() { Botan::round_up(static_cast<size_t>(-1), 1024); });

         return result;
      }

      using TestInt64 = Botan::Strong<uint64_t, struct TestInt64_>;
      using TestInt32 = Botan::Strong<uint32_t, struct TestInt64_>;
      using TestVectorSink = Botan::Strong<std::vector<uint8_t>, struct TestVectorSink_>;

      enum class TestEnum64 : uint64_t {
         _1 = 0x1234567890ABCDEF,
         _2 = 0xEFCDAB9078563412,
      };

      enum class TestEnum32 : uint32_t {
         _1 = 0x12345678,
         _2 = 0x78563412,
      };

      static Test::Result test_loadstore() {
         Test::Result result("Util load/store");

         const std::vector<uint8_t> membuf = Botan::hex_decode("00112233445566778899AABBCCDDEEFF");
         const uint8_t* mem = membuf.data();

         const uint16_t in16 = 0x1234;
         const uint32_t in32 = 0xA0B0C0D0;
         const uint64_t in64 = 0xABCDEF0123456789;

         result.test_is_eq<uint8_t>(Botan::get_byte<0>(in32), 0xA0);
         result.test_is_eq<uint8_t>(Botan::get_byte<1>(in32), 0xB0);
         result.test_is_eq<uint8_t>(Botan::get_byte<2>(in32), 0xC0);
         result.test_is_eq<uint8_t>(Botan::get_byte<3>(in32), 0xD0);

         result.test_is_eq<uint16_t>(Botan::make_uint16(0xAA, 0xBB), 0xAABB);
         result.test_is_eq<uint32_t>(Botan::make_uint32(0x01, 0x02, 0x03, 0x04), 0x01020304);

         result.test_is_eq<uint16_t>(Botan::load_be<uint16_t>(mem, 0), 0x0011);
         result.test_is_eq<uint16_t>(Botan::load_be<uint16_t>(mem, 1), 0x2233);
         result.test_is_eq<uint16_t>(Botan::load_be<uint16_t>(mem, 2), 0x4455);
         result.test_is_eq<uint16_t>(Botan::load_be<uint16_t>(mem, 3), 0x6677);

         result.test_is_eq<uint16_t>(Botan::load_le<uint16_t>(mem, 0), 0x1100);
         result.test_is_eq<uint16_t>(Botan::load_le<uint16_t>(mem, 1), 0x3322);
         result.test_is_eq<uint16_t>(Botan::load_le<uint16_t>(mem, 2), 0x5544);
         result.test_is_eq<uint16_t>(Botan::load_le<uint16_t>(mem, 3), 0x7766);

         result.test_is_eq<uint32_t>(Botan::load_be<uint32_t>(mem, 0), 0x00112233);
         result.test_is_eq<uint32_t>(Botan::load_be<uint32_t>(mem, 1), 0x44556677);
         result.test_is_eq<uint32_t>(Botan::load_be<uint32_t>(mem, 2), 0x8899AABB);
         result.test_is_eq<uint32_t>(Botan::load_be<uint32_t>(mem, 3), 0xCCDDEEFF);

         result.test_is_eq<uint32_t>(Botan::load_le<uint32_t>(mem, 0), 0x33221100);
         result.test_is_eq<uint32_t>(Botan::load_le<uint32_t>(mem, 1), 0x77665544);
         result.test_is_eq<uint32_t>(Botan::load_le<uint32_t>(mem, 2), 0xBBAA9988);
         result.test_is_eq<uint32_t>(Botan::load_le<uint32_t>(mem, 3), 0xFFEEDDCC);

         result.test_is_eq<uint64_t>(Botan::load_be<uint64_t>(mem, 0), 0x0011223344556677);
         result.test_is_eq<uint64_t>(Botan::load_be<uint64_t>(mem, 1), 0x8899AABBCCDDEEFF);

         result.test_is_eq<uint64_t>(Botan::load_le<uint64_t>(mem, 0), 0x7766554433221100);
         result.test_is_eq<uint64_t>(Botan::load_le<uint64_t>(mem, 1), 0xFFEEDDCCBBAA9988);

         // Check misaligned loads:
         result.test_is_eq<uint16_t>(Botan::load_be<uint16_t>(mem + 1, 0), 0x1122);
         result.test_is_eq<uint16_t>(Botan::load_le<uint16_t>(mem + 3, 0), 0x4433);

         result.test_is_eq<uint32_t>(Botan::load_be<uint32_t>(mem + 1, 1), 0x55667788);
         result.test_is_eq<uint32_t>(Botan::load_le<uint32_t>(mem + 3, 1), 0xAA998877);

         result.test_is_eq<uint64_t>(Botan::load_be<uint64_t>(mem + 1, 0), 0x1122334455667788);
         result.test_is_eq<uint64_t>(Botan::load_le<uint64_t>(mem + 7, 0), 0xEEDDCCBBAA998877);
         result.test_is_eq<uint64_t>(Botan::load_le<uint64_t>(mem + 5, 0), 0xCCBBAA9988776655);

         uint8_t outbuf[16] = {0};

         for(size_t offset = 0; offset != 7; ++offset) {
            uint8_t* out = outbuf + offset;

            Botan::store_be(in16, out);
            result.test_is_eq<uint8_t>(out[0], 0x12);
            result.test_is_eq<uint8_t>(out[1], 0x34);

            Botan::store_le(in16, out);
            result.test_is_eq<uint8_t>(out[0], 0x34);
            result.test_is_eq<uint8_t>(out[1], 0x12);

            Botan::store_be(in32, out);
            result.test_is_eq<uint8_t>(out[0], 0xA0);
            result.test_is_eq<uint8_t>(out[1], 0xB0);
            result.test_is_eq<uint8_t>(out[2], 0xC0);
            result.test_is_eq<uint8_t>(out[3], 0xD0);

            Botan::store_le(in32, out);
            result.test_is_eq<uint8_t>(out[0], 0xD0);
            result.test_is_eq<uint8_t>(out[1], 0xC0);
            result.test_is_eq<uint8_t>(out[2], 0xB0);
            result.test_is_eq<uint8_t>(out[3], 0xA0);

            Botan::store_be(in64, out);
            result.test_is_eq<uint8_t>(out[0], 0xAB);
            result.test_is_eq<uint8_t>(out[1], 0xCD);
            result.test_is_eq<uint8_t>(out[2], 0xEF);
            result.test_is_eq<uint8_t>(out[3], 0x01);
            result.test_is_eq<uint8_t>(out[4], 0x23);
            result.test_is_eq<uint8_t>(out[5], 0x45);
            result.test_is_eq<uint8_t>(out[6], 0x67);
            result.test_is_eq<uint8_t>(out[7], 0x89);

            Botan::store_le(in64, out);
            result.test_is_eq<uint8_t>(out[0], 0x89);
            result.test_is_eq<uint8_t>(out[1], 0x67);
            result.test_is_eq<uint8_t>(out[2], 0x45);
            result.test_is_eq<uint8_t>(out[3], 0x23);
            result.test_is_eq<uint8_t>(out[4], 0x01);
            result.test_is_eq<uint8_t>(out[5], 0xEF);
            result.test_is_eq<uint8_t>(out[6], 0xCD);
            result.test_is_eq<uint8_t>(out[7], 0xAB);
         }

         std::array<uint8_t, 8> outarr;
         uint16_t i0, i1, i2, i3;
         Botan::store_be(in64, outarr);

         Botan::load_be(outarr, i0, i1, i2, i3);
         result.test_is_eq<uint16_t>(i0, 0xABCD);
         result.test_is_eq<uint16_t>(i1, 0xEF01);
         result.test_is_eq<uint16_t>(i2, 0x2345);
         result.test_is_eq<uint16_t>(i3, 0x6789);

         Botan::load_le(std::span{outarr}.first<6>(), i0, i1, i2);
         result.test_is_eq<uint16_t>(i0, 0xCDAB);
         result.test_is_eq<uint16_t>(i1, 0x01EF);
         result.test_is_eq<uint16_t>(i2, 0x4523);
         result.test_is_eq<uint16_t>(i3, 0x6789);  // remains unchanged

         Botan::store_le(in64, outarr);

         Botan::load_le(outarr, i0, i1, i2, i3);
         result.test_is_eq<uint16_t>(i0, 0x6789);
         result.test_is_eq<uint16_t>(i1, 0x2345);
         result.test_is_eq<uint16_t>(i2, 0xEF01);
         result.test_is_eq<uint16_t>(i3, 0xABCD);

         Botan::load_be(std::span{outarr}.first<6>(), i0, i1, i2);
         result.test_is_eq<uint16_t>(i0, 0x8967);
         result.test_is_eq<uint16_t>(i1, 0x4523);
         result.test_is_eq<uint16_t>(i2, 0x01EF);
         result.test_is_eq<uint16_t>(i3, 0xABCD);  // remains unchanged

         i0 = 0xAA11;
         i1 = 0xBB22;
         i2 = 0xCC33;
         i3 = 0xDD44;
         Botan::store_be(outarr, i0, i1, i2, i3);
         result.test_is_eq(outarr, {0xAA, 0x11, 0xBB, 0x22, 0xCC, 0x33, 0xDD, 0x44});
         std::vector<uint8_t> outvec(8);
         Botan::store_be(outvec, i0, i1, i2, i3);
         result.test_is_eq(outvec, Botan::hex_decode("AA11BB22CC33DD44"));

         Botan::store_le(outarr, i0, i1, i2, i3);
         result.test_is_eq(outarr, {0x11, 0xAA, 0x22, 0xBB, 0x33, 0xCC, 0x44, 0xDD});
         Botan::store_le(outvec, i0, i1, i2, i3);
         result.test_is_eq(outvec, Botan::hex_decode("11AA22BB33CC44DD"));

#if !defined(BOTAN_TERMINATE_ON_ASSERTS)
         std::vector<uint8_t> sink56bits(7);
         std::vector<uint8_t> sink72bits(9);
         result.test_throws("store_le with a buffer that is too small",
                            [&] { Botan::store_le(sink56bits, i0, i1, i2, i3); });
         result.test_throws("store_le with a buffer that is too big",
                            [&] { Botan::store_le(sink72bits, i0, i1, i2, i3); });
         result.test_throws("store_be with a buffer that is too small",
                            [&] { Botan::store_be(sink56bits, i0, i1, i2, i3); });
         result.test_throws("store_be with a buffer that is too big",
                            [&] { Botan::store_be(sink72bits, i0, i1, i2, i3); });
#endif

         // can store multiple values straight into a collection
         auto out64_array_be = Botan::store_be(i0, i1, i2, i3);
         auto out64_vec_be = Botan::store_be<std::vector<uint8_t>>(i0, i1, i2, i3);
         auto out64_strong_be = Botan::store_be<TestVectorSink>(i0, i1, i2, i3);
         result.test_is_eq(out64_array_be, {0xAA, 0x11, 0xBB, 0x22, 0xCC, 0x33, 0xDD, 0x44});
         result.test_is_eq(out64_vec_be, Botan::hex_decode("AA11BB22CC33DD44"));
         result.test_is_eq(out64_strong_be, TestVectorSink(Botan::hex_decode("AA11BB22CC33DD44")));
         auto out64_array_le = Botan::store_le(i0, i1, i2, i3);
         auto out64_vec_le = Botan::store_le<std::vector<uint8_t>>(i0, i1, i2, i3);
         auto out64_strong_le = Botan::store_le<TestVectorSink>(i0, i1, i2, i3);
         result.test_is_eq(out64_array_le, {0x11, 0xAA, 0x22, 0xBB, 0x33, 0xCC, 0x44, 0xDD});
         result.test_is_eq(out64_vec_le, Botan::hex_decode("11AA22BB33CC44DD"));
         result.test_is_eq(out64_strong_le, TestVectorSink(Botan::hex_decode("11AA22BB33CC44DD")));

         result.test_is_eq(in16, Botan::load_be(Botan::store_be(in16)));
         result.test_is_eq(in32, Botan::load_be(Botan::store_be(in32)));
         result.test_is_eq(in64, Botan::load_be(Botan::store_be(in64)));

         result.test_is_eq(in16, Botan::load_le(Botan::store_le(in16)));
         result.test_is_eq(in32, Botan::load_le(Botan::store_le(in32)));
         result.test_is_eq(in64, Botan::load_le(Botan::store_le(in64)));

         // Test that the runtime detects incompatible range sizes
#if !defined(BOTAN_TERMINATE_ON_ASSERTS)
         std::vector<uint16_t> too_big16(4);
         std::vector<uint16_t> too_small16(1);
         result.test_throws("load_le with incompatible buffers",
                            [&] { Botan::load_le(too_big16, Botan::hex_decode("BAADB00B")); });
         result.test_throws("load_le with incompatible buffers",
                            [&] { Botan::load_le(too_small16, Botan::hex_decode("BAADB00B")); });
         result.test_throws("load_be with incompatible buffers",
                            [&] { Botan::load_be(too_big16, Botan::hex_decode("BAADB00B")); });
         result.test_throws("load_be with incompatible buffers",
                            [&] { Botan::load_be(too_small16, Botan::hex_decode("BAADB00B")); });

         std::vector<uint8_t> too_big8(4);
         std::vector<uint8_t> too_small8(1);
         result.test_throws("store_le with incompatible buffers",
                            [&] { Botan::store_le(too_big8, std::array<uint16_t, 1>{}); });
         result.test_throws("store_le with incompatible buffers",
                            [&] { Botan::store_le(too_small8, std::array<uint16_t, 1>{}); });
         result.test_throws("store_be with incompatible buffers",
                            [&] { Botan::store_be(too_big8, std::array<uint16_t, 1>{}); });
         result.test_throws("store_be with incompatible buffers",
                            [&] { Botan::store_be(too_small8, std::array<uint16_t, 1>{}); });
#endif

         // Test store of entire ranges
         std::array<uint16_t, 2> in16_array = {0x0A0B, 0x0C0D};
         result.test_is_eq(Botan::store_be<std::vector<uint8_t>>(in16_array), Botan::hex_decode("0A0B0C0D"));
         result.test_is_eq(Botan::store_le<std::vector<uint8_t>>(in16_array), Botan::hex_decode("0B0A0D0C"));

         std::vector<uint16_t> in16_vector = {0x0A0B, 0x0C0D};
         result.test_is_eq(Botan::store_be<std::vector<uint8_t>>(in16_vector), Botan::hex_decode("0A0B0C0D"));
         result.test_is_eq(Botan::store_le<std::vector<uint8_t>>(in16_vector), Botan::hex_decode("0B0A0D0C"));

         std::array<uint8_t, 4> out_array;
         Botan::store_be(out_array, in16_array);
         result.test_is_eq(out_array, std::array<uint8_t, 4>{0x0A, 0x0B, 0x0C, 0x0D});
         Botan::store_le(out_array, in16_array);
         result.test_is_eq(out_array, std::array<uint8_t, 4>{0x0B, 0x0A, 0x0D, 0x0C});

         const auto be_inferred = Botan::store_be(in16_array);
         result.test_is_eq(be_inferred, std::array<uint8_t, 4>{0x0A, 0x0B, 0x0C, 0x0D});
         const auto le_inferred = Botan::store_le(in16_array);
         result.test_is_eq(le_inferred, std::array<uint8_t, 4>{0x0B, 0x0A, 0x0D, 0x0C});

         // Test load of entire ranges
         const auto in_buffer = Botan::hex_decode("AABBCCDD");
         auto out16_array_be = Botan::load_be<std::array<uint16_t, 2>>(in_buffer);
         result.test_is_eq<uint16_t>(out16_array_be[0], 0xAABB);
         result.test_is_eq<uint16_t>(out16_array_be[1], 0xCCDD);
         auto out16_vec_be = Botan::load_be<std::vector<uint16_t>>(in_buffer);
         result.test_eq_sz("be-vector has expected size", out16_vec_be.size(), 2);
         result.test_is_eq<uint16_t>(out16_vec_be[0], 0xAABB);
         result.test_is_eq<uint16_t>(out16_vec_be[1], 0xCCDD);

         auto out16_array_le = Botan::load_le<std::array<uint16_t, 2>>(in_buffer);
         result.test_is_eq<uint16_t>(out16_array_le[0], 0xBBAA);
         result.test_is_eq<uint16_t>(out16_array_le[1], 0xDDCC);
         auto out16_vec_le = Botan::load_le<Botan::secure_vector<uint16_t>>(in_buffer);
         result.test_eq_sz("le-vector has expected size", out16_vec_be.size(), 2);
         result.test_is_eq<uint16_t>(out16_vec_le[0], 0xBBAA);
         result.test_is_eq<uint16_t>(out16_vec_le[1], 0xDDCC);

         // Test loading/storing of strong type integers
         const TestInt64 in64_strong{0xABCDEF0123456789};
         const TestInt32 in32_strong{0xABCDEF01};

         result.test_is_eq(Botan::store_be<std::vector<uint8_t>>(in64_strong), Botan::hex_decode("ABCDEF0123456789"));
         result.test_is_eq(Botan::store_le<std::vector<uint8_t>>(in64_strong), Botan::hex_decode("8967452301EFCDAB"));
         result.test_is_eq(Botan::store_be<std::vector<uint8_t>>(in32_strong), Botan::hex_decode("ABCDEF01"));
         result.test_is_eq(Botan::store_le<std::vector<uint8_t>>(in32_strong), Botan::hex_decode("01EFCDAB"));

         result.test_is_eq(Botan::load_be<TestInt64>(Botan::hex_decode("ABCDEF0123456789")), in64_strong);
         result.test_is_eq(Botan::load_le<TestInt64>(Botan::hex_decode("8967452301EFCDAB")), in64_strong);
         result.test_is_eq(Botan::load_be<TestInt32>(Botan::hex_decode("ABCDEF01")), in32_strong);
         result.test_is_eq(Botan::load_le<TestInt32>(Botan::hex_decode("01EFCDAB")), in32_strong);

         std::vector<TestInt64> some_in64_strongs{TestInt64{0xABCDEF0123456789}, TestInt64{0x0123456789ABCDEF}};
         result.test_is_eq(Botan::store_be<std::vector<uint8_t>>(some_in64_strongs),
                           Botan::hex_decode("ABCDEF01234567890123456789ABCDEF"));
         result.test_is_eq(Botan::store_le<std::vector<uint8_t>>(some_in64_strongs),
                           Botan::hex_decode("8967452301EFCDABEFCDAB8967452301"));

         const auto in64_strongs_le =
            Botan::load_le<std::array<TestInt64, 2>>(Botan::hex_decode("8967452301EFCDABEFCDAB8967452301"));
         result.test_is_eq(in64_strongs_le[0], TestInt64{0xABCDEF0123456789});
         result.test_is_eq(in64_strongs_le[1], TestInt64{0x0123456789ABCDEF});

         const auto in64_strongs_be =
            Botan::load_be<std::vector<TestInt64>>(Botan::hex_decode("ABCDEF01234567890123456789ABCDEF"));
         result.test_is_eq(in64_strongs_be[0], TestInt64{0xABCDEF0123456789});
         result.test_is_eq(in64_strongs_be[1], TestInt64{0x0123456789ABCDEF});

         // Test loading/storing of enum types with different endianness
         const auto in64_enum_le = Botan::load_le<TestEnum64>(Botan::hex_decode("1234567890ABCDEF"));
         result.test_is_eq(in64_enum_le, TestEnum64::_2);
         const auto in64_enum_be = Botan::load_be<TestEnum64>(Botan::hex_decode("1234567890ABCDEF"));
         result.test_is_eq(in64_enum_be, TestEnum64::_1);
         result.test_is_eq(Botan::store_le<std::vector<uint8_t>>(TestEnum64::_1),
                           Botan::hex_decode("EFCDAB9078563412"));
         result.test_is_eq<std::array<uint8_t, 8>>(Botan::store_be(TestEnum64::_2),
                                                   {0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12});

         const auto in32_enum_le = Botan::load_le<TestEnum32>(Botan::hex_decode("78563412"));
         result.test_is_eq(in32_enum_le, TestEnum32::_1);
         const auto in32_enum_be = Botan::load_be<TestEnum32>(Botan::hex_decode("78563412"));
         result.test_is_eq(in32_enum_be, TestEnum32::_2);
         result.test_is_eq(Botan::store_le<std::vector<uint8_t>>(TestEnum32::_1), Botan::hex_decode("78563412"));
         result.test_is_eq<std::array<uint8_t, 4>>(Botan::store_be(TestEnum32::_2), {0x78, 0x56, 0x34, 0x12});

         return result;
      }

      template <std::unsigned_integral T>
      static T fb_load_be(std::array<const uint8_t, sizeof(T)> in) {
         return Botan::detail::fallback_load_any<std::endian::big, T>(in);
      }

      template <std::unsigned_integral T>
      static T fb_load_le(std::array<const uint8_t, sizeof(T)> in) {
         return Botan::detail::fallback_load_any<std::endian::little, T>(in);
      }

      template <std::unsigned_integral T>
      static decltype(auto) fb_store_be(const T in) {
         std::array<uint8_t, sizeof(T)> out;
         Botan::detail::fallback_store_any<std::endian::big, T>(in, out);
         return out;
      }

      template <std::unsigned_integral T>
      static decltype(auto) fb_store_le(const T in) {
         std::array<uint8_t, sizeof(T)> out;
         Botan::detail::fallback_store_any<std::endian::little, T>(in, out);
         return out;
      }

      template <size_t N>
      using a = std::array<uint8_t, N>;

      static Test::Result test_loadstore_ambiguity() {
         // This is a regression test for a (probable) compiler bug in Xcode 15
         // where it would fail to compile the load/store functions for size_t
         //
         // It seems that this platform defines uint64_t as "unsigned long long"
         // and size_t as "unsigned long". Both are 64-bits but the compiler
         // was unable to disambiguate the two in reverse_bytes in bswap.h

         const uint32_t in32 = 0x01234567;
         const uint64_t in64 = 0x0123456789ABCDEF;
         const size_t inszt = 0x87654321;

         Test::Result result("Util load/store ambiguity");
         const auto out_be_32 = Botan::store_be(in32);
         const auto out_le_32 = Botan::store_le(in32);
         const auto out_be_64 = Botan::store_be(in64);
         const auto out_le_64 = Botan::store_le(in64);
         const auto out_be_szt = Botan::store_be(inszt);
         const auto out_le_szt = Botan::store_le(inszt);

         result.test_is_eq<uint32_t>("be 32", Botan::load_be<uint32_t>(out_be_32), in32);
         result.test_is_eq<uint32_t>("le 32", Botan::load_le<uint32_t>(out_le_32), in32);
         result.test_is_eq<uint64_t>("be 64", Botan::load_be<uint64_t>(out_be_64), in64);
         result.test_is_eq<uint64_t>("le 64", Botan::load_le<uint64_t>(out_le_64), in64);
         result.test_is_eq<size_t>("be szt", Botan::load_be<size_t>(out_be_szt), inszt);
         result.test_is_eq<size_t>("le szt", Botan::load_le<size_t>(out_le_szt), inszt);

         return result;
      }

      static Test::Result test_loadstore_fallback() {
         // The fallback implementation is only used if we don't know the
         // endianness of the target at compile time. This makes sure that the
         // fallback implementation is correct. On all typical platforms it
         // won't be called in production.
         Test::Result result("Util load/store fallback");

         result.test_is_eq<uint16_t>("lLE 16", fb_load_le<uint16_t>({1, 2}), 0x0201);
         result.test_is_eq<uint32_t>("lLE 32", fb_load_le<uint32_t>({1, 2, 3, 4}), 0x04030201);
         result.test_is_eq<uint64_t>("lLE 64", fb_load_le<uint64_t>({1, 2, 3, 4, 5, 6, 7, 8}), 0x0807060504030201);

         result.test_is_eq<uint16_t>("lBE 16", fb_load_be<uint16_t>({1, 2}), 0x0102);
         result.test_is_eq<uint32_t>("lBE 32", fb_load_be<uint32_t>({1, 2, 3, 4}), 0x01020304);
         result.test_is_eq<uint64_t>("lBE 64", fb_load_be<uint64_t>({1, 2, 3, 4, 5, 6, 7, 8}), 0x0102030405060708);

         result.test_is_eq<a<2>>("sLE 16", fb_store_le<uint16_t>(0x0201), {1, 2});
         result.test_is_eq<a<4>>("sLE 32", fb_store_le<uint32_t>(0x04030201), {1, 2, 3, 4});
         result.test_is_eq<a<8>>("sLE 64", fb_store_le<uint64_t>(0x0807060504030201), {1, 2, 3, 4, 5, 6, 7, 8});

         result.test_is_eq<a<2>>("sBE 16", fb_store_be<uint16_t>(0x0102), {1, 2});
         result.test_is_eq<a<4>>("sBE 32", fb_store_be<uint32_t>(0x01020304), {1, 2, 3, 4});
         result.test_is_eq<a<8>>("sBE 64", fb_store_be<uint64_t>(0x0102030405060708), {1, 2, 3, 4, 5, 6, 7, 8});

         return result;
      }

      static Test::Result test_loadstore_constexpr() {
         Test::Result result("Util load/store constexpr");

         constexpr uint16_t in16 = 0x1234;
         constexpr uint32_t in32 = 0xA0B0C0D0;
         constexpr uint64_t in64 = 0xABCDEF0123456789;

         // clang-format off
         constexpr std::array<uint8_t, 16> cex_mem = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
         };
         // clang-format on

         // get_byte<> w/ 16bit
         constexpr auto cex_byte_16_0 = Botan::get_byte<0>(in16);
         result.test_is_eq<uint8_t>(cex_byte_16_0, 0x12);
         constexpr auto cex_byte_16_1 = Botan::get_byte<1>(in16);
         result.test_is_eq<uint8_t>(cex_byte_16_1, 0x34);

         // get_byte<> w/ 32bit
         constexpr auto cex_byte_32_0 = Botan::get_byte<0>(in32);
         result.test_is_eq<uint8_t>(cex_byte_32_0, 0xA0);
         constexpr auto cex_byte_32_1 = Botan::get_byte<1>(in32);
         result.test_is_eq<uint8_t>(cex_byte_32_1, 0xB0);
         constexpr auto cex_byte_32_2 = Botan::get_byte<2>(in32);
         result.test_is_eq<uint8_t>(cex_byte_32_2, 0xC0);
         constexpr auto cex_byte_32_3 = Botan::get_byte<3>(in32);
         result.test_is_eq<uint8_t>(cex_byte_32_3, 0xD0);

         // get_byte<> w/ 64bit
         constexpr auto cex_byte_64_0 = Botan::get_byte<0>(in64);
         result.test_is_eq<uint8_t>(cex_byte_64_0, 0xAB);
         constexpr auto cex_byte_64_1 = Botan::get_byte<1>(in64);
         result.test_is_eq<uint8_t>(cex_byte_64_1, 0xCD);
         constexpr auto cex_byte_64_2 = Botan::get_byte<2>(in64);
         result.test_is_eq<uint8_t>(cex_byte_64_2, 0xEF);
         constexpr auto cex_byte_64_3 = Botan::get_byte<3>(in64);
         result.test_is_eq<uint8_t>(cex_byte_64_3, 0x01);
         constexpr auto cex_byte_64_4 = Botan::get_byte<4>(in64);
         result.test_is_eq<uint8_t>(cex_byte_64_4, 0x23);
         constexpr auto cex_byte_64_5 = Botan::get_byte<5>(in64);
         result.test_is_eq<uint8_t>(cex_byte_64_5, 0x45);
         constexpr auto cex_byte_64_6 = Botan::get_byte<6>(in64);
         result.test_is_eq<uint8_t>(cex_byte_64_6, 0x67);
         constexpr auto cex_byte_64_7 = Botan::get_byte<7>(in64);
         result.test_is_eq<uint8_t>(cex_byte_64_7, 0x89);

         // make_uintXX()
         constexpr auto cex_uint16_t = Botan::make_uint16(0x12, 0x34);
         result.test_is_eq<uint16_t>(cex_uint16_t, in16);
         constexpr auto cex_uint32_t = Botan::make_uint32(0xA0, 0xB0, 0xC0, 0xD0);
         result.test_is_eq<uint32_t>(cex_uint32_t, in32);
         constexpr auto cex_uint64_t = Botan::make_uint64(0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89);
         result.test_is_eq<uint64_t>(cex_uint64_t, in64);

         // store_le/be with a single integer
         constexpr std::array<uint8_t, 2> cex_store_le16 = Botan::store_le(in16);
         result.test_is_eq(cex_store_le16, std::array<uint8_t, 2>{0x34, 0x12});
         constexpr std::array<uint8_t, 4> cex_store_le32 = Botan::store_le(in32);
         result.test_is_eq(cex_store_le32, std::array<uint8_t, 4>{0xD0, 0xC0, 0xB0, 0xA0});
         constexpr std::array<uint8_t, 8> cex_store_le64 = Botan::store_le(in64);
         result.test_is_eq(cex_store_le64, std::array<uint8_t, 8>{0x89, 0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB});

         constexpr std::array<uint8_t, 2> cex_store_be16 = Botan::store_be(in16);
         result.test_is_eq(cex_store_be16, std::array<uint8_t, 2>{0x12, 0x34});
         constexpr std::array<uint8_t, 4> cex_store_be32 = Botan::store_be(in32);
         result.test_is_eq(cex_store_be32, std::array<uint8_t, 4>{0xA0, 0xB0, 0xC0, 0xD0});
         constexpr std::array<uint8_t, 8> cex_store_be64 = Botan::store_be(in64);
         result.test_is_eq(cex_store_be64, std::array<uint8_t, 8>{0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89});

         // store_le/be with multiple integers, both as a parameter pack and a range (std::array for constexpr)
         constexpr std::array<uint8_t, 16> cex_store_le16s =
            Botan::store_le(in16, in16, in16, in16, in16, in16, in16, in16);
         constexpr std::array<uint8_t, 16> cex_store_le16s2 =
            Botan::store_le(std::array{in16, in16, in16, in16, in16, in16, in16, in16});
         result.test_is_eq(
            cex_store_le16s,
            {0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12});
         result.test_is_eq(cex_store_le16s, cex_store_le16s2);
         constexpr std::array<uint8_t, 16> cex_store_le32s = Botan::store_le(in32, in32, in32, in32);
         constexpr std::array<uint8_t, 16> cex_store_le32s2 = Botan::store_le(std::array{in32, in32, in32, in32});
         result.test_is_eq(
            cex_store_le32s,
            {0xD0, 0xC0, 0xB0, 0xA0, 0xD0, 0xC0, 0xB0, 0xA0, 0xD0, 0xC0, 0xB0, 0xA0, 0xD0, 0xC0, 0xB0, 0xA0});
         result.test_is_eq(cex_store_le32s, cex_store_le32s2);
         constexpr std::array<uint8_t, 16> cex_store_le64s = Botan::store_le(in64, in64);
         constexpr std::array<uint8_t, 16> cex_store_le64s2 = Botan::store_le(std::array{in64, in64});
         result.test_is_eq(
            cex_store_le64s,
            {0x89, 0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB});
         result.test_is_eq(cex_store_le64s, cex_store_le64s2);

         constexpr std::array<uint8_t, 16> cex_store_be16s =
            Botan::store_be(in16, in16, in16, in16, in16, in16, in16, in16);
         constexpr std::array<uint8_t, 16> cex_store_be16s2 =
            Botan::store_be(std::array{in16, in16, in16, in16, in16, in16, in16, in16});
         result.test_is_eq(
            cex_store_be16s,
            {0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34});
         result.test_is_eq(cex_store_be16s, cex_store_be16s2);
         constexpr std::array<uint8_t, 16> cex_store_be32s = Botan::store_be(in32, in32, in32, in32);
         constexpr std::array<uint8_t, 16> cex_store_be32s2 = Botan::store_be(std::array{in32, in32, in32, in32});
         result.test_is_eq(
            cex_store_be32s,
            {0xA0, 0xB0, 0xC0, 0xD0, 0xA0, 0xB0, 0xC0, 0xD0, 0xA0, 0xB0, 0xC0, 0xD0, 0xA0, 0xB0, 0xC0, 0xD0});
         result.test_is_eq(cex_store_be32s, cex_store_be32s2);
         constexpr std::array<uint8_t, 16> cex_store_be64s = Botan::store_be(in64, in64);
         constexpr std::array<uint8_t, 16> cex_store_be64s2 = Botan::store_be(std::array{in64, in64});
         result.test_is_eq(
            cex_store_be64s,
            {0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89});
         result.test_is_eq(cex_store_be64s, cex_store_be64s2);

         // load_le/be a single integer
         constexpr uint16_t cex_load_le16 = Botan::load_le<uint16_t>(cex_store_le16);
         result.test_is_eq(cex_load_le16, in16);
         constexpr uint32_t cex_load_le32 = Botan::load_le<uint32_t>(cex_store_le32);
         result.test_is_eq(cex_load_le32, in32);
         constexpr uint64_t cex_load_le64 = Botan::load_le<uint64_t>(cex_store_le64);
         result.test_is_eq(cex_load_le64, in64);

         constexpr uint16_t cex_load_be16 = Botan::load_be<uint16_t>(cex_store_be16);
         result.test_is_eq(cex_load_be16, in16);
         constexpr uint32_t cex_load_be32 = Botan::load_be<uint32_t>(cex_store_be32);
         result.test_is_eq(cex_load_be32, in32);
         constexpr uint64_t cex_load_be64 = Botan::load_be<uint64_t>(cex_store_be64);
         result.test_is_eq(cex_load_be64, in64);

         // load_le/be multiple integers into a std::array for constexpr
         constexpr auto cex_load_le16s = Botan::load_le<std::array<uint16_t, cex_mem.size() / 2>>(cex_mem);
         result.test_is_eq(cex_load_le16s, {0x1100, 0x3322, 0x5544, 0x7766, 0x9988, 0xBBAA, 0xDDCC, 0xFFEE});
         constexpr auto cex_load_le32s = Botan::load_le<std::array<uint32_t, cex_mem.size() / 4>>(cex_mem);
         result.test_is_eq(cex_load_le32s, {0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC});
         constexpr auto cex_load_le64s = Botan::load_le<std::array<uint64_t, cex_mem.size() / 8>>(cex_mem);
         result.test_is_eq(cex_load_le64s, {0x7766554433221100, 0xFFEEDDCCBBAA9988});

         constexpr auto cex_load_be16s = Botan::load_be<std::array<uint16_t, cex_mem.size() / 2>>(cex_mem);
         result.test_is_eq(cex_load_be16s, {0x0011, 0x2233, 0x4455, 0x6677, 0x8899, 0xAABB, 0xCCDD, 0xEEFF});
         constexpr auto cex_load_be32s = Botan::load_be<std::array<uint32_t, cex_mem.size() / 4>>(cex_mem);
         result.test_is_eq(cex_load_be32s, {0x00112233, 0x44556677, 0x8899AABB, 0xCCDDEEFF});
         constexpr auto cex_load_be64s = Botan::load_be<std::array<uint64_t, cex_mem.size() / 8>>(cex_mem);
         result.test_is_eq(cex_load_be64s, {0x0011223344556677, 0x8899AABBCCDDEEFF});

         return result;
      }

      static std::vector<Test::Result> test_copy_out_be_le() {
         return {
            CHECK("copy_out_be with 16bit input (word aligned)",
                  [&](auto& result) {
                     std::vector<uint8_t> out_vector(4);
                     const std::array<uint16_t, 2> in_array = {0x0A0B, 0x0C0D};
                     Botan::copy_out_be(out_vector, in_array);
                     result.test_is_eq(out_vector, Botan::hex_decode("0A0B0C0D"));
                  }),

            CHECK("copy_out_be with 16bit input (partial words)",
                  [&](auto& result) {
                     std::vector<uint8_t> out_vector(3);
                     const std::array<uint16_t, 2> in_array = {0x0A0B, 0x0C0D};
                     Botan::copy_out_be(out_vector, in_array);
                     result.test_is_eq(out_vector, Botan::hex_decode("0A0B0C"));
                  }),

            CHECK("copy_out_le with 16bit input (word aligned)",
                  [&](auto& result) {
                     std::vector<uint8_t> out_vector(4);
                     const std::array<uint16_t, 2> in_array = {0x0A0B, 0x0C0D};
                     Botan::copy_out_le(out_vector, in_array);
                     result.test_is_eq(out_vector, Botan::hex_decode("0B0A0D0C"));
                  }),

            CHECK("copy_out_le with 16bit input (partial words)",
                  [&](auto& result) {
                     std::vector<uint8_t> out_vector(3);
                     const std::array<uint16_t, 2> in_array = {0x0A0B, 0x0C0D};
                     Botan::copy_out_le(out_vector, in_array);
                     result.test_is_eq(out_vector, Botan::hex_decode("0B0A0D"));
                  }),

            CHECK("copy_out_be with 64bit input (word aligned)",
                  [&](auto& result) {
                     std::vector<uint8_t> out_vector(16);
                     const std::array<uint64_t, 2> in_array = {0x0A0B0C0D0E0F1011, 0x1213141516171819};
                     Botan::copy_out_be(out_vector, in_array);
                     result.test_is_eq(out_vector, Botan::hex_decode("0A0B0C0D0E0F10111213141516171819"));
                  }),

            CHECK("copy_out_le with 64bit input (word aligned)",
                  [&](auto& result) {
                     std::vector<uint8_t> out_vector(16);
                     const std::array<uint64_t, 2> in_array = {0x0A0B0C0D0E0F1011, 0x1213141516171819};
                     Botan::copy_out_le(out_vector, in_array);
                     result.test_is_eq(out_vector, Botan::hex_decode("11100F0E0D0C0B0A1918171615141312"));
                  }),

            CHECK("copy_out_be with 64bit input (partial words)",
                  [&](auto& result) {
                     std::vector<uint8_t> out_vector(15);
                     const std::array<uint64_t, 2> in_array = {0x0A0B0C0D0E0F1011, 0x1213141516171819};
                     Botan::copy_out_be(out_vector, in_array);
                     result.test_is_eq(out_vector, Botan::hex_decode("0A0B0C0D0E0F101112131415161718"));
                  }),

            CHECK("copy_out_le with 64bit input (partial words)",
                  [&](auto& result) {
                     std::vector<uint8_t> out_vector(15);
                     const std::array<uint64_t, 2> in_array = {0x0A0B0C0D0E0F1011, 0x1213141516171819};
                     Botan::copy_out_le(out_vector, in_array);
                     result.test_is_eq(out_vector, Botan::hex_decode("11100F0E0D0C0B0A19181716151413"));
                  }),
         };
      }
};

BOTAN_REGISTER_SMOKE_TEST("utils", "util", Utility_Function_Tests);

class BitOps_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_power_of_2());
         results.push_back(test_ctz());
         results.push_back(test_sig_bytes());
         results.push_back(test_popcount());
         results.push_back(test_reverse_bits());

         return results;
      }

   private:
      template <typename T>
      void test_ctz(Test::Result& result, T val, size_t expected) {
         result.test_eq("ctz(" + std::to_string(val) + ")", Botan::ctz<T>(val), expected);
      }

      Test::Result test_ctz() {
         Test::Result result("ctz");
         test_ctz<uint32_t>(result, 0, 32);
         test_ctz<uint32_t>(result, 1, 0);
         test_ctz<uint32_t>(result, 0x80, 7);
         test_ctz<uint32_t>(result, 0x8000000, 27);
         test_ctz<uint32_t>(result, 0x8100000, 20);
         test_ctz<uint32_t>(result, 0x80000000, 31);

         return result;
      }

      template <typename T>
      void test_sig_bytes(Test::Result& result, T val, size_t expected) {
         result.test_eq("significant_bytes(" + std::to_string(val) + ")", Botan::significant_bytes<T>(val), expected);
      }

      Test::Result test_sig_bytes() {
         Test::Result result("significant_bytes");
         test_sig_bytes<uint32_t>(result, 0, 0);
         test_sig_bytes<uint32_t>(result, 1, 1);
         test_sig_bytes<uint32_t>(result, 0x80, 1);
         test_sig_bytes<uint32_t>(result, 255, 1);
         test_sig_bytes<uint32_t>(result, 256, 2);
         test_sig_bytes<uint32_t>(result, 65535, 2);
         test_sig_bytes<uint32_t>(result, 65536, 3);
         test_sig_bytes<uint32_t>(result, 0x80000000, 4);

         test_sig_bytes<uint64_t>(result, 0, 0);
         test_sig_bytes<uint64_t>(result, 1, 1);
         test_sig_bytes<uint64_t>(result, 0x80, 1);
         test_sig_bytes<uint64_t>(result, 256, 2);
         test_sig_bytes<uint64_t>(result, 0x80000000, 4);
         test_sig_bytes<uint64_t>(result, 0x100000000, 5);

         return result;
      }

      template <typename T>
      void test_power_of_2(Test::Result& result, T val, bool expected) {
         result.test_eq("power_of_2(" + std::to_string(val) + ")", Botan::is_power_of_2<T>(val), expected);
      }

      Test::Result test_power_of_2() {
         Test::Result result("is_power_of_2");

         test_power_of_2<uint32_t>(result, 0, false);
         test_power_of_2<uint32_t>(result, 1, false);
         test_power_of_2<uint32_t>(result, 2, true);
         test_power_of_2<uint32_t>(result, 3, false);
         test_power_of_2<uint32_t>(result, 0x8000, true);
         test_power_of_2<uint32_t>(result, 0x8001, false);
         test_power_of_2<uint32_t>(result, 0x8000000, true);

         test_power_of_2<uint64_t>(result, 0, false);
         test_power_of_2<uint64_t>(result, 1, false);
         test_power_of_2<uint64_t>(result, 2, true);
         test_power_of_2<uint64_t>(result, 3, false);
         test_power_of_2<uint64_t>(result, 0x8000, true);
         test_power_of_2<uint64_t>(result, 0x8001, false);
         test_power_of_2<uint64_t>(result, 0x8000000, true);
         test_power_of_2<uint64_t>(result, 0x100000000000, true);

         return result;
      }

      template <typename T>
      auto pc(T val) -> decltype(Botan::ct_popcount(val)) {
         return Botan::ct_popcount(val);
      }

      template <typename T>
      auto random_pc(Test::Result& result) {
         auto n = Botan::load_le<T>(Test::rng().random_array<sizeof(T)>());
         result.test_is_eq<size_t>(Botan::fmt("popcount({}) == {}", n, std::popcount(n)), pc(n), std::popcount(n));
      }

      Test::Result test_popcount() {
         Test::Result result("popcount");

         result.test_is_eq<uint8_t>("popcount<uint8_t>(0)", pc<uint8_t>(0), 0);
         result.test_is_eq<uint8_t>("popcount<uint16_t>(0)", pc<uint16_t>(0), 0);
         result.test_is_eq<uint8_t>("popcount<uint32_t>(0)", pc<uint32_t>(0), 0);
         result.test_is_eq<uint8_t>("popcount<uint64_t>(0)", pc<uint64_t>(0), 0);

         result.test_is_eq<uint8_t>("popcount<uint8_t>(1)", pc<uint8_t>(1), 1);
         result.test_is_eq<uint8_t>("popcount<uint16_t>(1)", pc<uint16_t>(1), 1);
         result.test_is_eq<uint8_t>("popcount<uint32_t>(1)", pc<uint32_t>(1), 1);
         result.test_is_eq<uint8_t>("popcount<uint64_t>(1)", pc<uint64_t>(1), 1);

         result.test_is_eq<uint8_t>("popcount<uint8_t>(0xAA)", pc<uint8_t>(0xAA), 4);
         result.test_is_eq<uint8_t>("popcount<uint16_t>(0xAAAA)", pc<uint16_t>(0xAAAA), 8);
         result.test_is_eq<uint8_t>("popcount<uint32_t>(0xAAAA...)", pc<uint32_t>(0xAAAAAAAA), 16);
         result.test_is_eq<uint8_t>("popcount<uint64_t>(0xAAAA...)", pc<uint64_t>(0xAAAAAAAAAAAAAAAA), 32);

         result.test_is_eq<uint8_t>("popcount<uint8_t>(0xFF)", pc<uint8_t>(0xFF), 8);
         result.test_is_eq<uint8_t>("popcount<uint16_t>(0xFFFF)", pc<uint16_t>(0xFFFF), 16);
         result.test_is_eq<uint8_t>("popcount<uint32_t>(0xFFFF...)", pc<uint32_t>(0xFFFFFFFF), 32);
         result.test_is_eq<uint8_t>("popcount<uint64_t>(0xFFFF...)", pc<uint64_t>(0xFFFFFFFFFFFFFFFF), 64);

         random_pc<uint8_t>(result);
         random_pc<uint16_t>(result);
         random_pc<uint32_t>(result);
         random_pc<uint64_t>(result);

         return result;
      }

      Test::Result test_reverse_bits() {
         Test::Result result("reverse_bits");

         result.test_is_eq<uint8_t>("rev(0u8)", Botan::ct_reverse_bits<uint8_t>(0b00000000), 0b00000000);
         result.test_is_eq<uint8_t>("rev(1u8)", Botan::ct_reverse_bits<uint8_t>(0b01010101), 0b10101010);
         result.test_is_eq<uint8_t>("rev(2u8)", Botan::ct_reverse_bits<uint8_t>(0b01001011), 0b11010010);

         result.test_is_eq<uint16_t>(
            "rev(0u16)", Botan::ct_reverse_bits<uint16_t>(0b0000000000000000), 0b0000000000000000);
         result.test_is_eq<uint16_t>(
            "rev(1u16)", Botan::ct_reverse_bits<uint16_t>(0b0101010101010101), 0b1010101010101010);
         result.test_is_eq<uint16_t>(
            "rev(2u16)", Botan::ct_reverse_bits<uint16_t>(0b0100101101011010), 0b0101101011010010);

         result.test_is_eq<uint32_t>("rev(0u32)", Botan::ct_reverse_bits<uint32_t>(0xFFFFFFFF), 0xFFFFFFFF);
         result.test_is_eq<uint32_t>("rev(1u32)", Botan::ct_reverse_bits<uint32_t>(0x55555555), 0xAAAAAAAA);
         result.test_is_eq<uint32_t>("rev(2u32)", Botan::ct_reverse_bits<uint32_t>(0x4B6A2C1D), 0xB83456D2);

         result.test_is_eq<uint64_t>(
            "rev(0u64)", Botan::ct_reverse_bits<uint64_t>(0xF0E0D0C005040302), 0x40C020A0030B070F);
         result.test_is_eq<uint64_t>(
            "rev(1u64)", Botan::ct_reverse_bits<uint64_t>(0x5555555555555555), 0xAAAAAAAAAAAAAAAA);
         result.test_is_eq<uint64_t>(
            "rev(2u64)", Botan::ct_reverse_bits<uint64_t>(0x4B6A2C1D5E7F8A90), 0x951FE7AB83456D2);

         return result;
      }
};

BOTAN_REGISTER_TEST("utils", "bit_ops", BitOps_Tests);

#if defined(BOTAN_HAS_POLY_DBL)

class Poly_Double_Tests final : public Text_Based_Test {
   public:
      Poly_Double_Tests() : Text_Based_Test("poly_dbl.vec", "In,Out") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("Polynomial doubling");
         const std::vector<uint8_t> in = vars.get_req_bin("In");
         const std::vector<uint8_t> out = vars.get_req_bin("Out");

         std::vector<uint8_t> b = in;
         Botan::poly_double_n(b.data(), b.size());

         result.test_eq("Expected value", b, out);
         return result;
      }
};

BOTAN_REGISTER_TEST("utils", "poly_dbl", Poly_Double_Tests);

#endif

class Version_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("Versions");

         result.confirm("Version datestamp matches macro", Botan::version_datestamp() == BOTAN_VERSION_DATESTAMP);

         const char* version_cstr = Botan::version_cstr();
         std::string version_str = Botan::version_string();
         result.test_eq("Same version string", version_str, std::string(version_cstr));

         const char* sversion_cstr = Botan::short_version_cstr();
         std::string sversion_str = Botan::short_version_string();
         result.test_eq("Same short version string", sversion_str, std::string(sversion_cstr));

         const auto expected_sversion =
            Botan::fmt("{}.{}.{}", BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH);

         // May have a suffix eg 4.0.0-rc2
         result.confirm("Short version string has expected format", sversion_str.starts_with(expected_sversion));

         const std::string version_check_ok =
            Botan::runtime_version_check(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH);

         result.confirm("Correct version no warning", version_check_ok.empty());

         const std::string version_check_bad = Botan::runtime_version_check(1, 19, 42);

         const std::string expected_error =
            "Warning: linked version (" + sversion_str + ") does not match version built against (1.19.42)\n";

         result.test_eq("Expected warning text", version_check_bad, expected_error);

         return {result};
      }
};

BOTAN_REGISTER_TEST("utils", "versioning", Version_Tests);

class Date_Format_Tests final : public Text_Based_Test {
   public:
      Date_Format_Tests() : Text_Based_Test("dates.vec", "Date") {}

      static std::vector<uint32_t> parse_date(const std::string& s) {
         const std::vector<std::string> parts = Botan::split_on(s, ',');
         if(parts.size() != 6) {
            throw Test_Error("Bad date format '" + s + "'");
         }

         std::vector<uint32_t> u32s;
         u32s.reserve(parts.size());
         for(const auto& sub : parts) {
            u32s.push_back(Botan::to_u32bit(sub));
         }
         return u32s;
      }

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override {
         const std::string date_str = vars.get_req_str("Date");
         Test::Result result("Date parsing");

         const std::vector<uint32_t> d = parse_date(date_str);

         if(type == "valid" || type == "valid.not_std" || type == "valid.64_bit_time_t") {
            Botan::calendar_point c(d[0], d[1], d[2], d[3], d[4], d[5]);
            result.test_is_eq(date_str + " year", c.year(), d[0]);
            result.test_is_eq(date_str + " month", c.month(), d[1]);
            result.test_is_eq(date_str + " day", c.day(), d[2]);
            result.test_is_eq(date_str + " hour", c.hour(), d[3]);
            result.test_is_eq(date_str + " minute", c.minutes(), d[4]);
            result.test_is_eq(date_str + " second", c.seconds(), d[5]);

            if(type == "valid.not_std" ||
               (type == "valid.64_bit_time_t" && c.year() > 2037 && sizeof(std::time_t) == 4)) {
               result.test_throws("valid but out of std::timepoint range", [c]() { c.to_std_timepoint(); });
            } else {
               Botan::calendar_point c2(c.to_std_timepoint());
               result.test_is_eq(date_str + " year", c2.year(), d[0]);
               result.test_is_eq(date_str + " month", c2.month(), d[1]);
               result.test_is_eq(date_str + " day", c2.day(), d[2]);
               result.test_is_eq(date_str + " hour", c2.hour(), d[3]);
               result.test_is_eq(date_str + " minute", c2.minutes(), d[4]);
               result.test_is_eq(date_str + " second", c2.seconds(), d[5]);
            }
         } else if(type == "invalid") {
            result.test_throws("invalid date", [d]() { Botan::calendar_point c(d[0], d[1], d[2], d[3], d[4], d[5]); });
         } else {
            throw Test_Error("Unexpected header '" + type + "' in date format tests");
         }

         return result;
      }

      std::vector<Test::Result> run_final_tests() override {
         Test::Result result("calendar_point::to_string");
         Botan::calendar_point d(2008, 5, 15, 9, 30, 33);
         // desired format: <YYYY>-<MM>-<dd>T<HH>:<mm>:<ss>
         result.test_eq("calendar_point::to_string", d.to_string(), "2008-05-15T09:30:33");
         return {result};
      }
};

BOTAN_REGISTER_TEST("utils", "util_dates", Date_Format_Tests);

class Charset_Tests final : public Text_Based_Test {
   public:
      Charset_Tests() : Text_Based_Test("charset.vec", "In,Out") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override {
         Test::Result result("Charset");

         const std::vector<uint8_t> in = vars.get_req_bin("In");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");

         std::string converted;

         if(type == "UCS2-UTF8") {
            converted = Botan::ucs2_to_utf8(in.data(), in.size());
         } else if(type == "UCS4-UTF8") {
            converted = Botan::ucs4_to_utf8(in.data(), in.size());
         } else if(type == "LATIN1-UTF8") {
            converted = Botan::latin1_to_utf8(in.data(), in.size());
         } else {
            throw Test_Error("Unexpected header '" + type + "' in charset tests");
         }

         result.test_eq(
            "string converted successfully", std::vector<uint8_t>(converted.begin(), converted.end()), expected);

         return result;
      }
};

BOTAN_REGISTER_TEST("utils", "charset", Charset_Tests);

class Hostname_Tests final : public Text_Based_Test {
   public:
      Hostname_Tests() : Text_Based_Test("hostnames.vec", "Issued,Hostname") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override {
         Test::Result result("Hostname Matching");

         const std::string issued = vars.get_req_str("Issued");
         const std::string hostname = vars.get_req_str("Hostname");
         const bool expected = (type == "Invalid") ? false : true;

         const std::string what = hostname + ((expected == true) ? " matches " : " does not match ") + issued;
         result.test_eq(what, Botan::host_wildcard_match(issued, hostname), expected);

         return result;
      }
};

BOTAN_REGISTER_TEST("utils", "hostname", Hostname_Tests);

class IPv4_Parsing_Tests final : public Text_Based_Test {
   public:
      IPv4_Parsing_Tests() : Text_Based_Test("utils/ipv4.vec", "IPv4") {}

      Test::Result run_one_test(const std::string& status, const VarMap& vars) override {
         Test::Result result("IPv4 parsing");

         const std::string input = vars.get_req_str("IPv4");
         const bool valid = (status == "Valid");

         auto ipv4 = Botan::string_to_ipv4(input);

         result.test_eq("string_to_ipv4 accepts only valid", valid, ipv4.has_value());

         if(ipv4) {
            const std::string rt = Botan::ipv4_to_string(ipv4.value());
            result.test_eq("ipv4_to_string and string_to_ipv4 round trip", input, rt);
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("utils", "ipv4_parse", IPv4_Parsing_Tests);

class ReadKV_Tests final : public Text_Based_Test {
   public:
      ReadKV_Tests() : Text_Based_Test("utils/read_kv.vec", "Input,Expected") {}

      Test::Result run_one_test(const std::string& status, const VarMap& vars) override {
         Test::Result result("read_kv");

         const bool is_valid = (status == "Valid");

         const std::string input = vars.get_req_str("Input");
         const std::string expected = vars.get_req_str("Expected");

         if(is_valid) {
            confirm_kv(result, Botan::read_kv(input), split_group(expected));
         } else {
            // In this case "expected" is the expected exception message
            result.test_throws("Invalid key value input throws exception", expected, [&]() { Botan::read_kv(input); });
         }
         return result;
      }

   private:
      static std::vector<std::string> split_group(const std::string& str) {
         std::vector<std::string> elems;
         if(str.empty()) {
            return elems;
         }

         std::string substr;
         for(auto i = str.begin(); i != str.end(); ++i) {
            if(*i == '|') {
               elems.push_back(substr);
               substr.clear();
            } else {
               substr += *i;
            }
         }

         if(!substr.empty()) {
            elems.push_back(substr);
         }

         return elems;
      }

      static void confirm_kv(Test::Result& result,
                             const std::map<std::string, std::string>& kv,
                             const std::vector<std::string>& expected) {
         if(!result.test_eq("expected size", expected.size() % 2, size_t(0))) {
            return;
         }

         for(size_t i = 0; i != expected.size(); i += 2) {
            auto j = kv.find(expected[i]);
            if(result.confirm("Found key", j != kv.end())) {
               result.test_eq("Matching value", j->second, expected[i + 1]);
            }
         }

         result.test_eq("KV has same size as expected", kv.size(), expected.size() / 2);
      }
};

BOTAN_REGISTER_TEST("utils", "util_read_kv", ReadKV_Tests);

#if defined(BOTAN_HAS_CPUID)

class CPUID_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("CPUID");

         const std::string cpuid_string = Botan::CPUID::to_string();
         result.test_success("CPUID::to_string doesn't crash");

         for(size_t b = 0; b != 32; ++b) {
            try {
               const auto bit = static_cast<uint32_t>(1) << b;
               const auto feat = Botan::CPUID::Feature(static_cast<Botan::CPUID::Feature::Bit>(bit));

               const std::string feat_str = feat.to_string();

               result.confirm("Feature string is not empty", !feat_str.empty());

               if(auto from_str = Botan::CPUID::Feature::from_string(feat_str)) {
                  result.test_int_eq("Feature::from_string returns expected bit", from_str->as_u32(), bit);
               } else {
                  result.test_failure(
                     Botan::fmt("Feature::from_string didn't recognize its own output ({})", feat_str));
               }
            } catch(Botan::Invalid_State&) {
               // This will thrown if the bit is not a valid one
            }
         }

   #if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

         const auto bit = Botan::CPUID::Feature::SSE2;

         if(Botan::CPUID::has(bit)) {
            result.confirm("Output string includes sse2", cpuid_string.find("sse2") != std::string::npos);

            Botan::CPUID::clear_cpuid_bit(bit);

            result.test_eq(
               "After clearing cpuid bit, CPUID::has for SSE2 returns false", Botan::CPUID::has(bit), false);

            Botan::CPUID::initialize();  // reset state
            result.test_eq(
               "After reinitializing, CPUID::has for SSE2 returns true again", Botan::CPUID::has(bit), true);
         }
   #endif

         return {result};
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("utils", "cpuid", CPUID_Tests);

#endif

#if defined(BOTAN_HAS_UUID)

class UUID_Tests : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("UUID");

         const Botan::UUID empty_uuid;
         const Botan::UUID random_uuid1(this->rng());
         const Botan::UUID random_uuid2(this->rng());
         const Botan::UUID loaded_uuid(std::vector<uint8_t>(16, 4));

         result.test_throws("Cannot load wrong number of bytes", []() { Botan::UUID u(std::vector<uint8_t>(15)); });

         result.test_eq("Empty UUID is empty", empty_uuid.is_valid(), false);
         result.confirm("Empty UUID equals another empty UUID", empty_uuid == Botan::UUID());

         result.test_throws("Empty UUID cannot become a string", [&]() { empty_uuid.to_string(); });

         result.test_eq("Random UUID not empty", random_uuid1.is_valid(), true);
         result.test_eq("Random UUID not empty", random_uuid2.is_valid(), true);

         result.confirm("Random UUIDs are distinct", random_uuid1 != random_uuid2);
         result.confirm("Random UUIDs not equal to empty", random_uuid1 != empty_uuid);

         const std::string uuid4_str = loaded_uuid.to_string();
         result.test_eq("String matches expected", uuid4_str, "04040404-0404-0404-0404-040404040404");

         const std::string uuid_r1_str = random_uuid1.to_string();
         result.confirm("UUID from string matches", Botan::UUID(uuid_r1_str) == random_uuid1);

         class AllSame_RNG : public Botan::RandomNumberGenerator {
            public:
               explicit AllSame_RNG(uint8_t b) : m_val(b) {}

               void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> /* ignored */) override {
                  for(auto& byte : output) {
                     byte = m_val;
                  }
               }

               std::string name() const override { return "zeros"; }

               bool accepts_input() const override { return false; }

               void clear() override {}

               bool is_seeded() const override { return true; }

            private:
               uint8_t m_val;
         };

         AllSame_RNG zeros(0x00);
         const Botan::UUID zero_uuid(zeros);
         result.test_eq("Zero UUID matches expected", zero_uuid.to_string(), "00000000-0000-4000-8000-000000000000");

         AllSame_RNG ones(0xFF);
         const Botan::UUID ones_uuid(ones);
         result.test_eq("Ones UUID matches expected", ones_uuid.to_string(), "FFFFFFFF-FFFF-4FFF-BFFF-FFFFFFFFFFFF");

         return {result};
      }
};

BOTAN_REGISTER_TEST("utils", "uuid", UUID_Tests);

#endif

class Formatter_Tests : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("Format utility");

         /*
         In a number of these tests, we are not strictly depending on the
         behavior, for instance checking `fmt("{}") == "{}"` is more about
         checking that we don't crash, rather than we return that precise string.
         */

         result.test_eq("test 1", Botan::fmt("hi"), "hi");
         result.test_eq("test 2", Botan::fmt("ignored", 5), "ignored");
         result.test_eq("test 3", Botan::fmt("answer is {}", 42), "answer is 42");
         result.test_eq("test 4", Botan::fmt("{", 5), "{");
         result.test_eq("test 4", Botan::fmt("{}"), "{}");
         result.test_eq("test 5", Botan::fmt("{} == '{}'", 5, "five"), "5 == 'five'");

         return {result};
      }
};

BOTAN_REGISTER_TEST("utils", "fmt", Formatter_Tests);

class ScopedCleanup_Tests : public Test {
   public:
      std::vector<Test::Result> run() override {
         return {
            CHECK("leaving a scope results in cleanup",
                  [](Test::Result& result) {
                     bool ran = false;
                     {
                        auto clean = Botan::scoped_cleanup([&] { ran = true; });
                     }
                     result.confirm("cleanup ran", ran);
                  }),

            CHECK("leaving a function, results in cleanup",
                  [](Test::Result& result) {
                     bool ran = false;
                     bool fn_called = false;
                     auto fn = [&] {
                        auto clean = Botan::scoped_cleanup([&] { ran = true; });
                        fn_called = true;
                     };

                     result.confirm("cleanup not yet ran", !ran);
                     fn();
                     result.confirm("fn called", fn_called);
                     result.confirm("cleanup ran", ran);
                  }),

            CHECK("stack unwinding results in cleanup",
                  [](Test::Result& result) {
                     bool ran = false;
                     bool fn_called = false;
                     bool exception_caught = false;
                     auto fn = [&] {
                        auto clean = Botan::scoped_cleanup([&] { ran = true; });
                        fn_called = true;
                        throw std::runtime_error("test");
                     };

                     result.confirm("cleanup not yet ran", !ran);
                     try {
                        fn();
                     } catch(const std::exception&) {
                        exception_caught = true;
                     }

                     result.confirm("fn called", fn_called);
                     result.confirm("cleanup ran", ran);
                     result.confirm("exception caught", exception_caught);
                  }),

            CHECK("cleanup isn't called after disengaging",
                  [](Test::Result& result) {
                     bool ran = false;
                     {
                        auto clean = Botan::scoped_cleanup([&] { ran = true; });
                        clean.disengage();
                     }
                     result.confirm("cleanup not ran", !ran);
                  }),

         };
      }
};

BOTAN_REGISTER_TEST("utils", "scoped_cleanup", ScopedCleanup_Tests);

}  // namespace

}  // namespace Botan_Tests
