/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/hex.h>
#include <botan/internal/bswap.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/isa_extn.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>

#if defined(BOTAN_HAS_SIMD_4X32)
   #include <botan/internal/simd_4x32.h>
#endif

#if defined(BOTAN_HAS_SIMD_2X64)
   #include <botan/internal/simd_2x64.h>
#endif

#if defined(BOTAN_HAS_SIMD_8X32)
   #include <botan/internal/simd_8x32.h>
#endif

#if defined(BOTAN_HAS_CPUID)
   #include <botan/internal/cpuid.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_SIMD_4X32) && defined(BOTAN_HAS_CPUID)

class SIMD_4X32_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         if(!Botan::CPUID::has(Botan::CPUID::Feature::SIMD_4X32)) {
            return {Test::Result::Note("simd_4x32", "Skipping tests due to missing SIMD support at runtime")};
         } else {
            return {test_simd_4x32()};
         }
      }

   private:
      Test::Result BOTAN_FN_ISA_SIMD_4X32 test_simd_4x32() {
         Test::Result result("SIMD_4x32");

         const uint32_t pat1 = 0xAABBCCDD;
         const uint32_t pat2 = 0x87654321;
         const uint32_t pat3 = 0x01234567;
         const uint32_t pat4 = 0xC0D0E0F0;

         // pat1 + pat{1,2,3,4}
         // precomputed to avoid integer overflow warnings
         const uint32_t pat1_1 = 0x557799BA;
         const uint32_t pat1_2 = 0x32210FFE;
         const uint32_t pat1_3 = 0xABDF1244;
         const uint32_t pat1_4 = 0x6B8CADCD;

         test_eq(result, "default init", Botan::SIMD_4x32(), 0, 0, 0, 0);
         test_eq(result, "SIMD scalar constructor", Botan::SIMD_4x32(1, 2, 3, 4), 1, 2, 3, 4);

         const Botan::SIMD_4x32 splat = Botan::SIMD_4x32::splat(pat1);

         test_eq(result, "splat", splat, pat1, pat1, pat1, pat1);

         const Botan::SIMD_4x32 input(pat1, pat2, pat3, pat4);

         result.test_u32_eq("SIMD_4x32::extract_word<0>", input.extract_word<0>(), pat1);
         result.test_u32_eq("SIMD_4x32::extract_word<1>", input.extract_word<1>(), pat2);
         result.test_u32_eq("SIMD_4x32::extract_word<2>", input.extract_word<2>(), pat3);
         result.test_u32_eq("SIMD_4x32::extract_word<3>", input.extract_word<3>(), pat4);

         const Botan::SIMD_4x32 rol = input.rotl<3>();

         test_eq(result,
                 "rotl",
                 rol,
                 Botan::rotl<3>(pat1),
                 Botan::rotl<3>(pat2),
                 Botan::rotl<3>(pat3),
                 Botan::rotl<3>(pat4));

         const Botan::SIMD_4x32 ror = input.rotr<9>();

         test_eq(result,
                 "rotr",
                 ror,
                 Botan::rotr<9>(pat1),
                 Botan::rotr<9>(pat2),
                 Botan::rotr<9>(pat3),
                 Botan::rotr<9>(pat4));

         Botan::SIMD_4x32 add = input + splat;
         test_eq(result, "add +", add, pat1_1, pat1_2, pat1_3, pat1_4);

         add -= splat;
         test_eq(result, "sub -=", add, pat1, pat2, pat3, pat4);

         add += splat;
         test_eq(result, "add +=", add, pat1_1, pat1_2, pat1_3, pat1_4);

         test_eq(result, "xor", input ^ splat, 0, pat2 ^ pat1, pat3 ^ pat1, pat4 ^ pat1);
         test_eq(result, "or", input | splat, pat1, pat2 | pat1, pat3 | pat1, pat4 | pat1);
         test_eq(result, "and", input & splat, pat1, pat2 & pat1, pat3 & pat1, pat4 & pat1);

         Botan::SIMD_4x32 blender = input;
         blender |= splat;
         test_eq(result, "|=", blender, pat1, pat2 | pat1, pat3 | pat1, pat4 | pat1);
         blender &= splat;
         test_eq(result, "&=", blender, pat1, pat1, pat1, pat1);
         blender ^= splat;
         test_eq(result, "^=", blender, 0, 0, 0, 0);

         blender = ~blender;
         test_eq(result, "~", blender, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF);

         blender = blender.shr<23>();
         test_eq(result, ">>", blender, 0x1FF, 0x1FF, 0x1FF, 0x1FF);

         blender = blender.shl<27>();
         test_eq(result, "<<", blender, 0xF8000000, 0xF8000000, 0xF8000000, 0xF8000000);

         blender = ~blender;
         test_eq(result, "~", blender, 0x7FFFFFF, 0x7FFFFFF, 0x7FFFFFF, 0x7FFFFFF);

         blender = input.andc(~blender);
         test_eq(
            result, "andc", blender, ~pat1 & 0xF8000000, ~pat2 & 0xF8000000, ~pat3 & 0xF8000000, ~pat4 & 0xF8000000);

         test_eq(result,
                 "bswap",
                 input.bswap(),
                 Botan::reverse_bytes(pat1),
                 Botan::reverse_bytes(pat2),
                 Botan::reverse_bytes(pat3),
                 Botan::reverse_bytes(pat4));

         Botan::SIMD_4x32 t1(pat1, pat2, pat3, pat4);
         Botan::SIMD_4x32 t2(pat1 + 1, pat2 + 1, pat3 + 1, pat4 + 1);
         Botan::SIMD_4x32 t3(pat1 + 2, pat2 + 2, pat3 + 2, pat4 + 2);
         Botan::SIMD_4x32 t4(pat1 + 3, pat2 + 3, pat3 + 3, pat4 + 3);

         Botan::SIMD_4x32::transpose(t1, t2, t3, t4);

         test_eq(result, "transpose t1", t1, pat1, pat1 + 1, pat1 + 2, pat1 + 3);
         test_eq(result, "transpose t2", t2, pat2, pat2 + 1, pat2 + 2, pat2 + 3);
         test_eq(result, "transpose t3", t3, pat3, pat3 + 1, pat3 + 2, pat3 + 3);
         test_eq(result, "transpose t4", t4, pat4, pat4 + 1, pat4 + 2, pat4 + 3);

         test_eq(result, "shift left 1", input.shift_elems_left<1>(), 0, pat1, pat2, pat3);
         test_eq(result, "shift left 2", input.shift_elems_left<2>(), 0, 0, pat1, pat2);
         test_eq(result, "shift left 3", input.shift_elems_left<3>(), 0, 0, 0, pat1);

         test_eq(result, "shift right 1", input.shift_elems_right<1>(), pat2, pat3, pat4, 0);
         test_eq(result, "shift right 2", input.shift_elems_right<2>(), pat3, pat4, 0, 0);
         test_eq(result, "shift right 3", input.shift_elems_right<3>(), pat4, 0, 0, 0);

         // Test load/stores SIMD wrapper types
         const auto simd_le_in = Botan::hex_decode("ABCDEF01234567890123456789ABCDEF");
         const auto simd_be_in = Botan::hex_decode("0123456789ABCDEFABCDEF0123456789");
         const auto simd_le_array_in = Botan::concat(simd_le_in, simd_be_in);
         const auto simd_be_array_in = Botan::concat(simd_be_in, simd_le_in);

         auto simd_le = Botan::load_le<Botan::SIMD_4x32>(simd_le_in);
         auto simd_be = Botan::load_be<Botan::SIMD_4x32>(simd_be_in);
         auto simd_le_array = Botan::load_le<std::array<Botan::SIMD_4x32, 2>>(simd_le_array_in);
         auto simd_be_array = Botan::load_be<std::array<Botan::SIMD_4x32, 2>>(simd_be_array_in);

         auto simd_le_vec = Botan::store_le<std::vector<uint8_t>>(simd_le);
         auto simd_be_vec = Botan::store_be(simd_be);
         auto simd_le_array_vec = Botan::store_le<std::vector<uint8_t>>(simd_le_array);
         auto simd_be_array_vec = Botan::store_be(simd_be_array);

         result.test_bin_eq("roundtrip SIMD little-endian", simd_le_vec, simd_le_in);
         result.test_bin_eq(
            "roundtrip SIMD big-endian", std::vector(simd_be_vec.begin(), simd_be_vec.end()), simd_be_in);
         result.test_bin_eq("roundtrip SIMD array little-endian", simd_le_array_vec, simd_le_array_in);
         result.test_bin_eq("roundtrip SIMD array big-endian",
                            std::vector(simd_be_array_vec.begin(), simd_be_array_vec.end()),
                            simd_be_array_in);

         using StrongSIMD = Botan::Strong<Botan::SIMD_4x32, struct StrongSIMD_>;
         const auto simd_le_strong = Botan::load_le<StrongSIMD>(simd_le_in);
         const auto simd_be_strong = Botan::load_be<StrongSIMD>(simd_be_in);

         result.test_bin_eq(
            "roundtrip SIMD strong little-endian", Botan::store_le<std::vector<uint8_t>>(simd_le_strong), simd_le_in);
         result.test_bin_eq(
            "roundtrip SIMD strong big-endian", Botan::store_be<std::vector<uint8_t>>(simd_be_strong), simd_be_in);

         return {result};
      }

      static void BOTAN_FN_ISA_SIMD_4X32 test_eq(Test::Result& result,
                                                 const std::string& op,
                                                 const Botan::SIMD_4x32& simd,
                                                 uint32_t exp0,
                                                 uint32_t exp1,
                                                 uint32_t exp2,
                                                 uint32_t exp3) {
         uint8_t arr_be[16 + 15];
         uint8_t arr_be2[16 + 15];
         uint8_t arr_le[16 + 15];
         uint8_t arr_le2[16 + 15];

         for(size_t misalignment = 0; misalignment != 16; ++misalignment) {
            uint8_t* mem_be = arr_be + misalignment;
            uint8_t* mem_be2 = arr_be2 + misalignment;
            uint8_t* mem_le = arr_le + misalignment;
            uint8_t* mem_le2 = arr_le2 + misalignment;

            simd.store_be(mem_be);

            result.test_u32_eq(
               "SIMD_4x32 " + op + " elem0 BE", Botan::make_uint32(mem_be[0], mem_be[1], mem_be[2], mem_be[3]), exp0);
            result.test_u32_eq(
               "SIMD_4x32 " + op + " elem1 BE", Botan::make_uint32(mem_be[4], mem_be[5], mem_be[6], mem_be[7]), exp1);
            result.test_u32_eq(
               "SIMD_4x32 " + op + " elem2 BE", Botan::make_uint32(mem_be[8], mem_be[9], mem_be[10], mem_be[11]), exp2);
            result.test_u32_eq("SIMD_4x32 " + op + " elem3 BE",
                               Botan::make_uint32(mem_be[12], mem_be[13], mem_be[14], mem_be[15]),
                               exp3);

            // Check load_be+store_be results in same value
            const Botan::SIMD_4x32 reloaded_be = Botan::SIMD_4x32::load_be(mem_be);
            reloaded_be.store_be(mem_be2);
            result.test_bin_eq("SIMD_4x32 load_be", {mem_be, 16}, {mem_be2, 16});

            simd.store_le(mem_le);

            result.test_u32_eq(
               "SIMD_4x32 " + op + " elem0 LE", Botan::make_uint32(mem_le[3], mem_le[2], mem_le[1], mem_le[0]), exp0);
            result.test_u32_eq(
               "SIMD_4x32 " + op + " elem1 LE", Botan::make_uint32(mem_le[7], mem_le[6], mem_le[5], mem_le[4]), exp1);
            result.test_u32_eq(
               "SIMD_4x32 " + op + " elem2 LE", Botan::make_uint32(mem_le[11], mem_le[10], mem_le[9], mem_le[8]), exp2);
            result.test_u32_eq("SIMD_4x32 " + op + " elem3 LE",
                               Botan::make_uint32(mem_le[15], mem_le[14], mem_le[13], mem_le[12]),
                               exp3);

            // Check load_le+store_le results in same value
            const Botan::SIMD_4x32 reloaded_le = Botan::SIMD_4x32::load_le(mem_le);
            reloaded_le.store_le(mem_le2);
            result.test_bin_eq("SIMD_4x32 load_le", {mem_le, 16}, {mem_le2, 16});
         }
      }
};

BOTAN_REGISTER_TEST("utils", "simd_4x32", SIMD_4X32_Tests);
#endif

#if defined(BOTAN_HAS_SIMD_2X64) && defined(BOTAN_HAS_CPUID)

class SIMD_2X64_Tests final : public Test {
   public:
      std::vector<Test::Result> BOTAN_FN_ISA_SIMD_2X64 run() override {
         if(!Botan::CPUID::has(Botan::CPUID::Feature::SIMD_2X64)) {
            return {Test::Result::Note("simd_2x64", "Skipping tests due to missing SIMD support at runtime")};
         } else {
            return {test_simd_2x64()};
         }
      }

   private:
      Test::Result BOTAN_FN_ISA_SIMD_2X64 test_simd_2x64() {
         Test::Result result("SIMD_2x64");

         const uint64_t pat1 = 0x2F8C91D4A37E5C10;
         const uint64_t pat2 = 0x1B74A6F8C29D1345;

         const uint64_t pat1_1 = pat1 + pat1;
         const uint64_t pat1_2 = pat1 + pat2;

         test_eq(result, "default init", Botan::SIMD_2x64(), 0, 0);
         test_eq(result, "SIMD scalar constructor", Botan::SIMD_2x64(1, 2), 1, 2);

         const auto input = Botan::SIMD_2x64(pat1, pat2);
         const auto splat = Botan::SIMD_2x64(pat1, pat1);

         const auto rotl = input.rotl<3>();
         test_eq(result, "rotl", rotl, Botan::rotl<3>(pat1), Botan::rotl<3>(pat2));

         const auto rotr = input.rotr<9>();
         test_eq(result, "rotr", rotr, Botan::rotr<9>(pat1), Botan::rotr<9>(pat2));

         test_eq(result, "rotr<8>", input.rotr<8>(), Botan::rotr<8>(pat1), Botan::rotr<8>(pat2));
         test_eq(result, "rotr<16>", input.rotr<16>(), Botan::rotr<16>(pat1), Botan::rotr<16>(pat2));
         test_eq(result, "rotr<24>", input.rotr<24>(), Botan::rotr<24>(pat1), Botan::rotr<24>(pat2));
         test_eq(result, "rotr<32>", input.rotr<32>(), Botan::rotr<32>(pat1), Botan::rotr<32>(pat2));

         const auto add = input + splat;
         test_eq(result, "add +", add, pat1_1, pat1_2);

         test_eq(result, "xor", input ^ splat, 0, pat2 ^ pat1);

         auto shifter = Botan::SIMD_2x64(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
         shifter = shifter.shr<23>();
         test_eq(result, ">>", shifter, 0x1FFFFFFFFFF, 0x1FFFFFFFFFF);

         shifter = shifter.shl<27>();
         test_eq(result, "<<", shifter, 0xFFFFFFFFF8000000, 0xFFFFFFFFF8000000);

         shifter = input.andc(shifter);
         test_eq(result, "andc", shifter, ~pat1 & 0xFFFFFFFFF8000000, ~pat2 & 0xFFFFFFFFF8000000);

         test_eq(result, "bswap", input.bswap(), Botan::reverse_bytes(pat1), Botan::reverse_bytes(pat2));

         test_eq(result,
                 "reverse_all_bytes",
                 Botan::SIMD_2x64(0x0001020304050607, 0x08090a0b0c0d0e0f).reverse_all_bytes(),
                 0x0f0e0d0c0b0a0908,
                 0x0706050403020100);

         test_eq(result, "swap_lanes", Botan::SIMD_2x64(pat1, pat2).swap_lanes(), pat2, pat1);

         const auto interleave_a = Botan::SIMD_2x64(0x1111111122222222, 0x3333333344444444);
         const auto interleave_b = Botan::SIMD_2x64(0x5555555566666666, 0x7777777788888888);
         test_eq(result,
                 "interleave_high",
                 Botan::SIMD_2x64::interleave_high(interleave_a, interleave_b),
                 0x3333333344444444,
                 0x7777777788888888);

         test_eq(result,
                 "interleave_low",
                 Botan::SIMD_2x64::interleave_low(interleave_a, interleave_b),
                 0x1111111122222222,
                 0x5555555566666666);

         test_eq(result, "all_ones", Botan::SIMD_2x64::all_ones(), 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);

         // Test load/stores SIMD wrapper types
         const auto simd_le_in = Botan::hex_decode("ABCDEF01234567890123456789ABCDEF");
         const auto simd_be_in = Botan::hex_decode("0123456789ABCDEFABCDEF0123456789");
         const auto simd_le_array_in = Botan::concat(simd_le_in, simd_be_in);
         const auto simd_be_array_in = Botan::concat(simd_be_in, simd_le_in);

         auto simd_le = Botan::load_le<Botan::SIMD_2x64>(simd_le_in);
         auto simd_be = Botan::load_be<Botan::SIMD_2x64>(simd_be_in);
         auto simd_le_array = Botan::load_le<std::array<Botan::SIMD_2x64, 2>>(simd_le_array_in);
         auto simd_be_array = Botan::load_be<std::array<Botan::SIMD_2x64, 2>>(simd_be_array_in);

         auto simd_le_vec = Botan::store_le<std::vector<uint8_t>>(simd_le);
         auto simd_be_vec = Botan::store_be(simd_be);
         auto simd_le_array_vec = Botan::store_le<std::vector<uint8_t>>(simd_le_array);
         auto simd_be_array_vec = Botan::store_be(simd_be_array);

         result.test_bin_eq("roundtrip SIMD little-endian", simd_le_vec, simd_le_in);
         result.test_bin_eq(
            "roundtrip SIMD big-endian", std::vector(simd_be_vec.begin(), simd_be_vec.end()), simd_be_in);
         result.test_bin_eq("roundtrip SIMD array little-endian", simd_le_array_vec, simd_le_array_in);
         result.test_bin_eq("roundtrip SIMD array big-endian",
                            std::vector(simd_be_array_vec.begin(), simd_be_array_vec.end()),
                            simd_be_array_in);

         using StrongSIMD = Botan::Strong<Botan::SIMD_2x64, struct StrongSIMD_>;
         const auto simd_le_strong = Botan::load_le<StrongSIMD>(simd_le_in);
         const auto simd_be_strong = Botan::load_be<StrongSIMD>(simd_be_in);

         result.test_bin_eq(
            "roundtrip SIMD strong little-endian", Botan::store_le<std::vector<uint8_t>>(simd_le_strong), simd_le_in);
         result.test_bin_eq(
            "roundtrip SIMD strong big-endian", Botan::store_be<std::vector<uint8_t>>(simd_be_strong), simd_be_in);

         return {result};
      }

   private:
      static void BOTAN_FN_ISA_SIMD_2X64
      test_eq(Test::Result& result, const std::string& op, const Botan::SIMD_2x64& simd, uint64_t exp0, uint64_t exp1) {
         uint8_t arr_be[16 + 15];
         uint8_t arr_be2[16 + 15];
         uint8_t arr_le[16 + 15];
         uint8_t arr_le2[16 + 15];

         for(size_t misalignment = 0; misalignment != 16; ++misalignment) {
            uint8_t* mem_be = arr_be + misalignment;
            uint8_t* mem_be2 = arr_be2 + misalignment;
            uint8_t* mem_le = arr_le + misalignment;
            uint8_t* mem_le2 = arr_le2 + misalignment;

            simd.store_be(mem_be);

            result.test_u64_eq(
               "SIMD_2x64 " + op + " elem0 BE",
               Botan::make_uint64(
                  mem_be[0], mem_be[1], mem_be[2], mem_be[3], mem_be[4], mem_be[5], mem_be[6], mem_be[7]),
               exp0);
            result.test_u64_eq(
               "SIMD_2x64 " + op + " elem1 BE",
               Botan::make_uint64(
                  mem_be[8], mem_be[9], mem_be[10], mem_be[11], mem_be[12], mem_be[13], mem_be[14], mem_be[15]),
               exp1);

            // Check load_be+store_be results in same value
            const Botan::SIMD_2x64 reloaded_be = Botan::SIMD_2x64::load_be(mem_be);
            reloaded_be.store_be(mem_be2);
            result.test_bin_eq("SIMD_2x64 load_be", {mem_be, 16}, {mem_be2, 16});

            simd.store_le(mem_le);

            result.test_u64_eq(
               "SIMD_2x64 " + op + " elem0 LE",
               Botan::make_uint64(
                  mem_le[7], mem_le[6], mem_le[5], mem_le[4], mem_le[3], mem_le[2], mem_le[1], mem_le[0]),
               exp0);
            result.test_u64_eq(
               "SIMD_2x64 " + op + " elem1 LE",
               Botan::make_uint64(
                  mem_le[15], mem_le[14], mem_le[13], mem_le[12], mem_le[11], mem_le[10], mem_le[9], mem_le[8]),
               exp1);

            // Check load_le+store_le results in same value
            const Botan::SIMD_2x64 reloaded_le = Botan::SIMD_2x64::load_le(mem_le);
            reloaded_le.store_le(mem_le2);
            result.test_bin_eq("SIMD_2x64 load_le", {mem_le, 16}, {mem_le2, 16});
         }
      }
};

BOTAN_REGISTER_TEST("utils", "simd_2x64", SIMD_2X64_Tests);
#endif

#if defined(BOTAN_HAS_SIMD_8X32) && defined(BOTAN_HAS_CPUID)

class SIMD_8X32_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         if(!Botan::CPUID::has(Botan::CPUID::Feature::SIMD_8X32)) {
            return {Test::Result::Note("simd_8x32", "Skipping tests due to missing SIMD support at runtime")};
         } else {
            return {test_simd_8x32()};
         }
      }

   private:
      using W8 = std::array<uint32_t, 8>;

      Test::Result BOTAN_FN_ISA_SIMD_8X32 test_simd_8x32() {
         Test::Result result("SIMD_8x32");

         const W8 pat = {
            0xAABBCCDD, 0x87654321, 0x01234567, 0xC0D0E0F0, 0x13579BDF, 0x2468ACE0, 0xFEDCBA98, 0x76543210};

         test_eq(result, "default init", Botan::SIMD_8x32(), W8{0, 0, 0, 0, 0, 0, 0, 0});
         test_eq(result, "scalar constructor", Botan::SIMD_8x32(1, 2, 3, 4, 5, 6, 7, 8), W8{1, 2, 3, 4, 5, 6, 7, 8});
         test_eq(result, "4 word constructor", Botan::SIMD_8x32(1, 2, 3, 4), W8{1, 2, 3, 4, 1, 2, 3, 4});
         test_eq(result, "array constructor", Botan::SIMD_8x32(pat.data()), pat);
         test_eq(result, "splat", Botan::SIMD_8x32::splat(pat[0]), splat8(pat[0]));

         const Botan::SIMD_8x32 input(pat.data());
         const Botan::SIMD_8x32 splat = Botan::SIMD_8x32::splat(pat[0]);

         test_eq(result, "rotl<3>", input.rotl<3>(), map(pat, [](uint32_t x) { return Botan::rotl<3>(x); }));
         test_eq(result, "rotl<8>", input.rotl<8>(), map(pat, [](uint32_t x) { return Botan::rotl<8>(x); }));
         test_eq(result, "rotl<16>", input.rotl<16>(), map(pat, [](uint32_t x) { return Botan::rotl<16>(x); }));
         test_eq(result, "rotl<24>", input.rotl<24>(), map(pat, [](uint32_t x) { return Botan::rotl<24>(x); }));
         test_eq(result, "rotr<9>", input.rotr<9>(), map(pat, [](uint32_t x) { return Botan::rotr<9>(x); }));

         test_eq(result, "sigma0", input.sigma0(), map(pat, [](uint32_t x) {
                    return Botan::rotr<2>(x) ^ Botan::rotr<13>(x) ^ Botan::rotr<22>(x);
                 }));
         test_eq(result, "sigma1", input.sigma1(), map(pat, [](uint32_t x) {
                    return Botan::rotr<6>(x) ^ Botan::rotr<11>(x) ^ Botan::rotr<25>(x);
                 }));

         test_eq(
            result, "add +", input + splat, zip(pat, splat8(pat[0]), [](uint32_t x, uint32_t y) { return x + y; }));
         test_eq(
            result, "sub -", input - splat, zip(pat, splat8(pat[0]), [](uint32_t x, uint32_t y) { return x - y; }));
         test_eq(result, "xor", input ^ splat, zip(pat, splat8(pat[0]), [](uint32_t x, uint32_t y) { return x ^ y; }));
         test_eq(result, "or", input | splat, zip(pat, splat8(pat[0]), [](uint32_t x, uint32_t y) { return x | y; }));
         test_eq(result, "and", input & splat, zip(pat, splat8(pat[0]), [](uint32_t x, uint32_t y) { return x & y; }));

         Botan::SIMD_8x32 acc = input;
         acc += splat;
         test_eq(result, "+=", acc, zip(pat, splat8(pat[0]), [](uint32_t x, uint32_t y) { return x + y; }));
         acc -= splat;
         test_eq(result, "-=", acc, pat);
         acc |= splat;
         test_eq(result, "|=", acc, zip(pat, splat8(pat[0]), [](uint32_t x, uint32_t y) { return x | y; }));
         acc &= splat;
         test_eq(result, "&=", acc, splat8(pat[0]));
         acc ^= splat;
         test_eq(result, "^=", acc, W8{0, 0, 0, 0, 0, 0, 0, 0});
         acc ^= pat[1];
         test_eq(result, "^= u32", acc, splat8(pat[1]));

         test_eq(result, "~", ~input, map(pat, [](uint32_t x) { return ~x; }));
         test_eq(result, "shl<5>", input.shl<5>(), map(pat, [](uint32_t x) { return x << 5; }));
         test_eq(result, "shr<7>", input.shr<7>(), map(pat, [](uint32_t x) { return x >> 7; }));
         test_eq(
            result, "andc", input.andc(splat), zip(pat, splat8(pat[0]), [](uint32_t x, uint32_t y) { return ~x & y; }));

         test_eq(result, "bswap", input.bswap(), map(pat, [](uint32_t x) { return Botan::reverse_bytes(x); }));
         test_eq(
            result, "rev_words", input.rev_words(), W8{pat[3], pat[2], pat[1], pat[0], pat[7], pat[6], pat[5], pat[4]});
         test_eq(result, "reverse", input.reverse(), input.rev_words().bswap());

         const auto lo_mask = Botan::SIMD_8x32(0xFFFFFFFF, 0, 0xFFFFFFFF, 0, 0, 0xFFFFFFFF, 0, 0xFFFFFFFF);
         test_eq(result,
                 "choose",
                 Botan::SIMD_8x32::choose(lo_mask, input, splat),
                 W8{pat[0], pat[0], pat[2], pat[0], pat[0], pat[5], pat[0], pat[7]});

         const auto maj_x =
            Botan::SIMD_8x32(0xF0F0F0F0, 0x00000000, 0xFFFFFFFF, 0x12345678, 0xF0F0F0F0, 0, 0xFFFFFFFF, 0x12345678);
         const auto maj_y = Botan::SIMD_8x32(
            0xFF00FF00, 0xFFFFFFFF, 0xFFFFFFFF, 0x0F0F0F0F, 0xFF00FF00, 0xFFFFFFFF, 0xFFFFFFFF, 0x0F0F0F0F);
         const auto maj_z =
            Botan::SIMD_8x32(0xAAAAAAAA, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xAAAAAAAA, 0, 0, 0xFFFFFFFF);
         test_eq(result,
                 "majority",
                 Botan::SIMD_8x32::majority(maj_x, maj_y, maj_z),
                 W8{(0xF0F0F0F0 & 0xFF00FF00) | (0xF0F0F0F0 & 0xAAAAAAAA) | (0xFF00FF00 & 0xAAAAAAAA),
                    0,
                    0xFFFFFFFF,
                    (0x12345678 & 0x0F0F0F0F) | (0x12345678 & 0xFFFFFFFF) | (0x0F0F0F0F & 0xFFFFFFFF),
                    (0xF0F0F0F0 & 0xFF00FF00) | (0xF0F0F0F0 & 0xAAAAAAAA) | (0xFF00FF00 & 0xAAAAAAAA),
                    0,
                    0xFFFFFFFF,
                    (0x12345678 & 0x0F0F0F0F) | (0x12345678 & 0xFFFFFFFF) | (0x0F0F0F0F & 0xFFFFFFFF)});

         const auto ult_a = Botan::SIMD_8x32(0, 1, 0x80000000, 0xFFFFFFFF, 5, 0x7FFFFFFF, 0x80000001, 0x80000000);
         const auto ult_b = Botan::SIMD_8x32(1, 0, 0x7FFFFFFF, 0xFFFFFFFF, 5, 0x80000000, 0x80000000, 0x80000001);
         test_eq(
            result, "unsigned_lt", ult_a.unsigned_lt(ult_b), W8{0xFFFFFFFF, 0, 0, 0, 0, 0xFFFFFFFF, 0, 0xFFFFFFFF});

         test_eq(result,
                 "shift_elems_left<1>",
                 input.shift_elems_left<1>(),
                 W8{0, pat[0], pat[1], pat[2], 0, pat[4], pat[5], pat[6]});
         test_eq(
            result, "shift_elems_left<2>", input.shift_elems_left<2>(), W8{0, 0, pat[0], pat[1], 0, 0, pat[4], pat[5]});
         test_eq(result, "shift_elems_left<3>", input.shift_elems_left<3>(), W8{0, 0, 0, pat[0], 0, 0, 0, pat[4]});
         test_eq(result,
                 "shift_elems_right<1>",
                 input.shift_elems_right<1>(),
                 W8{pat[1], pat[2], pat[3], 0, pat[5], pat[6], pat[7], 0});
         test_eq(result,
                 "shift_elems_right<2>",
                 input.shift_elems_right<2>(),
                 W8{pat[2], pat[3], 0, 0, pat[6], pat[7], 0, 0});
         test_eq(result, "shift_elems_right<3>", input.shift_elems_right<3>(), W8{pat[3], 0, 0, 0, pat[7], 0, 0, 0});

         const Botan::SIMD_8x32 other(11, 12, 13, 14, 15, 16, 17, 18);
         test_eq(result,
                 "alignr8",
                 Botan::SIMD_8x32::alignr8(other, input),
                 W8{pat[2], pat[3], 11, 12, pat[6], pat[7], 15, 16});

         // Byte shuffle within each lane: reverse the byte order of each 32-bit word (ie bswap)
         const Botan::SIMD_8x32 bswap_idx(0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F);
         test_eq(result, "byte_shuffle bswap", Botan::SIMD_8x32::byte_shuffle(input, bswap_idx), input.bswap());
         // Byte shuffle within each lane: reverse the byte order of the whole lane
         const Botan::SIMD_8x32 rev_idx(0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203);
         test_eq(result, "byte_shuffle reverse", Botan::SIMD_8x32::byte_shuffle(input, rev_idx), input.reverse());
         // Broadcast the first word of each lane
         const Botan::SIMD_8x32 splat_idx(0x03020100, 0x03020100, 0x03020100, 0x03020100);
         test_eq(result,
                 "byte_shuffle splat",
                 Botan::SIMD_8x32::byte_shuffle(input, splat_idx),
                 W8{pat[0], pat[0], pat[0], pat[0], pat[4], pat[4], pat[4], pat[4]});

         test_eq(result,
                 "swap_halves",
                 input.swap_halves(),
                 W8{pat[4], pat[5], pat[6], pat[7], pat[0], pat[1], pat[2], pat[3]});

         // Masked shuffle: reverse the bytes of the first word of each half, zero the rest
         const Botan::SIMD_8x32 mrev_idx(0x00010203, 0xFFFFFFFF, 0x80808080, 0xFFFFFFFF);
         test_eq(result,
                 "masked_byte_shuffle",
                 Botan::SIMD_8x32::masked_byte_shuffle(input, mrev_idx),
                 W8{Botan::reverse_bytes(pat[0]), 0, 0, 0, Botan::reverse_bytes(pat[4]), 0, 0, 0});
         // Bits 4-6 of an index are ignored, unless the top bit is set
         const Botan::SIMD_8x32 mzero_idx(0x73727170, 0x0F0E0D0C, 0xC7C6C5C4, 0x0B0A0908);
         test_eq(result,
                 "masked_byte_shuffle high bits",
                 Botan::SIMD_8x32::masked_byte_shuffle(input, mzero_idx),
                 W8{pat[0], pat[3], 0, pat[2], pat[4], pat[7], 0, pat[6]});

         // Load xtime input at runtime, otherwise MSVC performs in incorrect constant folding
         const auto xt_bytes = Botan::hex_decode("1020408001020408C0007FFFEC763B1D1020408001020408C0007FFFEC763B1D");
         const auto xt_in = Botan::SIMD_8x32::load_le(xt_bytes.data());
         test_eq(result,
                 "xtime<0x1D>",
                 xt_in.xtime<0x1D>(),
                 W8{0x1D804020, 0x10080402, 0xE3FE009D, 0x3A76ECC5, 0x1D804020, 0x10080402, 0xE3FE009D, 0x3A76ECC5});
         test_eq(result,
                 "xtime<0x1B>",
                 xt_in.xtime<0x1B>(),
                 W8{0x1B804020, 0x10080402, 0xE5FE009B, 0x3A76ECC3, 0x1B804020, 0x10080402, 0xE5FE009B, 0x3A76ECC3});

         Botan::SIMD_8x32 t0(pat[0], pat[1], pat[2], pat[3], pat[4], pat[5], pat[6], pat[7]);
         Botan::SIMD_8x32 t1(
            pat[0] + 1, pat[1] + 1, pat[2] + 1, pat[3] + 1, pat[4] + 1, pat[5] + 1, pat[6] + 1, pat[7] + 1);
         Botan::SIMD_8x32 t2(
            pat[0] + 2, pat[1] + 2, pat[2] + 2, pat[3] + 2, pat[4] + 2, pat[5] + 2, pat[6] + 2, pat[7] + 2);
         Botan::SIMD_8x32 t3(
            pat[0] + 3, pat[1] + 3, pat[2] + 3, pat[3] + 3, pat[4] + 3, pat[5] + 3, pat[6] + 3, pat[7] + 3);

         Botan::SIMD_8x32::transpose(t0, t1, t2, t3);

         test_eq(result,
                 "transpose4 t0",
                 t0,
                 W8{pat[0], pat[0] + 1, pat[0] + 2, pat[0] + 3, pat[4], pat[4] + 1, pat[4] + 2, pat[4] + 3});
         test_eq(result,
                 "transpose4 t1",
                 t1,
                 W8{pat[1], pat[1] + 1, pat[1] + 2, pat[1] + 3, pat[5], pat[5] + 1, pat[5] + 2, pat[5] + 3});
         test_eq(result,
                 "transpose4 t2",
                 t2,
                 W8{pat[2], pat[2] + 1, pat[2] + 2, pat[2] + 3, pat[6], pat[6] + 1, pat[6] + 2, pat[6] + 3});
         test_eq(result,
                 "transpose4 t3",
                 t3,
                 W8{pat[3], pat[3] + 1, pat[3] + 2, pat[3] + 3, pat[7], pat[7] + 1, pat[7] + 2, pat[7] + 3});

         // Fill 8 registers with r*8+c and check that the 8x8 transpose gives c*8+r
         Botan::SIMD_8x32 m[8];
         for(uint32_t r = 0; r != 8; ++r) {
            m[r] = Botan::SIMD_8x32(r * 8, r * 8 + 1, r * 8 + 2, r * 8 + 3, r * 8 + 4, r * 8 + 5, r * 8 + 6, r * 8 + 7);
         }
         Botan::SIMD_8x32::transpose(m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7]);
         for(uint32_t c = 0; c != 8; ++c) {
            test_eq(result, "transpose8", m[c], W8{c, 8 + c, 16 + c, 24 + c, 32 + c, 40 + c, 48 + c, 56 + c});
         }

         // Load/store variants
         const auto in32 = Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
         const auto le = Botan::SIMD_8x32::load_le(in32.data());
         test_eq(result,
                 "load_le",
                 le,
                 W8{0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C, 0x13121110, 0x17161514, 0x1B1A1918, 0x1F1E1D1C});
         const auto be = Botan::SIMD_8x32::load_be(in32.data());
         test_eq(result,
                 "load_be",
                 be,
                 W8{0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F, 0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F});

         const auto b128 = Botan::SIMD_8x32::load_le128(in32.data());
         test_eq(result,
                 "load_le128 broadcast",
                 b128,
                 W8{0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C, 0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C});
         const auto b128w = Botan::SIMD_8x32::load_le128(reinterpret_cast<const uint32_t*>(in32.data()));
         test_eq(result,
                 "load_le128 broadcast u32",
                 b128w,
                 W8{0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C, 0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C});

         // NOLINTBEGIN(*-container-data-pointer)
         const auto le2 = Botan::SIMD_8x32::load_le128(reinterpret_cast<const uint32_t*>(&in32[16]),
                                                       reinterpret_cast<const uint32_t*>(&in32[0]));
         test_eq(result,
                 "load_le128 two u32 ptrs",
                 le2,
                 W8{0x13121110, 0x17161514, 0x1B1A1918, 0x1F1E1D1C, 0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C});
         const auto be2 = Botan::SIMD_8x32::load_be128(&in32[16], &in32[0]);
         test_eq(result,
                 "load_be128 two ptrs",
                 be2,
                 W8{0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F, 0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F});

         uint8_t out16[16];
         le2.store_le128(out16);
         result.test_bin_eq(
            "store_le128 low", std::span<const uint8_t>(out16), std::span<const uint8_t>(&in32[16], 16));

         uint32_t out32a[4];
         uint32_t out32b[4];
         le2.store_le128(out32a, out32b);
         result.test_bin_eq("store_le128 two u32 ptrs (low)",
                            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(out32a), 16),
                            std::span<const uint8_t>(&in32[16], 16));
         result.test_bin_eq("store_le128 two u32 ptrs (high)",
                            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(out32b), 16),
                            std::span<const uint8_t>(&in32[0], 16));
         // NOLINTEND(*-container-data-pointer)

         return result;
      }

      static W8 splat8(uint32_t x) { return W8{x, x, x, x, x, x, x, x}; }

      template <typename F>
      static W8 map(const W8& a, F f) {
         W8 r{};
         for(size_t i = 0; i != 8; ++i) {
            r[i] = f(a[i]);
         }
         return r;
      }

      template <typename F>
      static W8 zip(const W8& a, const W8& b, F f) {
         W8 r{};
         for(size_t i = 0; i != 8; ++i) {
            r[i] = f(a[i], b[i]);
         }
         return r;
      }

      static void BOTAN_FN_ISA_SIMD_8X32 test_eq(Test::Result& result,
                                                 const std::string& op,
                                                 const Botan::SIMD_8x32& simd,
                                                 const Botan::SIMD_8x32& expected) {
         W8 exp{};
         expected.store_le(exp.data());
         test_eq(result, op, simd, exp);
      }

      static void BOTAN_FN_ISA_SIMD_8X32 test_eq(Test::Result& result,
                                                 const std::string& op,
                                                 const Botan::SIMD_8x32& simd,
                                                 const W8& expected) {
         uint8_t arr_be[32 + 31];
         uint8_t arr_be2[32 + 31];
         uint8_t arr_le[32 + 31];
         uint8_t arr_le2[32 + 31];

         for(size_t misalignment = 0; misalignment < 32; misalignment += 5) {
            uint8_t* mem_be = arr_be + misalignment;
            uint8_t* mem_be2 = arr_be2 + misalignment;
            uint8_t* mem_le = arr_le + misalignment;
            uint8_t* mem_le2 = arr_le2 + misalignment;

            simd.store_be(mem_be);
            simd.store_le(mem_le);

            for(size_t i = 0; i != 8; ++i) {
               result.test_u32_eq("SIMD_8x32 " + op + " elem" + std::to_string(i) + " BE",
                                  Botan::load_be<uint32_t>(mem_be, i),
                                  expected[i]);
               result.test_u32_eq("SIMD_8x32 " + op + " elem" + std::to_string(i) + " LE",
                                  Botan::load_le<uint32_t>(mem_le, i),
                                  expected[i]);
            }

            // Check load_be+store_be results in same value
            Botan::SIMD_8x32::load_be(mem_be).store_be(mem_be2);
            result.test_bin_eq("SIMD_8x32 load_be", {mem_be, 32}, {mem_be2, 32});

            // Check load_le+store_le results in same value
            Botan::SIMD_8x32::load_le(mem_le).store_le(mem_le2);
            result.test_bin_eq("SIMD_8x32 load_le", {mem_le, 32}, {mem_le2, 32});
         }

         // Also check the uint32_t store overload
         W8 words{};
         simd.store_le(words.data());
         result.test_is_true("SIMD_8x32 " + op + " store_le u32", words == expected);
      }
};

BOTAN_REGISTER_TEST("utils", "simd_8x32", SIMD_8X32_Tests);
#endif

}  // namespace

}  // namespace Botan_Tests
