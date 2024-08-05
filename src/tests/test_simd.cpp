/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_SIMD_32)
   #include <botan/internal/bswap.h>
   #include <botan/internal/cpuid.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/rotate.h>
   #include <botan/internal/simd_32.h>
   #include <botan/internal/stl_util.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_SIMD_32)

class SIMD_32_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("SIMD_4x32");

         if(Botan::CPUID::has_simd_32() == false) {
            result.test_note("Skipping SIMD_4x32 tests due to missing CPU support at runtime");
            return {result};
         }

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

         Botan::SIMD_4x32 rol = input.rotl<3>();

         test_eq(result,
                 "rotl",
                 rol,
                 Botan::rotl<3>(pat1),
                 Botan::rotl<3>(pat2),
                 Botan::rotl<3>(pat3),
                 Botan::rotl<3>(pat4));

         Botan::SIMD_4x32 ror = input.rotr<9>();

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

         result.test_is_eq("roundtrip SIMD little-endian", simd_le_vec, simd_le_in);
         result.test_is_eq(
            "roundtrip SIMD big-endian", std::vector(simd_be_vec.begin(), simd_be_vec.end()), simd_be_in);
         result.test_is_eq("roundtrip SIMD array little-endian", simd_le_array_vec, simd_le_array_in);
         result.test_is_eq("roundtrip SIMD array big-endian",
                           std::vector(simd_be_array_vec.begin(), simd_be_array_vec.end()),
                           simd_be_array_in);

         using StrongSIMD = Botan::Strong<Botan::SIMD_4x32, struct StrongSIMD_>;
         const auto simd_le_strong = Botan::load_le<StrongSIMD>(simd_le_in);
         const auto simd_be_strong = Botan::load_be<StrongSIMD>(simd_be_in);

         result.test_is_eq(
            "roundtrip SIMD strong little-endian", Botan::store_le<std::vector<uint8_t>>(simd_le_strong), simd_le_in);
         result.test_is_eq(
            "roundtrip SIMD strong big-endian", Botan::store_be<std::vector<uint8_t>>(simd_be_strong), simd_be_in);

         return {result};
      }

   private:
      static void test_eq(Test::Result& result,
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

            result.test_int_eq(
               "SIMD_4x32 " + op + " elem0 BE", Botan::make_uint32(mem_be[0], mem_be[1], mem_be[2], mem_be[3]), exp0);
            result.test_int_eq(
               "SIMD_4x32 " + op + " elem1 BE", Botan::make_uint32(mem_be[4], mem_be[5], mem_be[6], mem_be[7]), exp1);
            result.test_int_eq(
               "SIMD_4x32 " + op + " elem2 BE", Botan::make_uint32(mem_be[8], mem_be[9], mem_be[10], mem_be[11]), exp2);
            result.test_int_eq("SIMD_4x32 " + op + " elem3 BE",
                               Botan::make_uint32(mem_be[12], mem_be[13], mem_be[14], mem_be[15]),
                               exp3);

            // Check load_be+store_be results in same value
            const Botan::SIMD_4x32 reloaded_be = Botan::SIMD_4x32::load_be(mem_be);
            reloaded_be.store_be(mem_be2);
            result.test_eq(nullptr, "SIMD_4x32 load_be", mem_be, 16, mem_be2, 16);

            simd.store_le(mem_le);

            result.test_int_eq(
               "SIMD_4x32 " + op + " elem0 LE", Botan::make_uint32(mem_le[3], mem_le[2], mem_le[1], mem_le[0]), exp0);
            result.test_int_eq(
               "SIMD_4x32 " + op + " elem1 LE", Botan::make_uint32(mem_le[7], mem_le[6], mem_le[5], mem_le[4]), exp1);
            result.test_int_eq(
               "SIMD_4x32 " + op + " elem2 LE", Botan::make_uint32(mem_le[11], mem_le[10], mem_le[9], mem_le[8]), exp2);
            result.test_int_eq("SIMD_4x32 " + op + " elem3 LE",
                               Botan::make_uint32(mem_le[15], mem_le[14], mem_le[13], mem_le[12]),
                               exp3);

            // Check load_le+store_le results in same value
            const Botan::SIMD_4x32 reloaded_le = Botan::SIMD_4x32::load_le(mem_le);
            reloaded_le.store_le(mem_le2);
            result.test_eq(nullptr, "SIMD_4x32 load_le", mem_le, 16, mem_le2, 16);
         }
      }
};

BOTAN_REGISTER_TEST("utils", "simd_32", SIMD_32_Tests);
#endif

}  // namespace Botan_Tests
