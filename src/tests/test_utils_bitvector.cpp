/*
 * (C) 2023-2024 Jack Lloyd
 * (C) 2023-2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "tests.h"

#include <botan/internal/fmt.h>

#if defined(BOTAN_HAS_BITVECTOR)
   #include <botan/internal/bitvector.h>
#endif

#include <algorithm>
#include <numeric>

namespace Botan_Tests {

#if defined(BOTAN_HAS_BITVECTOR)

namespace {

/// Returns a random number in the range [min, max)
size_t rand_in_range(Botan::RandomNumberGenerator& rng, size_t min, size_t max) {
   if(min == max) {
      return min;
   }

   size_t val = Botan::load_le<size_t>(rng.random_array<sizeof(size_t)>());
   return min + (val % (max - min));
}

/// Returns @p n integers smaller than @p upper_bound in random order
std::vector<size_t> rand_indices(Botan::RandomNumberGenerator& rng, size_t n, size_t upper_bound) {
   auto shuffle = [&](std::vector<size_t>& v) {
      // Fisher-Yates shuffle
      if(v.size() < 2) {
         return;
      }
      for(size_t i = 0; i < v.size() - 1; ++i) {
         auto j = rand_in_range(rng, i, v.size());
         std::swap(v[i], v[j]);
      }
   };

   std::vector<size_t> indices(upper_bound);
   std::iota(indices.begin(), indices.end(), 0);
   shuffle(indices);
   indices.resize(n);
   return indices;
}

/// Create an empty bitvector of random size and chose a random number of points of interests
std::pair<Botan::bitvector, std::set<size_t>> rnd_bitvector_with_rnd_pois(Botan::RandomNumberGenerator& rng) {
   Botan::bitvector bv(rand_in_range(rng, 0, 65));
   size_t no_poi = rand_in_range(rng, 0, bv.size());
   auto points_of_interest = rand_indices(rng, no_poi, bv.size());

   return {bv, {points_of_interest.begin(), points_of_interest.end()}};
}

template <size_t mod>
auto pattern_generator(size_t offset = 0) {
   return [i = offset]() mutable -> bool {
      const bool result = (i % mod) != 0;
      ++i;
      return result;
   };
}

std::vector<Test::Result> test_bitvector_bitwise_accessors(Botan::RandomNumberGenerator& rng) {
   return {
      CHECK("default constructed bitvector",
            [](auto& result) {
               Botan::bitvector bv;
               result.confirm("default constructed bitvector is empty", bv.empty());
               result.test_eq("default constructed bitvector has zero size", bv.size(), size_t(0));
            }),

      CHECK("preallocated construction of bitvector",
            [](auto& result) {
               Botan::bitvector bv(10);
               result.confirm("allocated bitvector is not empty", !bv.empty());
               result.test_eq("allocated bitvector has allocated size", bv.size(), size_t(10));
               for(size_t i = 0; i < 10; ++i) {
                  result.confirm("bit not set yet", !bv.at(i));
               }
            }),

      CHECK("setting bits",
            [&](auto& result) {
               auto [bv, ones] = rnd_bitvector_with_rnd_pois(rng);

               for(size_t i : ones) {
                  if(rng.next_byte() % 2 == 0) {
                     bv.set(i);
                  } else {
                     bv.at(i) = true;
                  }
               }
               for(size_t i = 0; i < bv.size(); ++i) {
                  result.confirm(Botan::fmt("bit {} in expected state", i), bv.at(i) == ones.contains(i));
               }
            }),

      CHECK("unsetting bits",
            [&](auto& result) {
               auto [bv, zeros] = rnd_bitvector_with_rnd_pois(rng);
               for(auto b : bv) {
                  b.set();
               }

               for(size_t i : zeros) {
                  if(rng.next_byte() % 2 == 0) {
                     bv.unset(i);
                  } else {
                     bv.at(i) = false;
                  }
               }
               for(size_t i = 0; i < bv.size(); ++i) {
                  result.confirm(Botan::fmt("bit {} in expected state", i), bv.at(i) == !zeros.contains(i));
               }
            }),

      CHECK("flipping bits",
            [&](auto& result) {
               auto [bv, ones] = rnd_bitvector_with_rnd_pois(rng);

               for(size_t i = 0; i < bv.size(); ++i) {
                  if(std::find(ones.begin(), ones.end(), i) == ones.end()) {
                     bv.set(i);
                  }
                  bv.flip(i);
               }
               for(size_t i = 0; i < bv.size(); ++i) {
                  result.confirm(Botan::fmt("bit {} in expected state", i), bv.at(i) == ones.contains(i));
               }
            }),

      CHECK("accessors validate offsets",
            [](auto& result) {
               Botan::bitvector bv(10);
               result.template test_throws<Botan::Invalid_Argument>(
                  ".at() const out of range", [&] { const_cast<const decltype(bv)&>(bv).at(10); });
               result.template test_throws<Botan::Invalid_Argument>(".at() out of range", [&] { bv.at(10); });
               result.template test_throws<Botan::Invalid_Argument>(".set() out of range", [&] { bv.set(10); });
               result.template test_throws<Botan::Invalid_Argument>(".unset() out of range", [&] { bv.unset(10); });
               result.template test_throws<Botan::Invalid_Argument>(".flip() out of range", [&] { bv.flip(10); });
            }),

      CHECK("multiblock handling",
            [](auto& result) {
               Botan::bitvector bv(128);
               result.test_eq("has more than 64 bits", bv.size(), 128);
               bv.set(1).set(63).set(64).set(127);
               for(size_t i = 0; i < bv.size(); ++i) {
                  bool expected = (i == 1 || i == 63 || i == 64 || i == 127);
                  result.test_eq(Botan::fmt("bit {} in expected state", i), bv.at(i), expected);
               }
            }),

      CHECK("subscript operator",
            [](auto& result) {
               Botan::bitvector bv(128);
               bv[0].set();
               bv[1] = true;
               bv[2].flip();
               bv[64] = true;
               bv[80] = true;
               result.confirm("bit 0", bv[0]);
               result.confirm("bit 1", bv[1]);
               result.confirm("bit 2", bv[2]);
               result.confirm("bit 3", !bv[3]);
               result.confirm("bit 64", bv[64]);
               result.confirm("bit 80", bv[80]);
            }),

      CHECK("subscript operator does not validate offsets",
            [](auto& result) {
               Botan::bitvector bv(10);
               result.template test_throws<Botan::Invalid_Argument>(".at() out of range", [&] { bv.at(10); });
               // Technically the next line is undefined behaviour.
               // Though, the current implementation detail won't
               // cause issues, which might change!
               result.test_no_throw("subscript out of range", [&] { bv[10]; });
            }),

      CHECK("bitwise assignment modifiers",
            [](auto& result) {
               Botan::bitvector bv(4);

               result.require("precondition", !bv[0] && !bv[1]);
               bv[0] &= 1;  // NOLINT(*-use-bool-literals)
               result.confirm("bv[0] still 0", !bv[0]);
               bv[0].set();
               bv[0] &= 1;  // NOLINT(*-use-bool-literals)
               result.confirm("bv[0] still 1", bv[0]);
               bv[0] &= false;
               result.confirm("bv[0] now 0 again", !bv[0]);
               bv[0] &= !bv[1];
               result.confirm("bv[0] still 0 once more", !bv[0]);

               result.require("precondition 2", !bv[1] && !bv[2]);
               bv[1] |= 1;  // NOLINT(modernize-use-bool-literals)
               result.confirm("bv[1] is now 1", bv[1]);
               bv[1] |= 0;  // NOLINT(modernize-use-bool-literals)
               result.confirm("bv[1] is still 1", bv[1]);
               bv[1].unset();
               bv[1] |= false;
               result.confirm("bv[1] is 0", !bv[1]);
               bv[1] |= !bv[2];
               result.confirm("bv[1] is 1 again", bv[1]);

               result.require("precondition 3", !bv[2] && !bv[3]);
               bv[2] ^= 0;  // NOLINT(modernize-use-bool-literals)
               result.confirm("bv[2] is still 0", !bv[2]);
               bv[2] ^= true;
               result.confirm("bv[2] is now 1", bv[2]);
               bv[2] ^= !bv[3];
               result.confirm("bv[2] is 0 again", !bv[2]);
            }),
   };
}

std::vector<Test::Result> test_bitvector_capacity(Botan::RandomNumberGenerator&) {
   return {
      CHECK("default constructed bitvector",
            [](auto& result) {
               Botan::bitvector bv;
               result.confirm("empty", bv.empty());
               result.test_eq("no size", bv.size(), size_t(0));
               result.test_eq("no capacity", bv.capacity(), size_t(0));
            }),

      CHECK("allocated bitvector has capacity",
            [](auto& result) {
               Botan::bitvector bv(1);
               result.confirm("empty", !bv.empty());
               result.test_eq("small size", bv.size(), size_t(1));
               result.test_gte("a little capacity", bv.capacity(), size_t(8));
            }),

      CHECK("reserved bitvector has capacity",
            [](auto& result) {
               Botan::bitvector bv;
               result.test_eq("no size", bv.size(), size_t(0));
               result.test_eq("no capacity", bv.capacity(), size_t(0));

               bv.reserve(64);
               result.test_eq("no size", bv.size(), size_t(0));
               result.test_gte("no capacity", bv.capacity(), size_t(64));

               bv.reserve(128);
               result.test_eq("no size", bv.size(), size_t(0));
               result.test_gte("no capacity", bv.capacity(), size_t(128));
            }),

      CHECK("push_back() extends bitvector",
            [](Test::Result& result) {
               Botan::bitvector bv;
               result.confirm("empty", bv.empty());
               result.test_eq("no size", bv.size(), size_t(0));

               bv.push_back(true);
               bv.push_back(false);
               bv.push_back(true);
               bv.push_back(false);

               result.confirm("not empty", !bv.empty());
               result.test_eq("some size", bv.size(), size_t(4));
               result.test_gte("capacity is typically bigger than size", bv.capacity(), size_t(8));

               result.confirm("bit 0", bv.at(0));
               result.confirm("bit 1", !bv.at(1));
               result.confirm("bit 2", bv.at(2));
               result.confirm("bit 3", !bv.at(3));

               result.test_throws("bit 4 is not yet allocated", [&] { bv.at(4); });
            }),

      CHECK("pop_back() shortens bitvector",
            [](Test::Result& result) {
               Botan::bitvector bv;
               bv.push_back(true);
               bv.push_back(false);
               bv.push_back(true);
               bv.push_back(false);
               result.confirm("last is false", !bv.back());

               bv.pop_back();
               result.test_eq("size() == 3", bv.size(), 3);
               result.confirm("last is true", bv.back());

               bv.pop_back();
               result.test_eq("size() == 2", bv.size(), 2);
               result.confirm("last is false", !bv.back());

               bv.pop_back();
               result.test_eq("size() == 1", bv.size(), 1);
               result.confirm("last is true", bv.back());
               result.confirm("first is true", bv.front());

               bv.pop_back();
               result.confirm("empty", bv.empty());

               result.test_throws("bit 4 is not yet allocated", [&] { bv.at(4); });
            }),

      CHECK("resize()",
            [](auto& result) {
               Botan::bitvector bv(10);
               bv[0] = true;
               bv[5] = true;
               bv[9] = true;

               bv.resize(8);
               result.test_eq("size is reduced", bv.size(), size_t(8));

               for(size_t i = 0; i < bv.size(); ++i) {
                  const bool expected = (i == 0 || i == 5);
                  result.test_eq(Botan::fmt("{} is as expected", i), bv[i], expected);
               }

               bv.resize(0);
               result.confirm("resize(0) empties buffer", bv.empty());

               bv.resize(8);
               result.confirm("0 is false", !bv[0]);
               result.confirm("5 is false", !bv[5]);
            }),
   };
}

std::vector<Test::Result> test_bitvector_subvector(Botan::RandomNumberGenerator&) {
   auto make_bitpattern = [&]<typename T>(T& bitvector, size_t pattern_offset = 0) {
      auto next = pattern_generator<3>(pattern_offset);

      if constexpr(std::unsigned_integral<T>) {
         for(size_t i = 0; i < sizeof(T) * 8; ++i) {
            bitvector |= static_cast<T>(next()) << i;
         }
      } else {
         for(auto& i : bitvector) {
            i = next();
         }
      }
   };

   auto bitpattern_at = [&]<std::unsigned_integral T>(T /* ignored */, size_t pattern_offset) -> T {
      T bitvector = 0;
      make_bitpattern(bitvector, pattern_offset);
      return bitvector;
   };

   auto check_bitpattern = [&](auto& result, auto& bitvector, size_t offset = 0) {
      using bv_t = std::remove_cvref_t<decltype(bitvector)>;
      auto next = pattern_generator<3>(offset);

      if constexpr(std::unsigned_integral<bv_t>) {
         for(size_t i = 0; i < sizeof(bv_t) * 8; ++i) {
            result.confirm(Botan::fmt("{} is as expected", i), (bitvector & (bv_t(1) << i)) != 0, next());
         }
      } else {
         for(size_t i = 0; i < bitvector.size(); ++i) {
            result.confirm(Botan::fmt("{} is as expected", i), bitvector[i], next());
         }
      }
   };

   auto check_bitpattern_with_zero_region = [&](auto& result, auto& bitvector, std::pair<size_t, size_t> zero_region) {
      auto next = pattern_generator<3>();
      for(size_t i = 0; i < bitvector.size(); ++i) {
         const bool i_in_range = (zero_region.first <= i && i < zero_region.second);
         const bool expected = next();
         result.confirm(Botan::fmt("{} is as expected", i), bitvector[i], !i_in_range && expected);
      }
   };

   return {
      CHECK("range errors are caught",
            [&](auto& result) {
               Botan::bitvector bv(100);
               result.template test_throws<Botan::Invalid_Argument>("out of range", [&] { bv.subvector(0, 101); });
               result.template test_throws<Botan::Invalid_Argument>("out of range", [&] { bv.subvector(90, 11); });
               result.template test_throws<Botan::Invalid_Argument>("out of range", [&] { bv.subvector(100, 1); });
               result.template test_throws<Botan::Invalid_Argument>("out of range", [&] { bv.subvector(101, 0); });
            }),

      CHECK("empty copy is allowed",
            [&](auto& result) {
               Botan::bitvector bv1(100);
               auto bv2 = bv1.subvector(0, 0);
               result.test_eq("empty at 0", bv2.size(), size_t(0));
               auto bv3 = bv1.subvector(10, 0);
               result.test_eq("empty at 10", bv3.size(), size_t(0));
               auto bv4 = bv1.subvector(100, 0);
               result.test_eq("empty at 100", bv3.size(), size_t(0));
            }),

      CHECK("byte-aligned copy",
            [&](auto& result) {
               Botan::bitvector bv1(100);
               make_bitpattern(bv1);

               auto bv2 = bv1.subvector(16, 58);
               result.test_eq("size is as requested", bv2.size(), size_t(58));
               check_bitpattern(result, bv2, 16);

               auto bv3 = bv1.subvector(32);  // copy until the end
               result.test_eq("size is as expected", bv3.size(), size_t(68));
               check_bitpattern(result, bv3, 32);
            }),

      CHECK("byte-aligned 2",
            [&](auto& result) {
               Botan::bitvector bv1(100);
               make_bitpattern(bv1);

               auto bv2 = bv1.subvector(8, 91);
               result.test_eq("size is as expected", bv2.size(), size_t(91));
               check_bitpattern(result, bv2, 8);

               auto bv3 = bv1.subvector(16, 58);
               result.test_eq("size is as requested", bv3.size(), size_t(58));
               check_bitpattern(result, bv3, 16);

               auto bv4 = bv1.subvector(24);  // copy until the end
               result.test_eq("size is as expected", bv4.size(), size_t(100 - 24));
               check_bitpattern(result, bv4, 24);

               auto bv5 = bv1.subvector(32);  // copy until the end
               result.test_eq("size is as expected", bv5.size(), size_t(100 - 32));
               check_bitpattern(result, bv5, 32);

               auto bv6 = bv1.subvector(48, 51);  // copy until the end
               result.test_eq("size is as expected", bv6.size(), size_t(51));
               check_bitpattern(result, bv6, 48);
            }),

      CHECK("byte-aligned copy must zero-out unused bits",
            [&](auto& result) {
               Botan::bitvector bv1(100);
               make_bitpattern(bv1);

               auto bv2 = bv1.subvector(16, 17);
               result.test_eq("size is as requested", bv2.size(), size_t(17));
               check_bitpattern(result, bv2, 16);

               bv2.resize(32);
               for(size_t i = 17; i < bv2.size(); ++i) {
                  result.confirm("tail is zero", !bv2[i]);
               }
            }),

      CHECK("unaligned copy",
            [&](auto& result) {
               Botan::bitvector bv1(100);
               make_bitpattern(bv1);

               auto bv2 = bv1.subvector(19, 69);
               result.test_eq("size is as requested", bv2.size(), size_t(69));
               check_bitpattern(result, bv2, 19);

               auto bv3 = bv1.subvector(21);  // copy until the end
               result.test_eq("size is as expected", bv3.size(), size_t(79));
               check_bitpattern(result, bv3, 21);

               auto bv4 = bv1.subvector(1, 16);
               result.test_eq("size is as expected", bv4.size(), size_t(16));
               check_bitpattern(result, bv4, 1);

               auto bv5 = bv1.subvector(1, 32);
               result.test_eq("size is as expected", bv5.size(), size_t(32));
               check_bitpattern(result, bv5, 1);

               auto bv6 = bv5.subvector(1, 12);
               result.test_eq("size is as expected", bv6.size(), size_t(12));
               check_bitpattern(result, bv6, 1 + 1);

               auto bv7 = bv1.subvector(17, 67);
               result.test_eq("size is as expected", bv7.size(), size_t(67));
               check_bitpattern(result, bv7, 17);

               auto bv8 = bv1.subvector(33);  // copy until the end
               result.test_eq("size is as expected", bv8.size(), size_t(67));
               check_bitpattern(result, bv8, 33);
            }),

      CHECK("byte-aligned unsigned integer subvector",
            [&](auto& result) {
               Botan::bitvector bv1(100);
               make_bitpattern(bv1);

               const auto u8_0 = bv1.subvector<uint8_t>(0);
               const auto u8_32 = bv1.subvector<uint8_t>(32);
               check_bitpattern(result, u8_0, 0);
               check_bitpattern(result, u8_32, 32);

               const auto u16_0 = bv1.subvector<uint16_t>(0);
               const auto u16_56 = bv1.subvector<uint16_t>(56);
               check_bitpattern(result, u16_0, 0);
               check_bitpattern(result, u16_56, 56);

               const auto u32_0 = bv1.subvector<uint32_t>(0);
               const auto u32_48 = bv1.subvector<uint32_t>(48);
               check_bitpattern(result, u32_0, 0);
               check_bitpattern(result, u32_48, 48);

               const auto u64_0 = bv1.subvector<uint64_t>(0);
               const auto u64_32 = bv1.subvector<uint64_t>(32);
               check_bitpattern(result, u64_0, 0);
               check_bitpattern(result, u64_32, 32);

               result.test_throws("out of range (uint8_t)", [&] { bv1.subvector<uint8_t>(93); });
               result.test_throws("out of range (uint16_t)", [&] { bv1.subvector<uint16_t>(85); });
               result.test_throws("out of range (uint32_t)", [&] { bv1.subvector<uint32_t>(69); });
               result.test_throws("out of range (uint64_t)", [&] { bv1.subvector<uint64_t>(37); });
            }),

      CHECK("unaligned unsigned integer subvector",
            [&](Test::Result& result) {
               Botan::bitvector bv1(100);
               make_bitpattern(bv1);

               const auto u8_3 = bv1.subvector<uint8_t>(3);
               const auto u8_92 = bv1.subvector<uint8_t>(92);
               check_bitpattern(result, u8_3, 3);
               check_bitpattern(result, u8_92, 92);

               const auto u16_7 = bv1.subvector<uint16_t>(7);
               const auto u16_84 = bv1.subvector<uint16_t>(84);
               check_bitpattern(result, u16_7, 7);
               check_bitpattern(result, u16_84, 84);

               const auto u32_11 = bv1.subvector<uint32_t>(11);
               const auto u32_68 = bv1.subvector<uint32_t>(68);
               check_bitpattern(result, u32_11, 11);
               check_bitpattern(result, u32_68, 68);

               const auto u64_21 = bv1.subvector<uint64_t>(21);
               const auto u64_36 = bv1.subvector<uint64_t>(36);
               check_bitpattern(result, u64_21, 21);
               check_bitpattern(result, u64_36, 36);
            }),

      CHECK("byte-aligned unsigned integer subvector replacement",
            [&](auto& result) {
               Botan::bitvector bv1(100);
               make_bitpattern(bv1);

               bv1.subvector_replace(0, uint8_t(0));
               check_bitpattern_with_zero_region(result, bv1, {0, 8});
               bv1.subvector_replace(0, bitpattern_at(uint8_t(0), 0));
               check_bitpattern(result, bv1);

               bv1.subvector_replace(32, uint8_t(0));
               check_bitpattern_with_zero_region(result, bv1, {32, 32 + 8});
               bv1.subvector_replace(32, bitpattern_at(uint8_t(0), 32));
               check_bitpattern(result, bv1);

               bv1.subvector_replace(56, uint16_t(0));
               check_bitpattern_with_zero_region(result, bv1, {56, 56 + 16});
               bv1.subvector_replace(56, bitpattern_at(uint16_t(0), 56));
               check_bitpattern(result, bv1);

               bv1.subvector_replace(48, uint32_t(0));
               check_bitpattern_with_zero_region(result, bv1, {48, 48 + 32});
               bv1.subvector_replace(48, bitpattern_at(uint32_t(0), 48));
               check_bitpattern(result, bv1);

               bv1.subvector_replace(16, uint64_t(0));
               check_bitpattern_with_zero_region(result, bv1, {16, 16 + 64});
               bv1.subvector_replace(16, bitpattern_at(uint64_t(0), 16));
               check_bitpattern(result, bv1);

               result.test_throws("out of range (uint8_t)", [&] { bv1.subvector_replace<uint8_t>(93, 42); });
               result.test_throws("out of range (uint16_t)", [&] { bv1.subvector_replace<uint16_t>(85, 42); });
               result.test_throws("out of range (uint32_t)", [&] { bv1.subvector_replace<uint32_t>(69, 42); });
               result.test_throws("out of range (uint64_t)", [&] { bv1.subvector_replace<uint64_t>(37, 42); });
            }),

      CHECK("unaligned unsigned integer subvector replacement",
            [&](auto& result) {
               Botan::bitvector bv1(100);
               make_bitpattern(bv1);

               bv1.subvector_replace(3, uint8_t(0));
               check_bitpattern_with_zero_region(result, bv1, {3, 3 + 8});
               bv1.subvector_replace(3, bitpattern_at(uint8_t(0), 3));
               check_bitpattern(result, bv1);

               bv1.subvector_replace(92, uint8_t(0));
               check_bitpattern_with_zero_region(result, bv1, {92, 92 + 8});
               bv1.subvector_replace(92, bitpattern_at(uint8_t(0), 92));
               check_bitpattern(result, bv1);

               bv1.subvector_replace(7, uint16_t(0));
               check_bitpattern_with_zero_region(result, bv1, {7, 7 + 16});
               bv1.subvector_replace(7, bitpattern_at(uint16_t(0), 7));
               check_bitpattern(result, bv1);

               bv1.subvector_replace(84, uint16_t(0));
               check_bitpattern_with_zero_region(result, bv1, {84, 84 + 16});
               bv1.subvector_replace(84, bitpattern_at(uint16_t(0), 84));
               check_bitpattern(result, bv1);

               bv1.subvector_replace(11, uint32_t(0));
               check_bitpattern_with_zero_region(result, bv1, {11, 11 + 32});
               bv1.subvector_replace(11, bitpattern_at(uint32_t(0), 11));
               check_bitpattern(result, bv1);

               bv1.subvector_replace(68, uint32_t(0));
               check_bitpattern_with_zero_region(result, bv1, {68, 68 + 32});
               bv1.subvector_replace(68, bitpattern_at(uint32_t(0), 68));
               check_bitpattern(result, bv1);

               bv1.subvector_replace(21, uint64_t(0));
               check_bitpattern_with_zero_region(result, bv1, {21, 21 + 64});
               bv1.subvector_replace(21, bitpattern_at(uint64_t(0), 21));
               check_bitpattern(result, bv1);
            }),
   };
}

std::vector<Test::Result> test_bitvector_global_modifiers_and_predicates(Botan::RandomNumberGenerator&) {
   auto make_bitpattern = [](auto& bitvector) {
      auto next = pattern_generator<5>();
      for(auto& i : bitvector) {
         i = next();
      }
   };

   auto check_bitpattern = [](auto& result, auto& bitvector) {
      auto next = pattern_generator<5>();
      for(size_t i = 0; i < bitvector.size(); ++i) {
         result.confirm(Botan::fmt("{} is as expected", i), bitvector[i], next());
      }
   };

   auto check_flipped_bitpattern = [](auto& result, auto& bitvector) {
      auto next = pattern_generator<5>();
      for(size_t i = 0; i < bitvector.size(); ++i) {
         result.confirm(Botan::fmt("{} is as expected", i), bitvector[i], !next());
      }
   };

   return {
      CHECK("one bit",
            [](auto& result) {
               Botan::bitvector bv;
               bv.push_back(true);

               bv.flip();
               result.confirm("bit is flipped", !bv[0]);

               // check that unused bits aren't flipped
               bv.resize(8);
               for(size_t i = 0; i < bv.size(); ++i) {
                  result.confirm("all bits are false", !bv[i]);
               }
               bv.resize(1);

               bv.flip();
               result.confirm("bit is flipped again", bv[0]);
            }),

      CHECK("bits in many blocks",
            [&](auto& result) {
               Botan::bitvector bv(99);

               make_bitpattern(bv);
               bv.flip();
               check_flipped_bitpattern(result, bv);

               bv = ~bv;
               check_bitpattern(result, bv);

               bv.resize(112);
               for(size_t i = 99; i < bv.size(); ++i) {
                  result.confirm("just-allocated bit is not set", !bv[i]);
               }
            }),

      CHECK("set and unset",
            [&](auto& result) {
               Botan::bitvector bv(99);

               make_bitpattern(bv);
               bv.set();
               bv.resize(128);
               for(size_t i = 0; i < bv.size(); ++i) {
                  const bool expected = (i < 99);
                  result.test_eq("only set bits are set", bv[i], expected);
               }

               bv.unset();
               for(size_t i = 0; i < bv.size(); ++i) {
                  result.confirm("bit is not set", !bv[i]);
               }
            }),

      CHECK("any, none and all",
            [&](auto& result) {
               Botan::bitvector bv(99);

               result.confirm("default construction yields all-zero", bv.none_vartime());
               result.confirm("default construction yields all-zero 2", !bv.any_vartime());
               result.confirm("default construction yields all-zero 3", !bv.all_vartime());
               result.confirm("default construction yields all-zero 4", bv.none());
               result.confirm("default construction yields all-zero 5", !bv.any());
               result.confirm("default construction yields all-zero 6", !bv.all());

               bv.set(42);
               result.confirm("setting a bit means there's a bit set", !bv.none_vartime());
               result.confirm("setting a bit means there's a bit set 2", bv.any_vartime());
               result.confirm("setting a bit means there's not all bits set", !bv.all_vartime());
               result.confirm("setting a bit means there's a bit set 3", !bv.none());
               result.confirm("setting a bit means there's a bit set 4", bv.any());
               result.confirm("setting a bit means there's not all bits set 2", !bv.all());

               bv.set();
               result.confirm("setting all bits means there's a bit set", !bv.none_vartime());
               result.confirm("setting all bits means there's a bit set 2", bv.any_vartime());
               result.confirm("setting all bits means all bits are set", bv.all_vartime());
               result.confirm("setting all bits means there's a bit set 3", !bv.none());
               result.confirm("setting all bits means there's a bit set 4", bv.any());
               result.confirm("setting all bits means all bits are set 2", bv.all());

               bv.unset(97);
               result.confirm("a single 0 at the end means that there's a bit set", !bv.none_vartime());
               result.confirm("a single 0 at the end means that there are bits set", bv.any_vartime());
               result.confirm("a single 0 at the end means that there are not all bits set", !bv.all_vartime());
               result.confirm("a single 0 at the end means that there's a bit set 2", !bv.none());
               result.confirm("a single 0 at the end means that there are bits set 2", bv.any());
               result.confirm("a single 0 at the end means that there are not all bits set 2", !bv.all());

               bv.unset();
               result.confirm("unsetting all bits means there's no bit set", bv.none_vartime());
               result.confirm("unsetting all bits means there's no bit set 2", !bv.any_vartime());
               result.confirm("unsetting all bits means there's not all bits set", !bv.all_vartime());
               result.confirm("unsetting all bits means there's no bit set 3", bv.none());
               result.confirm("unsetting all bits means there's no bit set 4", !bv.any());
               result.confirm("unsetting all bits means there's not all bits set 2", !bv.all());
            }),

      CHECK("hamming weight oddness",
            [](auto& result) {
               const auto evn = Botan::hex_decode("FE3410CB0278E4D26602");
               const auto odd = Botan::hex_decode("BB2418C2B4F288921203");

               result.confirm("odd hamming", Botan::bitvector(odd).has_odd_hamming_weight().as_bool());
               result.confirm("even hamming", !Botan::bitvector(evn).has_odd_hamming_weight().as_bool());
            }),

      CHECK("hamming weight",
            [](auto& result) {
               auto naive_count = [](auto& v) {
                  size_t weight = 0;
                  for(const auto& bit : v) {
                     weight += bit.template as<size_t>();
                  }
                  return weight;
               };

               // the last three bits of this bitvector are set, then there's a gap
               auto bv = Botan::bitvector(Botan::hex_decode("FE3410CB0278E4D26602E0"));
               result.test_eq("hamming weight", bv.hamming_weight(), size_t(37));
               result.test_eq("hamming weight", bv.hamming_weight(), naive_count(bv));

               bv.pop_back();
               result.test_eq("hamming weight", bv.hamming_weight(), size_t(36));
               result.test_eq("hamming weight", bv.hamming_weight(), naive_count(bv));

               bv.pop_back();
               result.test_eq("hamming weight", bv.hamming_weight(), size_t(35));
               result.test_eq("hamming weight", bv.hamming_weight(), naive_count(bv));

               bv.pop_back();
               result.test_eq("hamming weight", bv.hamming_weight(), size_t(34));
               result.test_eq("hamming weight", bv.hamming_weight(), naive_count(bv));

               bv.pop_back();
               result.test_eq("hamming weight", bv.hamming_weight(), size_t(34));
               result.test_eq("hamming weight", bv.hamming_weight(), naive_count(bv));
            }),
   };
}

std::vector<Test::Result> test_bitvector_binary_operators(Botan::RandomNumberGenerator&) {
   auto check_set = [](auto& result, auto bits, std::vector<size_t> set_bits) {
      for(size_t i = 0; i < bits.size(); ++i) {
         const auto should_be_set = std::find(set_bits.begin(), set_bits.end(), i) != set_bits.end();
         result.test_eq(Botan::fmt("{} should {}be set", i, (!should_be_set ? "not " : "")), bits[i], should_be_set);
      }
   };

   auto is_secure_allocator = []<template <typename> typename AllocatorT>(auto& result,
                                                                          const Botan::bitvector_base<AllocatorT>&) {
      result.confirm("allocator is Botan::secure_allocator<>",
                     std::same_as<Botan::secure_allocator<uint8_t>, AllocatorT<uint8_t>>);
   };

   auto is_standard_allocator = []<template <typename> typename AllocatorT>(auto& result,
                                                                            const Botan::bitvector_base<AllocatorT>&) {
      result.confirm("allocator is std::allocator<>", std::same_as<std::allocator<uint8_t>, AllocatorT<uint8_t>>);
   };

   return {
      CHECK("bitwise_equals",
            [&](auto& result) {
               Botan::bitvector lhs(20);
               lhs.set(0).set(4).set(15).set(16).set(19);
               Botan::bitvector rhs(20);
               rhs.set(1).set(4).set(16).set(17).set(18);

               result.test_eq("Not equal bitvectors", lhs.equals_vartime(rhs), false);
               result.test_eq("Not equal bitvectors 2", lhs.equals(rhs), false);

               lhs.unset().set(13);
               rhs.unset().set(13);

               result.test_eq("equal bitvectors", lhs.equals_vartime(rhs), true);
               result.test_eq("equal bitvectors 2", lhs.equals(rhs), true);
            }),

      CHECK("bitwise OR",
            [&](auto& result) {
               Botan::bitvector lhs(20);
               lhs.set(0).set(4).set(15).set(16).set(19);
               Botan::bitvector rhs(20);
               rhs.set(1).set(4).set(16).set(17).set(18);
               Botan::bitvector unary(20);
               unary.set(8);

               Botan::bitvector res = lhs | rhs;
               check_set(result, res, {0, 1, 4, 15, 16, 17, 18, 19});

               res |= unary;
               check_set(result, res, {0, 1, 4, 8, 15, 16, 17, 18, 19});

               is_standard_allocator(result, res);
            }),

      CHECK("bitwise AND",
            [&](auto& result) {
               Botan::bitvector lhs(20);
               lhs.set(0).set(4).set(15).set(16).set(18);
               Botan::bitvector rhs(20);
               rhs.set(1).set(4).set(16).set(17).set(18);
               Botan::bitvector unary(20);
               unary.set(8).set(16);

               Botan::bitvector res = lhs & rhs;
               check_set(result, res, {4, 16, 18});

               res &= unary;
               check_set(result, res, {16});

               is_standard_allocator(result, res);
            }),

      CHECK("bitwise XOR",
            [&](auto& result) {
               Botan::bitvector lhs(20);
               lhs.set(0).set(4).set(15).set(16).set(18);
               Botan::bitvector rhs(20);
               rhs.set(1).set(4).set(16).set(17).set(18);
               Botan::bitvector unary(20);
               unary.set(8).set(16);

               Botan::bitvector res = lhs ^ rhs;
               check_set(result, res, {0, 1, 15, 17});

               res ^= unary;
               check_set(result, res, {0, 1, 8, 15, 16, 17});

               is_standard_allocator(result, res);
            }),

      CHECK("bitwise operators with heterogeneous allocators",
            [&](auto& result) {
               Botan::bitvector lhs(20);
               lhs.set(0).set(4).set(15).set(16).set(18);
               Botan::secure_bitvector rhs(20);
               rhs.set(1).set(4).set(16).set(17).set(18);
               Botan::bitvector unary(20);
               unary.set(8).set(16);

               auto res1 = lhs | rhs;
               is_secure_allocator(result, res1);
               check_set(result, res1, {0, 1, 4, 15, 16, 17, 18, 20});

               auto res2 = rhs | lhs;
               is_secure_allocator(result, res2);
               check_set(result, res2, {0, 1, 4, 15, 16, 17, 18, 20});

               auto res3 = lhs & rhs;
               is_secure_allocator(result, res3);
               check_set(result, res3, {4, 16, 18});

               auto res4 = rhs & lhs;
               is_secure_allocator(result, res4);
               check_set(result, res4, {4, 16, 18});

               auto res5 = lhs ^ rhs;
               is_secure_allocator(result, res5);
               check_set(result, res5, {0, 1, 15, 17});

               auto res6 = rhs ^ lhs;
               is_secure_allocator(result, res6);
               check_set(result, res6, {0, 1, 15, 17});
            }),
   };
}

std::vector<Test::Result> test_bitvector_serialization(Botan::RandomNumberGenerator&) {
   constexpr uint8_t outlen = 64;
   const auto bytearray = [] {
      std::array<uint8_t, outlen> out;
      for(uint8_t i = 0; i < outlen; ++i) {
         out[i] = i;
      }
      return out;
   }();

   auto validate_bytewise = [](auto& result, const auto& bv, std::span<const uint8_t> bytes) {
      for(size_t i = 0; i < bytes.size(); ++i) {
         const uint8_t b = (static_cast<uint8_t>(bv[0 + i * 8]) << 0) | (static_cast<uint8_t>(bv[1 + i * 8]) << 1) |
                           (static_cast<uint8_t>(bv[2 + i * 8]) << 2) | (static_cast<uint8_t>(bv[3 + i * 8]) << 3) |
                           (static_cast<uint8_t>(bv[4 + i * 8]) << 4) | (static_cast<uint8_t>(bv[5 + i * 8]) << 5) |
                           (static_cast<uint8_t>(bv[6 + i * 8]) << 6) | (static_cast<uint8_t>(bv[7 + i * 8]) << 7);

         result.test_eq(Botan::fmt("byte {} is as expected", i), static_cast<size_t>(b), static_cast<size_t>(bytes[i]));
      }
   };

   return {
      CHECK("empty byte-array",
            [](auto& result) {
               std::vector<uint8_t> bytes;
               result.require("empty buffer", bytes.empty());

               Botan::bitvector bv(bytes);
               result.confirm("empty bit vector", bv.empty());

               auto rendered = bv.to_bytes();
               result.confirm("empty bit vector renders an empty buffer", rendered.empty());
            }),

      CHECK("to_bytes() uses secure_allocator if necessary",
            [](auto& result) {
               Botan::bitvector bv;
               Botan::secure_bitvector sbv;

               auto rbv = bv.to_bytes();
               auto rsbv = sbv.to_bytes();

               result.confirm("ordinary bitvector uses ordinary std::vector",
                              std::is_same_v<std::vector<uint8_t>, decltype(rbv)>);
               result.confirm("secure bitvector uses secure_vector",
                              std::is_same_v<Botan::secure_vector<uint8_t>, decltype(rsbv)>);
            }),

      CHECK("load all bits from byte-array (aligned data)",
            [&](auto& result) {
               Botan::bitvector bv(bytearray);
               validate_bytewise(result, bv, bytearray);

               const auto rbv = bv.to_bytes();
               result.confirm("uint8_t rendered correctly", std::ranges::equal(bytearray, rbv));
            }),

      CHECK("load all bits from byte-array (unaligned blocks)",
            [&](auto& result) {
               std::array<uint8_t, 63> unaligned_bytearray;
               Botan::copy_mem(unaligned_bytearray, std::span{bytearray}.first<unaligned_bytearray.size()>());

               Botan::bitvector bv(unaligned_bytearray);
               validate_bytewise(result, bv, unaligned_bytearray);

               const auto rbv = bv.to_bytes();
               result.confirm("uint8_t rendered correctly", std::ranges::equal(unaligned_bytearray, rbv));
            }),

      CHECK("load bits from byte-array (unaligned data)",
            [&](auto& result) {
               constexpr size_t bits_to_load = 31;
               constexpr size_t bytes_to_load = Botan::ceil_tobytes(bits_to_load);

               Botan::bitvector bv(bytearray, bits_to_load);

               for(size_t i = 0; i < bits_to_load; ++i) {
                  const bool expected = (i == 8) || (i == 17) || (i == 24) || (i == 25);
                  result.test_eq(Botan::fmt("bit {} is correct", i), bv.at(i), expected);
               }

               const auto rbv = bv.to_bytes();
               std::array<uint8_t, bytes_to_load> expected_bytes;
               Botan::copy_mem(expected_bytes, std::span{bytearray}.first<bytes_to_load>());
               expected_bytes.back() &= (uint8_t(1) << (bits_to_load % 8)) - 1;
               result.confirm("uint8_t rendered correctly", std::ranges::equal(expected_bytes, rbv));
            }),

      CHECK("to_bytes(std::span) can handle non-zero out-memory",
            [&](auto& result) {
               constexpr size_t bits_to_load = 33;
               constexpr size_t bytes_to_load = Botan::ceil_tobytes(bits_to_load);

               Botan::bitvector bv(bytearray, bits_to_load);
               bv.set(32);

               std::array<uint8_t, bytes_to_load> out = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
               bv.to_bytes(out);

               result.test_eq_sz("uint8_t rendered correctly", out[4], 0x01);
            }),
   };
}

std::vector<Test::Result> test_bitvector_constant_time_operations(Botan::RandomNumberGenerator&) {
   constexpr Botan::CT::Choice yes = Botan::CT::Choice::yes();
   constexpr Botan::CT::Choice no = Botan::CT::Choice::no();

   return {
      CHECK("conditional XOR, block aligned",
            [&](auto& result) {
               Botan::bitvector bv1(Botan::hex_decode("BAADF00DCAFEBEEF"));
               Botan::secure_bitvector bv2(Botan::hex_decode("CAFEBEEFC001B33F"));
               const auto initial_bv1 = bv1;
               const auto xor_result = bv1 ^ bv2;

               bv1.ct_conditional_xor(no, bv2);
               result.confirm("no change after false condition", bv1 == initial_bv1);

               bv1.ct_conditional_xor(yes, bv2);
               result.confirm("XORed if condition was true", bv1 == xor_result);
            }),

      CHECK("conditional XOR, byte aligned",
            [&](auto& result) {
               Botan::bitvector bv1(Botan::hex_decode("BAADF00DCAFEBEEF42"));
               Botan::secure_bitvector bv2(Botan::hex_decode("CAFEBEEFC001B33F13"));
               const auto initial_bv1 = bv1;
               const auto xor_result = bv1 ^ bv2;

               bv1.ct_conditional_xor(no, bv2);
               result.confirm("no change after false condition", bv1 == initial_bv1);

               bv1.ct_conditional_xor(yes, bv2);
               result.confirm("XORed if condition was true", bv1 == xor_result);
            }),

      CHECK("conditional XOR, no alignment",
            [&](auto& result) {
               Botan::bitvector bv1(Botan::hex_decode("BAADF00DCAFEBEEF42"));
               bv1.push_back(true);
               bv1.push_back(false);
               Botan::secure_bitvector bv2(Botan::hex_decode("CAFEBEEFC001B33F13"));
               bv2.push_back(false);
               bv2.push_back(false);

               const auto initial_bv1 = bv1;
               const auto xor_result = bv1 ^ bv2;

               bv1.ct_conditional_xor(no, bv2);
               result.confirm("no change after false condition", bv1 == initial_bv1);

               bv1.ct_conditional_xor(yes, bv2);
               result.confirm("XORed if condition was true", bv1 == xor_result);
            }),
   };
}

std::vector<Test::Result> test_bitvector_conditional_xor_workload(Botan::RandomNumberGenerator&) {
   Test::Result res("Conditional XOR, Gauss Workload");

   auto rng = Test::new_rng("Conditional XOR, Gauss Workload");

   const size_t matrix_rows = 1664;
   const size_t matrix_columns = 8192;

   std::vector<Botan::bitvector> bitvec_vec;
   bitvec_vec.reserve(matrix_rows);
   for(size_t i = 0; i < matrix_rows; ++i) {
      bitvec_vec.push_back(Botan::bitvector(rng->random_vec(matrix_columns / 8)));
   }

   // Simulate #ops of Gaussian Elimination
   const size_t total_iter = matrix_rows * (3 * matrix_rows - 1) / 2;
   const auto start = Test::timestamp();
   for(size_t i = 0; i < total_iter; ++i) {
      const auto choice = Botan::CT::Choice::from_int(static_cast<uint8_t>(rng->next_byte() % 2));
      bitvec_vec.at(i % matrix_rows).ct_conditional_xor(choice, bitvec_vec.at(rng->next_byte() % matrix_rows));
   }
   res.set_ns_consumed(Test::timestamp() - start);

   res.confirm("Prevent compiler from optimizing away",
               bitvec_vec.at(0).any_vartime() || bitvec_vec.at(0).none_vartime());
   return {res};
}

std::vector<Test::Result> test_bitvector_iterators(Botan::RandomNumberGenerator&) {
   return {
      CHECK("Iterators: range-based for loop",
            [](auto& result) {
               Botan::bitvector bv(6);
               bv.set(0).set(3).set(4);

               for(size_t i = 0; auto& ref : bv) {
                  const bool expected = i == 0 || i == 3 || i == 4;
                  result.test_eq(Botan::fmt("bit {} is as expected", i), ref, expected);
                  ++i;
               }

               for(size_t i = 0; const auto& ref : bv) {
                  const bool expected = i == 0 || i == 3 || i == 4;
                  result.test_eq(Botan::fmt("const bit {} is as expected", i), ref, expected);
                  ++i;
               }

               for(auto ref : bv) {
                  ref = true;
               }

               result.confirm("all bits are set", bv.all_vartime());
            }),

      CHECK("Iterators: bare usage",
            [](auto& result) {
               Botan::bitvector bv(6);
               bv.set(0).set(3).set(4);

               size_t i = 0;
               for(auto itr = bv.begin(); itr != bv.end(); ++itr, ++i) {
                  const bool expected = i == 0 || i == 3 || i == 4;
                  result.test_eq(Botan::fmt("bit {} is as expected", i), *itr, expected);
               }

               i = 0;
               for(auto itr = bv.cbegin(); itr != bv.cend(); itr++, ++i) {
                  const bool expected = i == 0 || i == 3 || i == 4;
                  result.test_eq(Botan::fmt("const bit {} is as expected", i), itr->is_set(), expected);
               }

               i = 6;
               auto ritr = bv.end();
               do {
                  --ritr;
                  --i;
                  const bool expected = i == 0 || i == 3 || i == 4;
                  result.test_eq(Botan::fmt("reverse bit {} is as expected", i), *ritr, expected);
               } while(ritr != bv.begin());

               for(auto itr = bv.begin(); itr != bv.end(); ++itr) {
                  itr->flip();
               }

               i = 0;
               for(auto itr = bv.begin(); itr != bv.end(); ++itr, ++i) {
                  const bool expected = i == 1 || i == 2 || i == 5;
                  result.test_eq(Botan::fmt("flipped bit {} is as expected", i), *itr, expected);
               }
            }),

      CHECK("Iterators: std::distance and std::advance",
            [](auto& result) {
               Botan::bitvector bv(6);
               using signed_size_t = std::make_signed_t<size_t>;

               result.test_is_eq("distance", std::distance(bv.begin(), bv.end()), signed_size_t(6));
               result.test_is_eq("const distance", std::distance(bv.cbegin(), bv.cend()), signed_size_t(6));

               auto b = bv.begin();
               std::advance(b, 3);
               result.test_is_eq("half distance", std::distance(bv.begin(), b), signed_size_t(3));
            }),

      CHECK("Iterators: large bitvector",
            [](auto& result) {
               Botan::bitvector bv(500);

               for(auto itr = bv.begin(); itr != bv.end(); ++itr) {
                  if(std::distance(bv.begin(), itr) % 2 == 0) {
                     itr->set();
                  }
                  if(std::distance(bv.begin(), itr) % 3 == 0) {
                     *itr = true;
                  }
               }

               for(size_t i = 0; const auto& bit : bv) {
                  const bool expected = (i % 2 == 0) || (i % 3 == 0);
                  result.test_eq(Botan::fmt("bit {} is as expected", i), bit, expected);
                  ++i;
               }
            }),

      CHECK("Iterators: satiesfies C++20 concepts",
            [](auto& result) {
               Botan::secure_bitvector bv(42);
               auto ro_itr = bv.cbegin();
               auto rw_itr = bv.begin();

               using ro = decltype(ro_itr);
               using rw = decltype(rw_itr);

               result.confirm("ro input iterator", std::input_iterator<ro>);
               result.confirm("rw input iterator", std::input_iterator<rw>);
               result.confirm("ro is not an output iterator", !std::output_iterator<ro, bool>);
               result.confirm("rw output iterator", std::output_iterator<rw, bool>);
               result.confirm("ro bidirectional iterator", std::bidirectional_iterator<ro>);
               result.confirm("rw bidirectional iterator", std::bidirectional_iterator<rw>);
               result.confirm("ro not a contiguous iterator", !std::contiguous_iterator<ro>);
               result.confirm("rw not a contiguous iterator", !std::contiguous_iterator<rw>);
            }),
   };
}

using TestBitvector = Botan::Strong<Botan::bitvector, struct TestBitvector_>;
using TestSecureBitvector = Botan::Strong<Botan::secure_bitvector, struct TestBitvector_>;
using TestUInt32 = Botan::Strong<uint32_t, struct TestUInt32_>;

std::vector<Test::Result> test_bitvector_strongtype_adapter(Botan::RandomNumberGenerator&) {
   Test::Result result("Bitvector in strong type");

   TestBitvector bv1(33);

   result.confirm("bv1 is not empty", !bv1.empty());
   result.test_eq("bv1 has size 33", bv1.size(), size_t(33));

   bv1[0] = true;
   bv1.at(1) = true;
   bv1.set(2);
   bv1.unset(3);
   bv1.flip(4);
   bv1.push_back(true);
   bv1.push_back(false);
   bv1.pop_back();

   result.confirm("bv1 front is set", bv1.front());
   result.confirm("bv1 back is set", bv1.back());
   result.confirm("bv1 has some one bits", bv1.any_vartime());
   result.confirm("bv1 is not all zero", !bv1.none_vartime());
   result.confirm("bv1 is not all one", !bv1.all_vartime());

   result.confirm("hamming weight of bv1", bv1.has_odd_hamming_weight().as_bool());

   for(size_t i = 0; auto bit : bv1) {
      const bool expected = (i == 0 || i == 1 || i == 2 || i == 4 || i == 33);
      result.confirm(Botan::fmt("bv1 bit {} is set", i), bit == expected);
      ++i;
   }

   bv1.flip();

   for(size_t i = 0; auto bit : bv1) {
      const bool expected = (i == 0 || i == 1 || i == 2 || i == 4 || i == 33);
      result.confirm(Botan::fmt("bv1 bit {} is set", i), bit != expected);
      ++i;
   }

   auto bv2 = bv1.as<TestSecureBitvector>();

   auto bv3 = bv1 | bv2;
   result.confirm("bv3 is a secure_bitvector", std::same_as<Botan::secure_bitvector, decltype(bv3)>);

   auto bv4 = bv2.subvector<TestSecureBitvector>(0, 5);
   result.confirm("bv4 is a TestSecureBitvector", std::same_as<TestSecureBitvector, decltype(bv4)>);

   auto bv5 = bv2.subvector<TestUInt32>(1);
   result.confirm("bv5 is a TestUInt32", std::same_as<TestUInt32, decltype(bv5)>);
   result.test_is_eq<TestUInt32::wrapped_type>("bv5 has expected value", bv5.get(), 0xFFFFFFF4);

   const auto str = bv4.to_string();
   result.test_eq("bv4 to_string", str, "00010");

   return {result};
}

}  // namespace

class BitVector_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;
         auto& rng = Test::rng();

         std::vector<std::function<std::vector<Test::Result>(Botan::RandomNumberGenerator&)>> funcs{
            test_bitvector_bitwise_accessors,
            test_bitvector_capacity,
            test_bitvector_subvector,
            test_bitvector_global_modifiers_and_predicates,
            test_bitvector_binary_operators,
            test_bitvector_serialization,
            test_bitvector_constant_time_operations,
            test_bitvector_conditional_xor_workload,
            test_bitvector_iterators,
            test_bitvector_strongtype_adapter,
         };

         for(const auto& test_func : funcs) {
            auto fn_results = test_func(rng);
            results.insert(results.end(), fn_results.begin(), fn_results.end());
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("utils", "bitvector", BitVector_Tests);

#endif

}  // namespace Botan_Tests
