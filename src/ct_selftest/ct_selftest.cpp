/*
 * Basic tests for the CT::poison annotations.
 * Some of those are expected to fail, because they deliberately
 * branch on secret memory.
 *
 * (C) 2024 Jack Lloyd
 * (C) 2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <iostream>

#include <botan/hex.h>
#include <botan/system_rng.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>

#include <functional>
#include <map>

namespace {

void test_conditional_jump_on_poisoned_data(Botan::RandomNumberGenerator& rng) {
   const uint8_t poisoned_byte = rng.next_byte();
   Botan::CT::poison(poisoned_byte);

   // Performing a conditional jump on a "secret" value would introduce
   // a potential side channel.
   if(poisoned_byte == 0) {
      std::cout << "I may or may not be printed." << std::endl;
   }
}

void test_array_access_on_poisoned_data(Botan::RandomNumberGenerator& rng) {
   const uint8_t poisoned_byte = rng.next_byte();
   const auto lookup_table = rng.random_array<1 << (sizeof(poisoned_byte) * 8)>();
   Botan::CT::poison(poisoned_byte);

   // Accessing memory with a "secret" value would introduce a potential side channel.
   std::cout << lookup_table[poisoned_byte] << std::endl;
}

void test_conditional_jump_on_transitively_poisoned_data(Botan::RandomNumberGenerator& rng) {
   const uint8_t poisoned_byte = rng.next_byte();
   const uint8_t innocent_byte = rng.next_byte();
   Botan::CT::poison(poisoned_byte);

   const uint8_t derived_byte = poisoned_byte ^ innocent_byte;

   // Performing a conditional jump on a value that was calculated from a "secret" value
   // would (in general) introduce a potential side channel.
   if(derived_byte == 0) {
      std::cout << "I may or may not be printed." << std::endl;
   }
}

void test_array_access_on_transitively_poisoned_data(Botan::RandomNumberGenerator& rng) {
   const uint8_t poisoned_byte = rng.next_byte();
   const uint8_t innocent_byte = rng.next_byte();
   Botan::CT::poison(poisoned_byte);

   const uint8_t derived_byte = poisoned_byte ^ innocent_byte;
   const auto lookup_table = rng.random_array<1 << (sizeof(derived_byte) * 8)>();

   // Performing a memory access on a value that was calculated from a "secret" value
   // would introduce a potential side channel.
   std::cout << lookup_table[poisoned_byte] << std::endl;
}

void test_unpoisen_transitively_poisoned_data(Botan::RandomNumberGenerator& rng) {
   const uint8_t poisoned_byte = rng.next_byte();
   const uint8_t innocent_byte = rng.next_byte();
   Botan::CT::poison(poisoned_byte);

   const uint8_t derived_byte = poisoned_byte ^ innocent_byte;
   Botan::CT::unpoison(derived_byte);

   // This is okay, because the value is not secret anymore.
   if(derived_byte == 0) {
      std::cout << "I may or may not be printed." << std::endl;
   }
}

void test_poisoned_and_cleared_data(Botan::RandomNumberGenerator& rng) {
   const uint8_t poisoned_byte = rng.next_byte();
   Botan::CT::poison(poisoned_byte);

   uint8_t derived_byte = poisoned_byte & 0x00;
   derived_byte ^= rng.next_byte();  // To prevent the compiler from optimizing the whole thing away.

   // This is okay, because the value was cleared (i.e. is not secret-dependent anymore)
   if(derived_byte == 0) {
      std::cout << "I may or may not be printed." << std::endl;
   }
}

void test_conditional_branch_on_unpoisoned_bit(Botan::RandomNumberGenerator& rng) {
   const auto poisoned_byte = rng.next_byte();
   Botan::CT::poison(poisoned_byte);

   // Clears the last poisoned bit (effectively unpoisoning it)
   // All other bits are still poisoned (aka secret dependent)
   uint8_t derived_byte = poisoned_byte & 0b11111110;

   derived_byte ^= rng.next_byte();  // To prevent the compiler from optimizing the whole thing away.

   // This conditional jump is okay, because the jump does not depend on the "secret" value.
   if((derived_byte & 0b00000001) == 0) {
      std::cout << "I may or may not be printed." << std::endl;
   }
}

void test_conditional_branch_on_poisoned_bit(Botan::RandomNumberGenerator& rng) {
   const auto poisoned_byte = rng.next_byte();
   Botan::CT::poison(poisoned_byte);

   // Clears all but one poisoned bit (effectively unpoisoning them)
   // One bit remains poisoned (aka secret dependent)
   uint8_t derived_byte = poisoned_byte & 0b00000010;

   derived_byte ^= rng.next_byte() & 0b00000010;  // To prevent the compiler from optimizing the whole thing away.

   // This conditional jump is not okay, because the jump depends on the "secret" value.
   if((derived_byte & 0b00000010) == 0) {
      std::cout << "I may or may not be printed." << std::endl;
   }
}

void test_clang_conditional_jump_on_bare_metal_ct_mask(Botan::RandomNumberGenerator& rng) {
   const auto poisoned_byte = rng.next_byte();
   Botan::CT::poison(poisoned_byte);

   std::array<uint8_t, 16> output_bytes;
   std::memset(output_bytes.data(), 0x42, sizeof(output_bytes));

   // This mimicks what went wrong in Kyber's secret message expansion
   // that was found by PQShield in Kyber's reference implementation and
   // was fixed in https://github.com/randombit/botan/pull/4107.
   //
   // Certain versions of Clang, namely 15, 16, 17 and 18 (maybe more) with
   // specific optimization flags (-Os, -O1, -O2 -fno-vectorize, ...) do
   // realize that `poisoned_mask` can only ever be all-zero or all-one and
   // conditionally jump over the loop execution below.
   //
   // See: https://pqshield.com/pqshield-plugs-timing-leaks-in-kyber-ml-kem-to-improve-pqc-implementation-maturity/
   const uint8_t poisoned_mask = -static_cast<uint8_t>(poisoned_byte & 1);
   for(size_t i = 0; i < sizeof(output_bytes); ++i) {
      output_bytes[i] &= poisoned_mask;
   }

   // Unpoison output_bytes to safely print them. The actual side channel
   // happened above.
   Botan::CT::unpoison(output_bytes);
   std::cout << Botan::hex_encode(output_bytes) << std::endl;
}

void test_poison_range(Botan::RandomNumberGenerator& rng) {
   auto range = rng.random_array<16>();
   Botan::CT::poison(range);

   // conditional jump on a "secret" value in a range
   if((range.back() & 0xF0) != 0) {
      std::cout << "I may or may not be printed." << std::endl;
   }
}

void test_unpoison_range(Botan::RandomNumberGenerator& rng) {
   auto range = rng.random_array<16>();
   Botan::CT::poison(range);

   // "calculations" on poisoned memory are fine
   std::vector<uint8_t> result;
   std::copy(range.begin(), range.end(), std::back_inserter(result));

   // unpoison the result range
   Botan::CT::unpoison(result);

   // the result range is not poisoned and conditional jumps should be fine
   if((result.back() & 0xF0) != 0) {
      std::cout << "I may or may not be printed." << std::endl;
   }
}

void test_scoped_poison_inner(Botan::RandomNumberGenerator& rng) {
   const auto poisoned_byte = rng.next_byte();

   const auto scope = Botan::CT::scoped_poison(poisoned_byte);

   // conditional jump on a "secret" value in a range
   if(poisoned_byte != 0) {
      std::cout << "I may or may not be printed." << std::endl;
   }
}

void test_scoped_poison_outer(Botan::RandomNumberGenerator& rng) {
   auto poisoned_byte = rng.next_byte();

   {
      const auto scope = Botan::CT::scoped_poison(poisoned_byte);
      poisoned_byte += rng.next_byte();
   }

   // conditional jump on a value that should be unpoisoned
   // by the closing curly brace above
   if(poisoned_byte != 0) {
      std::cout << "I may or may not be printed." << std::endl;
   }
}

// Similar to test_clang_conditional_jump_on_bare_metal_ct_mask() but with Botan's CT::Masks.
// Should not fail, because CT::Mask uses CT::value_barrier().
void regression_test_conditional_jump_in_ct_mask(Botan::RandomNumberGenerator& rng) {
   const auto poisoned_byte = rng.next_byte();
   Botan::CT::poison(poisoned_byte);

   std::array<uint8_t, 16> output_bytes;
   std::memset(output_bytes.data(), 0x42, sizeof(output_bytes));

   // Before the introduction of CT::value_barrier, this did generate a
   // conditional jump when compiled with clang using certain compiler
   // optimizations. See the test case above for further details.
   auto poisoned_mask = Botan::CT::Mask<uint8_t>::expand(poisoned_byte & 1);
   for(size_t i = 0; i < sizeof(output_bytes); ++i) {
      output_bytes[i] = poisoned_mask.select(output_bytes[i], 0);
   }

   Botan::CT::unpoison(output_bytes);
   std::cout << Botan::hex_encode(output_bytes) << std::endl;
}

void cond_jump_on_shifted_out_secret_data(Botan::RandomNumberGenerator& rng) {
   const auto rand = rng.random_array<8>();
   Botan::CT::poison(rand);

   std::vector<uint32_t> secret_data(8);

   // Only the i least significant bits are actually secret dependent
   // the rest is just initialized zero bits and not secret.
   for(size_t i = 0; i < 8; ++i) {
      secret_data[i] = rand[i] & ((1 << (i)) - 1);
   }

   // This conditional jump is okay, because the jump does not depend on the
   // "secret" bits that are shifted out in every loop iteration.
   for(size_t i = 0; i < 8; ++i) {
      if((secret_data[i] >> i) != 0) {
         std::cout << "I won't ever be printed." << std::endl;
      }
   }
}

struct Test {
      bool expect_failure;
      bool needs_special_conditions;
      std::function<void(Botan::RandomNumberGenerator&)> test;
};

constexpr bool SHOULD_FAIL = true;
constexpr bool SHOULD_SUCCEED = false;

/// Marks tests that don't produce the expected results without a special
/// constellation of external conditions (e.g. a specific compiler version
/// and/or specific optimization flags).
constexpr bool REQUIRES_SPECIAL_CONDITIONS = true;

/// Tests that should always expose the expected behavior, regardless of
/// compiler or other external factors.
constexpr bool IS_GENERIC = false;

void print_help(std::string_view path) {
   std::cerr << "Usage: valgrind [...] " << path << " [testname]" << std::endl;
   std::cerr << "Usage: " << path << " [--list|--list-special|--help]" << std::endl;
   std::cerr << "By design, this can only run one test at a time. "
             << "Some tests are expected to cause CT::poison warnings and crashes." << std::endl;
}

void list_tests(const std::map<std::string, Test>& tests) {
   std::cout << "fail?\tspecial?\ttest name\n\n";

   auto str = [](bool value) { return value ? "true" : "false"; };

   for(const auto& [name, test_info] : tests) {
      std::cout << Botan::fmt(
         "{}\t{}\t{}\n", str(test_info.expect_failure), str(test_info.needs_special_conditions), name);
   }
}

}  // namespace

int main(int argc, char* argv[]) {
   // clang-format off
   const std::map<std::string, Test> available_tests = {
      {"poisoned_conditional_jump",            {SHOULD_FAIL,    IS_GENERIC,                  test_conditional_jump_on_poisoned_data}},
      {"poisoned_memory_lookup",               {SHOULD_FAIL,    IS_GENERIC,                  test_array_access_on_poisoned_data}},
      {"transitive_poisoned_conditional_jump", {SHOULD_FAIL,    IS_GENERIC,                  test_conditional_jump_on_transitively_poisoned_data}},
      {"transitive_poisoned_memory_lookup",    {SHOULD_FAIL,    IS_GENERIC,                  test_array_access_on_transitively_poisoned_data}},
      {"unpoison_transitive_poisoned",         {SHOULD_SUCCEED, IS_GENERIC,                  test_unpoisen_transitively_poisoned_data}},
      {"poisoned_and_cleared",                 {SHOULD_SUCCEED, IS_GENERIC,                  test_poisoned_and_cleared_data}},
      {"conditional_jump_on_unpoisoned_bit",   {SHOULD_SUCCEED, IS_GENERIC,                  test_conditional_branch_on_unpoisoned_bit}},
      {"conditional_jump_on_poisoned_bit",     {SHOULD_FAIL,    IS_GENERIC,                  test_conditional_branch_on_poisoned_bit}},
      {"regression_test_clang_vs_ct_mask",     {SHOULD_SUCCEED, IS_GENERIC,                  regression_test_conditional_jump_in_ct_mask}},
      {"poison_range",                         {SHOULD_FAIL,    IS_GENERIC,                  test_poison_range}},
      {"unpoison_range",                       {SHOULD_SUCCEED, IS_GENERIC,                  test_unpoison_range}},
      {"scoped_poison_inner",                  {SHOULD_FAIL,    IS_GENERIC,                  test_scoped_poison_inner}},
      {"scoped_poison_outer",                  {SHOULD_SUCCEED, IS_GENERIC,                  test_scoped_poison_outer}},
      {"clang_vs_bare_metal_ct_mask",          {SHOULD_FAIL,    REQUIRES_SPECIAL_CONDITIONS, test_clang_conditional_jump_on_bare_metal_ct_mask}},
      {"cond_jump_on_shifted_out_secret_data", {SHOULD_SUCCEED, IS_GENERIC,                  cond_jump_on_shifted_out_secret_data}},
   };
   // clang-format on

   if(argc != 2) {
      print_help(argv[0]);
      return 1;
   }

   const std::string argument(argv[1]);
   if(argument == "--help") {
      print_help(argv[0]);
      return 0;
   }

   if(argument == "--list") {
      list_tests(available_tests);
      return 0;
   }

   const auto test = available_tests.find(argument);
   if(test == available_tests.end()) {
      std::cerr << "Unknown test: " << argument << std::endl;
      return 1;
   }

#if !defined(BOTAN_CT_POISON_ENABLED)
   std::cout << "The CT::poison API is disabled in this build, this test won't do anything useful\n"
             << "Configure with a compatible checker (e.g. --with-valgrind) to make the magic happen." << std::endl;
   return 1;
#else
   if(!Botan::CT::poison_has_effect()) {
      std::cerr << "This test must run with a tool populating the CT::poison (e.g. valgrind)." << std::endl;
      return 1;
   }

   try {
      test->second.test(Botan::system_rng());
   } catch(const std::exception& ex) {
      std::cerr << "Caught exception: " << ex.what() << std::endl;
      return 1;
   }

   return 0;
#endif
}
