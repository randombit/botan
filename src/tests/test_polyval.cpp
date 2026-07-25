/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_POLYVAL)
   #include <botan/exceptn.h>
   #include <botan/hex.h>
   #include <botan/internal/polyval.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_POLYVAL)

class Polyval_Tests final : public Text_Based_Test {
   public:
      Polyval_Tests() : Text_Based_Test("polyval.vec", "Key,In,Out") {}

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("POLYVAL");

         const std::vector<uint8_t> key = vars.get_req_bin("Key");
         const std::vector<uint8_t> input = vars.get_req_bin("In");
         const std::vector<uint8_t> expected = vars.get_req_bin("Out");

         Botan::Polyval polyval;
         std::array<uint8_t, 16> digest{};

         result.test_throws<Botan::Invalid_State>("POLYVAL update requires a key", [&]() { polyval.update(input); });
         result.test_throws<Botan::Invalid_State>("POLYVAL final requires a key", [&]() { polyval.final(digest); });

         polyval.set_key(key);

         polyval.update(input);
         polyval.final(digest);
         result.test_bin_eq("POLYVAL one-shot", digest, expected);

         // final resets the state, allowing hashing a further message
         polyval.update(input);
         polyval.final(digest);
         result.test_bin_eq("POLYVAL reused after final", digest, expected);

         // Splitting the input must not affect the result
         const size_t split_step = (input.size() <= 256) ? 1 : 37;
         for(size_t split = 1; split < input.size(); split += split_step) {
            polyval.update(std::span{input}.first(split));
            polyval.update(std::span{input}.subspan(split));
            polyval.final(digest);
            result.test_bin_eq("POLYVAL split input", digest, expected);
         }

         // Nor must feeding the input in small chunks
         for(const size_t chunk : {1, 3, 7, 9, 16, 33}) {
            for(size_t off = 0; off < input.size(); off += chunk) {
               polyval.update(std::span{input}.subspan(off, std::min(chunk, input.size() - off)));
            }
            polyval.final(digest);
            result.test_bin_eq("POLYVAL chunked input", digest, expected);
         }

         return result;
      }

      std::vector<Test::Result> run_final_tests() override {
         Test::Result result("POLYVAL");

         const auto key = Botan::hex_decode("25629347589242761D31F826BA4B757B");
         const auto block = Botan::hex_decode("4F4F95668C83DFB6401762BB2D01A262");

         Botan::Polyval p1;
         Botan::Polyval p2;
         p1.set_key(key);
         p2.set_key(key);

         std::array<uint8_t, 16> d1{};
         std::array<uint8_t, 16> d2{};

         // zero_pad is equivalent to explicitly padding with zeros
         p1.update(std::span{block}.first(12));
         p1.zero_pad();
         p1.final(d1);

         std::vector<uint8_t> padded(block.begin(), block.begin() + 12);
         padded.resize(16);
         p2.update(padded);
         p2.final(d2);
         result.test_bin_eq("zero_pad matches explicit zero padding", d1, d2);

         // zero_pad of block aligned input does nothing
         p1.update(block);
         p1.zero_pad();
         p1.update(block);
         p1.zero_pad();
         p1.final(d1);

         p2.update(block);
         p2.update(block);
         p2.final(d2);
         result.test_bin_eq("zero_pad of aligned input is a no-op", d1, d2);

         return {result};
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("utils", "polyval", Polyval_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
