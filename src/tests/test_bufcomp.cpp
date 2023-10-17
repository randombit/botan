/**
 * (C) 2023 Jack Lloyd
 *     2023 Philippe Lieser - Rohde & Schwarz Cybersecurity
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "tests.h"

#include <botan/buf_comp.h>
#include <botan/mem_ops.h>
#include <botan/secmem.h>
#include <botan/strong_type.h>

#include <array>
#include <string>
#include <vector>

namespace Botan_Tests {

namespace {

class Test_Buf_Comp final : public Botan::Buffered_Computation {
   public:
      Test_Buf_Comp(Test::Result& res) : m_result(res), m_counter(0) {}

      size_t output_length() const override { return sizeof(m_counter); }

      void add_data(std::span<const uint8_t> input) override {
         if(m_result.test_eq("input length as expected", input.size(), size_t(5))) {
            m_result.confirm("input[0] == 'A'", input[0] == 'A');
            m_result.confirm("input[0] == 'B'", input[1] == 'B');
            m_result.confirm("input[0] == 'C'", input[2] == 'C');
            m_result.confirm("input[0] == 'D'", input[3] == 'D');
            m_result.confirm("input[0] == 'E'", input[4] == 'E');
         }

         ++m_counter;
      }

      void final_result(std::span<uint8_t> out) override {
         const uint8_t* counter = reinterpret_cast<const uint8_t*>(&m_counter);
         std::copy(counter, counter + sizeof(m_counter), out.begin());
      }

      size_t counter() const { return m_counter; }

   private:
      Test::Result& m_result;
      size_t m_counter;
};

void check(Test::Result& result, std::span<const uint8_t> produced, size_t expected) {
   uint8_t expected_bytes[sizeof(size_t)];
   std::memcpy(expected_bytes, &expected, sizeof(expected));
   result.test_eq("", "result is correct", produced.data(), produced.size(), expected_bytes, sizeof(expected_bytes));
}

using TestStdVector = Botan::Strong<std::vector<uint8_t>, struct TestStdVector_>;
using TestSecureVector = Botan::Strong<Botan::secure_vector<uint8_t>, struct TestSecureVector_>;

Test::Result test_buffered_computation_convenience_api() {
   // This is mainly to test compilability of the various container
   // types as in and out parameters. Hence, we refrain from checking
   // the 'final' output everywhere.
   Test::Result result("Convenience API of Buffered_Computation");

   Test_Buf_Comp t(result);

   constexpr auto test_string = "ABCDE";
   const std::vector<uint8_t> test_vector = {'A', 'B', 'C', 'D', 'E'};
   const std::array<uint8_t, 5> test_array = {'A', 'B', 'C', 'D', 'E'};
   const TestStdVector test_strong_type(test_vector);

   Botan::secure_vector<uint8_t> out_sv;
   std::vector<uint8_t> out_vec;
   std::array<uint8_t, sizeof(std::size_t)> out_arr;
   TestSecureVector out_strong_type;

   // update with basic string-ish types
   t.update("ABCDE");
   t.update(test_string);
   t.update(std::string(test_string));

   // update with container types
   t.update(test_vector);
   t.update(test_array);
   t.update(test_strong_type);

   // final returning result
   out_sv = t.final();
   out_vec = t.final_stdvec();
   out_strong_type = t.final<TestSecureVector>();

   // final using out param
   t.final(out_sv);
   t.final(out_arr);
   t.final(out_strong_type);

   check(result, out_strong_type, 6);

   // test resizing of final out param
   out_vec.clear();
   t.final(out_vec);
   out_vec.resize(t.output_length() * 2);
   t.final(out_vec);
   result.test_int_eq("out vector is resized", out_vec.size(), t.output_length());

   check(result, out_vec, 6);

   // process with basic string-ish types as input
   out_sv = t.process(test_string);
   out_sv = t.process(std::string(test_string));

   check(result, out_sv, 8);

   // process with container types as input
   out_sv = t.process(test_vector);
   out_sv = t.process(test_array);

   check(result, out_sv, 10);

   // process with specific in and out type
   out_vec = t.process<std::vector<uint8_t>>(test_vector);
   const auto out_strong_sec_vec = t.process<TestSecureVector>(test_vector);

   check(result, out_strong_sec_vec, 12);

   return result;
}

BOTAN_REGISTER_TEST_FN("base", "bufcomp_base_api", test_buffered_computation_convenience_api);

}  // namespace

}  // namespace Botan_Tests
