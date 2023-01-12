/*
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "tests.h"

#include <botan/strong_type.h>
#include <botan/hex.h>

#include <sstream>
#include <algorithm>

namespace Botan_Tests {

namespace {

using Test_Size = Botan::Strong<size_t, struct Test_Size_>;
using Test_Length = Botan::Strong<size_t, struct Test_Length_>;

std::string foo(Test_Size)
   { return "some size"; }
std::string foo(Test_Length)
   { return "some length"; }

using Test_Nonce = Botan::Strong<std::vector<uint8_t>, struct Test_Nonce_>;
using Test_Hash_Name = Botan::Strong<std::string, struct Test_Hash_Name_>;

std::vector<Test::Result> test_strong_type()
   {
   return
      {
      Botan_Tests::CHECK("strong type initialization", [](auto&)
         {
         // default constructor
         Test_Size size1;

         // value initialization
         [[maybe_unused]] Test_Size size2(42);

         // assignment operator
         size1 = Test_Size(42);
         }),

      Botan_Tests::CHECK("value retrieval", [](auto& result)
         {
         Test_Size a(42);
         const Test_Size b(42);

         result.test_is_eq("get()", a.get(), size_t(42));
         result.test_is_eq("const get()", b.get(), size_t(42));
         }),

      Botan_Tests::CHECK("comparisons", [](auto& result)
         {
         const Test_Size a(42);
         const Test_Size b(42);

         result.confirm("equal", a == b);
         result.confirm("lower than", a < Test_Size(1337));
         result.confirm("greater than", Test_Size(1337) > b);
         }),

      Botan_Tests::CHECK("function overloading", [](auto& result)
         {
         result.test_eq("overloading size", foo(Test_Size(42)), "some size");
         result.test_eq("overloading size", foo(Test_Length(42)), "some length");
         }),
      };
   }

std::vector<Test::Result> test_container_strong_type()
   {
   return
      {
      Botan_Tests::CHECK("initialization", [](auto&)
         {
         [[maybe_unused]] Test_Nonce empty_nonce;
         [[maybe_unused]] Test_Nonce short_nonce(Botan::hex_decode("DEADBEEF"));
         }),

      Botan_Tests::CHECK("behaves like a standard container", [](auto& result)
         {
         auto base_nonce = Botan::hex_decode("DEADBEEF");
         auto dataptr = base_nonce.data();
         auto nonce = Test_Nonce(std::move(base_nonce));

         result.test_is_eq("size()", nonce.size(), size_t(4));
         result.confirm("empty()", !nonce.empty());
         result.test_is_eq("data()", nonce.data(), dataptr);

         for(auto& c : nonce)
            { result.confirm("iteration", c > 0); }
         }),

      Botan_Tests::CHECK("binds to a std::span<>", [](auto& result)
         {
         auto get_size = [](std::span<const uint8_t> data)
            { return data.size(); };

         const auto nonce = Test_Nonce(Botan::hex_decode("DEADBEEF"));

         result.test_is_eq("can bind to std::span<>", get_size(nonce), nonce.size());
         }),

      Botan_Tests::CHECK("std::string container", [](auto& result)
         {
         Test_Hash_Name thn("SHA-1");

         std::stringstream stream;
         stream << thn;
         result.test_eq("strong types are streamable", stream.str(), std::string("SHA-1"));
         }),

      Botan_Tests::CHECK("strong types are sortable", [](auto& result)
         {
         using Test_Length_List = Botan::Strong<std::vector<Test_Length>, struct Test_Length_List_>;

         Test_Length_List hashes(
            {
            Test_Length(3),
            Test_Length(1),
            Test_Length(4),
            Test_Length(2)
            });

         // TODO: C++20 - std::ranges::sort
         std::sort(hashes.begin(), hashes.end());

         result.test_eq("1", hashes.get().at(0).get(), size_t(1));
         result.test_eq("2", hashes.get().at(1).get(), size_t(2));
         result.test_eq("3", hashes.get().at(2).get(), size_t(3));
         result.test_eq("4", hashes.get().at(3).get(), size_t(4));
         }),
      };
   }

}

BOTAN_REGISTER_TEST_FN("stream", "strong_type", test_strong_type, test_container_strong_type);

}
