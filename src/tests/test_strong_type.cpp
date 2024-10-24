/*
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "test_rng.h"
#include "tests.h"

#include <botan/hex.h>
#include <botan/rng.h>
#include <botan/secmem.h>
#include <botan/strong_type.h>

#include <algorithm>
#include <array>
#include <sstream>
#include <string>
#include <vector>

namespace Botan_Tests {

namespace {

using Test_Size = Botan::Strong<size_t, struct Test_Size_>;
using Test_Length = Botan::Strong<size_t, struct Test_Length_>;

std::string foo(Test_Size) {
   return "some size";
}

std::string foo(Test_Length) {
   return "some length";
}

using Test_Nonce = Botan::Strong<std::vector<uint8_t>, struct Test_Nonce_>;
using Test_Hash_Name = Botan::Strong<std::string, struct Test_Hash_Name_>;

std::vector<Test::Result> test_strong_type() {
   return {
      CHECK("strong type initialization",
            [](auto&) {
               // default constructor
               Test_Size size1;

               // value initialization
               [[maybe_unused]] Test_Size size2(42);

               // assignment operator
               size1 = Test_Size(42);
            }),

      CHECK("value retrieval",
            [](auto& result) {
               Test_Size a(42);
               const Test_Size b(42);

               result.test_is_eq("get()", a.get(), size_t(42));
               result.test_is_eq("const get()", b.get(), size_t(42));
            }),

      CHECK("comparisons",
            [](auto& result) {
               const Test_Size a(42);
               const Test_Size b(42);

               result.confirm("equal", a == b);
               result.confirm("lower than", a < Test_Size(1337));
               result.confirm("greater than", Test_Size(1337) > b);
            }),

      CHECK("function overloading",
            [](auto& result) {
               result.test_eq("overloading size", foo(Test_Size(42)), "some size");
               result.test_eq("overloading size", foo(Test_Length(42)), "some length");
            }),

      CHECK("is_strong_type",
            [](auto& result) {
               result.confirm("strong type (int)", Botan::is_strong_type_v<Test_Size>);
               result.confirm("no strong type (int)", !Botan::is_strong_type_v<size_t>);
               result.confirm("strong type (vector)", Botan::is_strong_type_v<Test_Nonce>);
               result.confirm("no strong type (vector)", !Botan::is_strong_type_v<std::vector<uint8_t>>);
               result.confirm("strong type (const vector)", Botan::is_strong_type_v<const Test_Nonce>);
               result.confirm("no strong type (const vector)", !Botan::is_strong_type_v<const std::vector<uint8_t>>);
            }),
   };
}

std::vector<Test::Result> test_container_strong_type() {
   return {
      CHECK("initialization",
            [](auto&) {
               [[maybe_unused]] Test_Nonce empty_nonce;
               [[maybe_unused]] Test_Nonce short_nonce(Botan::hex_decode("DEADBEEF"));
            }),

      CHECK("behaves like a standard container",
            [](auto& result) {
               auto base_nonce = Botan::hex_decode("DEADBEEF");
               auto dataptr = base_nonce.data();
               auto nonce = Test_Nonce(std::move(base_nonce));

               result.test_is_eq("size()", nonce.size(), size_t(4));
               result.confirm("empty()", !nonce.empty());
               result.test_is_eq("data()", nonce.data(), dataptr);

               for(auto& c : nonce) {
                  result.confirm("iteration", c > 0);
               }
            }),

      CHECK(
         "container concepts are satisfied",
         [](auto& result) {
            using Test_Map = Botan::Strong<std::map<int, std::string>, struct Test_Map_>;
            using Test_Array = Botan::Strong<std::array<uint64_t, 32>, struct Test_Array_>;

            result.confirm("Test_Nonce is container", Botan::concepts::container<Test_Nonce>);
            result.confirm("Test_Array is container", Botan::concepts::container<Test_Array>);
            result.confirm("Test_Map is container", Botan::concepts::container<Test_Map>);
            result.confirm("Test_Size is not container", !Botan::concepts::container<Test_Size>);

            result.confirm("Test_Nonce is contiguous_container", Botan::concepts::contiguous_container<Test_Nonce>);
            result.confirm("Test_Array is contiguous_container", Botan::concepts::contiguous_container<Test_Array>);
            result.confirm("Test_Map is not contiguous_container", !Botan::concepts::contiguous_container<Test_Map>);
            result.confirm("Test_Size is not contiguous_container", !Botan::concepts::contiguous_container<Test_Size>);

            result.confirm("Test_Nonce is resizable_container", Botan::concepts::resizable_container<Test_Nonce>);
            result.confirm("Test_Array is not resizable_container", !Botan::concepts::resizable_container<Test_Array>);
            result.confirm("Test_Map is not resizable_container", !Botan::concepts::resizable_container<Test_Map>);
            result.confirm("Test_Size is not resizable_container", !Botan::concepts::resizable_container<Test_Size>);
         }),

      CHECK("binds to a std::span<>",
            [](auto& result) {
               auto get_size = [](std::span<const uint8_t> data) { return data.size(); };

               const auto nonce = Test_Nonce(Botan::hex_decode("DEADBEEF"));

               result.test_is_eq("can bind to std::span<>", get_size(nonce), nonce.size());
            }),

      CHECK("std::string container",
            [](auto& result) {
               Test_Hash_Name thn("SHA-1");

               std::stringstream stream;
               stream << thn;
               result.test_eq("strong types are streamable", stream.str(), std::string("SHA-1"));
            }),

      CHECK("strong types are sortable",
            [](auto& result) {
               using Test_Length_List = Botan::Strong<std::vector<Test_Length>, struct Test_Length_List_>;

               Test_Length_List hashes({Test_Length(3), Test_Length(1), Test_Length(4), Test_Length(2)});

               // TODO: C++20 - std::ranges::sort
               std::sort(hashes.begin(), hashes.end());

               result.test_eq("1", hashes.get().at(0).get(), size_t(1));
               result.test_eq("2", hashes.get().at(1).get(), size_t(2));
               result.test_eq("3", hashes.get().at(2).get(), size_t(3));
               result.test_eq("4", hashes.get().at(3).get(), size_t(4));
            }),

      CHECK("byte-container strong types can be randomly generated",
            [](auto& result) {
               using Test_Buffer = Botan::Strong<std::vector<uint8_t>, struct Test_Buffer_>;
               using Test_Secure_Buffer = Botan::Strong<Botan::secure_vector<uint8_t>, struct Test_Secure_Buffer_>;
               using Test_Fixed_Array = Botan::Strong<std::array<uint8_t, 4>, struct Test_Fixed_Array_>;

               Fixed_Output_RNG rng;
               const auto e1 = Botan::hex_decode("deadbeef");
               const auto e2 = Botan::hex_decode("baadcafe");
               const auto e3 = Botan::hex_decode("baadf00d");
               rng.add_entropy(e1.data(), e1.size());
               rng.add_entropy(e2.data(), e2.size());
               rng.add_entropy(e3.data(), e3.size());

               auto tb = rng.random_vec<Test_Buffer>(4);
               auto tsb = rng.random_vec<Test_Secure_Buffer>(4);
               Test_Fixed_Array tfa;
               rng.random_vec(tfa);

               result.test_eq("generated expected output", tb.get(), Botan::hex_decode("deadbeef"));
               result.test_eq("generated expected secure output", tsb.get(), Botan::hex_decode_locked("baadcafe"));
               result.test_eq("generated expected fixed output",
                              std::vector(tfa.begin(), tfa.end()),
                              Botan::hex_decode("baadf00d"));
            }),

      CHECK("bounds-checked accessors are exposed opportunistically",
            [](Test::Result& result) {
               using Test_Array = Botan::Strong<std::array<uint8_t, 4>, struct Test_Array_>;
               using Test_Map = Botan::Strong<std::map<int, std::string>, struct Test_Map_>;
               using Test_Vector = Botan::Strong<std::vector<uint8_t>, struct Test_Vector_>;

               Test_Array a({1, 2, 3, 4});
               result.test_is_eq<uint8_t>("at() returns 3", a.at(2), 3);
               result.test_throws("at() throws on out-of-bounds access", [&a]() { a.at(4); });

               Test_Map m({{1, "one"}, {2, "two"}, {3, "three"}});
               result.test_is_eq<std::string>("at() returns 'two'", m.at(2), "two");
               result.test_throws("at() throws on out-of-bounds access", [&m]() { m.at(4); });

               Test_Vector v({1, 2, 3, 4});
               result.test_is_eq<uint8_t>("at() returns 2", v.at(1), 2);
               result.test_throws("at() throws on out-of-bounds access", [&v]() { v.at(4); });
            }),

      CHECK("subscript accessors are exposed",
            [](Test::Result& result) {
               using Test_Array = Botan::Strong<std::array<uint8_t, 4>, struct Test_Array_>;
               using Test_Map = Botan::Strong<std::map<int, std::string>, struct Test_Map_>;
               using Test_Vector = Botan::Strong<std::vector<uint8_t>, struct Test_Vector_>;

               Test_Array a({1, 2, 3, 4});
               result.test_is_eq<uint8_t>("[] returns 3", a[2], 3);

               Test_Map m({{1, "one"}, {2, "two"}, {3, "three"}});
               result.test_is_eq<std::string>("[] returns 'two'", m[2], "two");

               Test_Vector v({1, 2, 3, 4});
               result.test_is_eq<uint8_t>("[] returns 2", v[1], 2);
            }),
   };
}

std::vector<Test::Result> test_integer_strong_type() {
   using StrongInt = Botan::Strong<int, struct StrongInt_>;
   using StrongIntWithPodArithmetics = Botan::Strong<int, struct StrongInt_, Botan::EnableArithmeticWithPlainNumber>;

   return {
      CHECK("comparison operators with POD are always allowed",
            [](auto& result) {
               StrongInt i(42);

               result.confirm("i ==", i == 42);
               result.confirm("i !=", i != 0);
               result.confirm("i >", i > 41);
               result.confirm("i >= 1", i >= 41);
               result.confirm("i >= 2", i >= 42);
               result.confirm("i <", i < 43);
               result.confirm("i <= 1", i <= 43);
               result.confirm("i <= 2", i <= 42);

               result.confirm("== i", 42 == i);
               result.confirm("!= i", 0 != i);
               result.confirm("> i", 43 > i);
               result.confirm(">= 1 i", 43 >= i);
               result.confirm(">= 2 i", 42 >= i);
               result.confirm("< i", 41 < i);
               result.confirm("<= 1 i", 41 <= i);
               result.confirm("<= 2 i", 42 <= i);
            }),

      CHECK("increment/decrement are always allowed",
            [](auto& result) {
               StrongInt i(42);

               result.confirm("i++", i++ == 42);
               result.confirm("i post-incremented", i == 43);
               result.confirm("++i", ++i == 44);
               result.confirm("i pre-incremented", i == 44);

               result.confirm("i--", i-- == 44);
               result.confirm("i post-decremented", i == 43);
               result.confirm("--i", --i == 42);
               result.confirm("i pre-decremented", i == 42);
            }),

      CHECK("comparison operators with Strong<>",
            [](auto& result) {
               StrongInt i(42);
               StrongInt i42(42);
               StrongInt i41(41);
               StrongInt i43(43);
               StrongInt i0(0);

               result.confirm("==", i == i42);
               result.confirm("!=", i != i0);
               result.confirm(">", i > i41);
               result.confirm(">= 1", i >= i41);
               result.confirm(">= 2", i >= i42);
               result.confirm("<", i < i43);
               result.confirm("<= 1", i <= i43);
               result.confirm("<= 2", i <= i42);
            }),

      CHECK("arithmetics with Strong<>",
            [](auto& result) {
               StrongInt i(42);
               StrongInt i2(2);
               StrongInt i4(4);
               StrongInt i12(12);

               result.confirm("+", i + i == 84);
               result.confirm("-", i - i == 0);
               result.confirm("*", i * i == 1764);
               result.confirm("/", i / i == 1);
               result.confirm("^", (i ^ i) == 0);
               result.confirm("&", (i & i) == 42);
               result.confirm("|", (i | i) == 42);
               result.confirm(">>", (i >> i2) == 10);
               result.confirm("<<", (i << i2) == 168);

               result.confirm("+=", (i += i2) == 44);
               result.confirm("-=", (i -= i2) == 42);
               result.confirm("*=", (i *= i2) == 84);
               result.confirm("/=", (i /= i2) == 42);
               result.confirm("^=", (i ^= i2) == 40);
               result.confirm("&=", (i &= i12) == 8);
               result.confirm("|=", (i |= i2) == 10);
               result.confirm("<<=", (i <<= i2) == 40);
               result.confirm(">>=", (i >>= i4) == 2);
            }),

      CHECK("arithmetics with POD",
            [](auto& result) {
               StrongIntWithPodArithmetics i(42);
               StrongIntWithPodArithmetics i2(2);

               result.confirm("i +", i + 1 == 43);
               result.confirm("i -", i - 1 == 41);
               result.confirm("i *", i * 2 == 84);
               result.confirm("i /", i / 2 == 21);
               result.confirm("i ^", (i ^ 10) == 32);
               result.confirm("i &", (i & 15) == 10);
               result.confirm("i |", (i | 4) == 46);
               result.confirm("i >>", (i >> 2) == 10);
               result.confirm("i <<", (i << 2) == 168);

               result.confirm("+ i", 1 + i == 43);
               result.confirm("- i", 1 - i == -41);
               result.confirm("* i", 2 * i == 84);
               result.confirm("/ i", 84 / i == 2);
               result.confirm("^ i", (10 ^ i) == 32);
               result.confirm("& i", (15 & i) == 10);
               result.confirm("| i", (4 | i) == 46);
               result.confirm(">> i", (4 >> i2) == 1);
               result.confirm("<< i", (2 << i2) == 8);

               result.confirm("i +=", (i += 2) == 44);
               result.confirm("i -=", (i -= 2) == 42);
               result.confirm("i *=", (i *= 2) == 84);
               result.confirm("i /=", (i /= 2) == 42);
               result.confirm("i ^=", (i ^= 2) == 40);
               result.confirm("i &=", (i &= 12) == 8);
               result.confirm("i |=", (i |= 2) == 10);
               result.confirm("i <<=", (i <<= 2) == 40);
               result.confirm("i >>=", (i >>= 4) == 2);
            }),

      CHECK("arithmetics with POD is still Strong<>",
            [](auto& result) {
               StrongIntWithPodArithmetics i(42);
               StrongIntWithPodArithmetics i2(2);

               result.confirm("i +", Botan::is_strong_type_v<decltype(i + 1)>);
               result.confirm("i -", Botan::is_strong_type_v<decltype(i - 1)>);
               result.confirm("i *", Botan::is_strong_type_v<decltype(i * 2)>);
               result.confirm("i /", Botan::is_strong_type_v<decltype(i / 2)>);
               result.confirm("i ^", Botan::is_strong_type_v<decltype((i ^ 10))>);
               result.confirm("i &", Botan::is_strong_type_v<decltype((i & 15))>);
               result.confirm("i |", Botan::is_strong_type_v<decltype((i | 4))>);
               result.confirm("i >>", Botan::is_strong_type_v<decltype((i >> 2))>);
               result.confirm("i <<", Botan::is_strong_type_v<decltype((i << 2))>);

               result.confirm("+ i", Botan::is_strong_type_v<decltype(1 + i)>);
               result.confirm("- i", Botan::is_strong_type_v<decltype(1 - i)>);
               result.confirm("* i", Botan::is_strong_type_v<decltype(2 * i)>);
               result.confirm("/ i", Botan::is_strong_type_v<decltype(84 / i)>);
               result.confirm("^ i", Botan::is_strong_type_v<decltype((10 ^ i))>);
               result.confirm("& i", Botan::is_strong_type_v<decltype((15 & i))>);
               result.confirm("| i", Botan::is_strong_type_v<decltype((4 | i))>);
               result.confirm(">> i", Botan::is_strong_type_v<decltype((4 >> i2))>);
               result.confirm("<< i", Botan::is_strong_type_v<decltype((2 << i2))>);

               result.confirm("i +=", Botan::is_strong_type_v<decltype(i += 2)>);
               result.confirm("i -=", Botan::is_strong_type_v<decltype(i -= 2)>);
               result.confirm("i *=", Botan::is_strong_type_v<decltype(i *= 2)>);
               result.confirm("i /=", Botan::is_strong_type_v<decltype(i /= 2)>);
               result.confirm("i ^=", Botan::is_strong_type_v<decltype(i ^= 2)>);
               result.confirm("i &=", Botan::is_strong_type_v<decltype(i &= 12)>);
               result.confirm("i |=", Botan::is_strong_type_v<decltype(i |= 2)>);
               result.confirm("i <<=", Botan::is_strong_type_v<decltype(i <<= 2)>);
               result.confirm("i >>=", Botan::is_strong_type_v<decltype(i >>= 4)>);
            }),
   };
}

using Test_Foo = Botan::Strong<std::vector<uint8_t>, struct Test_Foo_>;
using Test_Bar = Botan::Strong<std::vector<uint8_t>, struct Test_Bar_>;

[[maybe_unused]] int test_strong_helper(const Botan::StrongSpan<Test_Foo>&) {
   return 0;
}

[[maybe_unused]] int test_strong_helper(const Botan::StrongSpan<const Test_Foo>&) {
   return 1;
}

[[maybe_unused]] int test_strong_helper(const Botan::StrongSpan<Test_Bar>&) {
   return 2;
}

Test::Result test_strong_span() {
   Test::Result result("StrongSpan<>");

   const Test_Foo foo(Botan::hex_decode("DEADBEEF"));
   result.test_is_eq("binds to StrongSpan<const Test_Foo>", test_strong_helper(foo), 1);

   Test_Bar bar(Botan::hex_decode("CAFECAFE"));
   result.test_is_eq("binds to StrongSpan<Test_Bar>", test_strong_helper(bar), 2);

   Botan::StrongSpan<const Test_Foo> span(foo);

   result.confirm("underlying type is uint8_t", std::is_same_v<decltype(span)::value_type, uint8_t>);
   result.confirm("strong type is a contiguous buffer", Botan::concepts::contiguous_container<decltype(foo)>);
   result.confirm("strong type is a contiguous strong type buffer",
                  Botan::concepts::contiguous_strong_type<decltype(foo)>);
   result.confirm("strong span is not a contiguous buffer", !Botan::concepts::contiguous_container<decltype(span)>);
   result.confirm("strong span is not a contiguous strong type buffer",
                  !Botan::concepts::contiguous_strong_type<decltype(span)>);

   return result;
}

std::vector<Test::Result> test_wrapping_unwrapping() {
   using Strong_String = Botan::Strong<std::string, struct Strong_String_>;
   using Strong_Unique = Botan::Strong<std::unique_ptr<std::string>, struct Strong_Unique_>;

   using namespace std::string_literals;

   return {
      CHECK("generically wrapping an object into a strong type",
            [&](Test::Result& result) {
               const std::string expl("explicit creation"s);
               std::string rval("rvalue-ref creation"s);
               auto stt_copy = Botan::wrap_strong_type<Strong_String>(expl);
               auto stt_implicit = Botan::wrap_strong_type<Strong_String>("implicit conversion from const char*");
               auto stt_rvalue_ref = Botan::wrap_strong_type<Strong_String>(std::move(rval));
               auto stt_rvalue = Botan::wrap_strong_type<Strong_String>("rvalue creation from std::string (literal)"s);

               result.test_eq("stt_copy", stt_copy.get(), "explicit creation");
               result.test_eq("stt_implicit", stt_implicit.get(), "implicit conversion from const char*");
               result.test_eq("stt_rvalue_ref", stt_rvalue_ref.get(), "rvalue-ref creation");
               result.test_eq("stt_rvalue", stt_rvalue.get(), "rvalue creation from std::string (literal)");

               // unique_ptr does not support copy construction and prohibits
               // implicit conversion from a raw pointer of its wrapped type.
               auto rval_ptr = std::make_unique<std::string>("rvalue creation from ptr");
               auto stt_implicit_ptr =
                  Botan::wrap_strong_type<Strong_Unique>(new std::string("implicit creation from ptr"));
               auto stt_rvalue_ptr = Botan::wrap_strong_type<Strong_Unique>(std::move(rval_ptr));

               result.test_eq("stt_implicit_ptr", *stt_implicit_ptr.get(), "implicit creation from ptr");
               result.test_eq("stt_rvalue_ptr", *stt_rvalue_ptr.get(), "rvalue creation from ptr");
            }),

      CHECK("generically wrapping a strong type from itself",
            [&](Test::Result& result) {
               const Strong_String stt("wrapped");
               Strong_String stt_rval("wrapped and moved");

               auto stt_copy = Botan::wrap_strong_type<Strong_String>(stt);
               auto stt_move = Botan::wrap_strong_type<Strong_String>(std::move(stt_rval));
               auto stt_inplace = Botan::wrap_strong_type<Strong_String>(Strong_String("inplace"));

               result.test_eq("stt_copy", stt_copy.get(), "wrapped");
               result.test_eq("stt_move", stt_move.get(), "wrapped and moved");
               result.test_eq("stt_inplace", stt_inplace.get(), "inplace");

               Strong_Unique stt_ptr(std::make_unique<std::string>("wrapped ptr"));

               auto stt_ptr_move = Botan::wrap_strong_type<Strong_Unique>(std::move(stt_ptr));

               result.test_eq("stt_ptr_move", *stt_ptr_move.get(), "wrapped ptr");
            }),

      CHECK("unwrapping a strong type wisely chooses return reference type",
            [&](Test::Result& result) {
               Strong_String stt("wrapped");
               const Strong_String stt_const("const wrapped");

               using lvalue_ref = decltype(Botan::unwrap_strong_type(stt));
               result.confirm("unpack() on non-const is an lvalue reference", std::is_lvalue_reference_v<lvalue_ref>);
               result.confirm("unpack() on non-const is a non-const lvalue reference",
                              !std::is_const_v<std::remove_reference_t<lvalue_ref>>);
               result.confirm(
                  "wrapped_type on non-const lvalue strong type",
                  std::same_as<Botan::strong_type_wrapped_type<decltype(stt)>, std::remove_cvref_t<lvalue_ref>>);

               using const_lvalue_ref = decltype(Botan::unwrap_strong_type(stt_const));
               result.confirm("unpack() on const is an lvalue reference", std::is_lvalue_reference_v<const_lvalue_ref>);
               result.confirm("unpack() on const is a const lvalue reference",
                              std::is_const_v<std::remove_reference_t<const_lvalue_ref>>);
               result.confirm(
                  "wrapped_type on const lvalue strong type",
                  std::same_as<Botan::strong_type_wrapped_type<decltype(stt_const)>, std::remove_cvref_t<lvalue_ref>>);

               using lvalue = decltype(Botan::unwrap_strong_type(std::move(stt)));
               result.confirm("unpack() on rvalue reference is an rvalue reference",
                              std::is_rvalue_reference_v<lvalue>);
               result.confirm("unpack() on rvalue is a non-const rvalue reference",
                              !std::is_const_v<std::remove_reference_t<lvalue>>);
               result.confirm(
                  "wrapped_type on rvalue reference strong type",
                  std::same_as<Botan::strong_type_wrapped_type<decltype(std::move(stt))>, std::remove_cvref_t<lvalue>>);

               using lvalue2 = decltype(Botan::unwrap_strong_type(Strong_String("wrapped rvalue")));
               result.confirm("unpack() on rvalue is an rvalue reference", std::is_rvalue_reference_v<lvalue2>);
               result.confirm("unpack() on rvalue is a non-const rvalue reference",
                              !std::is_const_v<std::remove_reference_t<lvalue2>>);
               result.confirm("wrapped_type on rvalue strong type",
                              std::same_as<Botan::strong_type_wrapped_type<decltype(Strong_String("wrapped rvalue"))>,
                                           std::remove_cvref_t<lvalue2>>);
            }),

      CHECK(
         "unwrapping a non-strong type does not alter return reference type",
         [](Test::Result& result) {
            std::string stt("wrapped");
            const std::string stt_const("const wrapped");

            using lvalue_ref = decltype(Botan::unwrap_strong_type(stt));
            result.confirm("unpack() on non-const is an lvalue reference", std::is_lvalue_reference_v<lvalue_ref>);
            result.confirm("unpack() on non-const is a non-const lvalue reference",
                           !std::is_const_v<std::remove_reference_t<lvalue_ref>>);
            result.confirm(
               "wrapped_type on lvalue non-strong type",
               std::same_as<Botan::strong_type_wrapped_type<decltype(stt)>, std::remove_cvref_t<lvalue_ref>>);

            using const_lvalue_ref = decltype(Botan::unwrap_strong_type(stt_const));
            result.confirm("unpack() on const is an lvalue reference", std::is_lvalue_reference_v<const_lvalue_ref>);
            result.confirm("unpack() on const is a const lvalue reference",
                           std::is_const_v<std::remove_reference_t<const_lvalue_ref>>);
            result.confirm("wrapped_type on const lvalue non-strong type",
                           std::same_as<Botan::strong_type_wrapped_type<decltype(stt_const)>,
                                        std::remove_cvref_t<const_lvalue_ref>>);

            using lvalue = decltype(Botan::unwrap_strong_type(std::move(stt)));
            result.confirm("unpack() on rvalue reference is an rvalue reference", std::is_rvalue_reference_v<lvalue>);
            result.confirm("unpack() on rvalue is a non-const rvalue reference",
                           !std::is_const_v<std::remove_reference_t<lvalue>>);
            result.confirm(
               "wrapped_type on rvalue reference non-strong type",
               std::same_as<Botan::strong_type_wrapped_type<decltype(std::move(stt))>, std::remove_cvref_t<lvalue>>);

            using lvalue2 = decltype(Botan::unwrap_strong_type(std::string("rvalue")));
            result.confirm("unpack() on rvalue reference is an rvalue reference", std::is_rvalue_reference_v<lvalue2>);
            result.confirm("unpack() on rvalue is a non-const rvalue reference",
                           !std::is_const_v<std::remove_reference_t<lvalue2>>);
            result.confirm("wrapped_type on rvalue non-strong type",
                           std::same_as<Botan::strong_type_wrapped_type<decltype(std::string("rvalue"))>,
                                        std::remove_cvref_t<lvalue2>>);
         }),

      CHECK("generically unwrapping an object from a strong type",
            [&](Test::Result& result) {
               Strong_String stt("wrapped lvalue");
               Strong_String stt_move("wrapped lvalue to be moved");
               const Strong_String const_stt("wrapped const lvalue");

               auto& unwrapped_stt = Botan::unwrap_strong_type(stt);
               auto& unwrapped_const_stt = Botan::unwrap_strong_type(const_stt);
               auto unwrapped_rvalue = Botan::unwrap_strong_type(std::move(stt_move));
               auto unwrapped_rvalue2 = Botan::unwrap_strong_type(Strong_String("wrapped rvalue"));

               result.test_eq("unwrapped_stt", unwrapped_stt, "wrapped lvalue");
               result.test_eq("unwrapped_const_stt", unwrapped_const_stt, "wrapped const lvalue");
               result.test_eq("unwrapped_rvalue", unwrapped_rvalue, "wrapped lvalue to be moved");
               result.test_eq("unwrapped_rvalue2", unwrapped_rvalue2, "wrapped rvalue");

               Strong_Unique stt_ptr(std::make_unique<std::string>("wrapped ptr"));
               Strong_Unique stt_ptr_move(std::make_unique<std::string>("wrapped ptr to be moved"));

               auto& unwrapped_ptr = Botan::unwrap_strong_type(stt_ptr);
               auto unwrapped_ptr_move = Botan::unwrap_strong_type(std::move(stt_ptr_move));
               auto unwrapped_ptr_rvalue =
                  Botan::unwrap_strong_type(std::make_unique<std::string>("wrapped ptr rvalue"));

               result.test_eq("unwrapped_ptr", *unwrapped_ptr, "wrapped ptr");
               result.test_eq("unwrapped_ptr_move", *unwrapped_ptr_move, "wrapped ptr to be moved");
               result.test_eq("unwrapped_ptr_rvalue", *unwrapped_ptr_rvalue, "wrapped ptr rvalue");
            }),

      CHECK("generically unwrapping an object that isn't a strong type",
            [&](Test::Result& result) {
               std::string stt("wrapped lvalue");
               std::string stt_move("wrapped lvalue to be moved");
               const std::string const_stt("wrapped const lvalue");

               auto& unwrapped_stt = Botan::unwrap_strong_type(stt);
               auto& unwrapped_const_stt = Botan::unwrap_strong_type(const_stt);
               auto unwrapped_rvalue = Botan::unwrap_strong_type(std::move(stt_move));
               auto unwrapped_rvalue2 = Botan::unwrap_strong_type(std::string("wrapped rvalue"));

               result.test_eq("unwrapped_stt", unwrapped_stt, "wrapped lvalue");
               result.test_eq("unwrapped_const_stt", unwrapped_const_stt, "wrapped const lvalue");
               result.test_eq("unwrapped_rvalue", unwrapped_rvalue, "wrapped lvalue to be moved");
               result.test_eq("unwrapped_rvalue2", unwrapped_rvalue2, "wrapped rvalue");

               std::unique_ptr<std::string> stt_ptr(std::make_unique<std::string>("wrapped ptr"));
               std::unique_ptr<std::string> stt_ptr_move(std::make_unique<std::string>("wrapped ptr to be moved"));

               auto& unwrapped_ptr = Botan::unwrap_strong_type(stt_ptr);
               auto unwrapped_ptr_move = Botan::unwrap_strong_type(std::move(stt_ptr_move));
               auto unwrapped_ptr_rvalue =
                  Botan::unwrap_strong_type(std::make_unique<std::string>("wrapped ptr rvalue"));

               result.test_eq("unwrapped_ptr", *unwrapped_ptr, "wrapped ptr");
               result.test_eq("unwrapped_ptr_move", *unwrapped_ptr_move, "wrapped ptr to be moved");
               result.test_eq("unwrapped_ptr_rvalue", *unwrapped_ptr_rvalue, "wrapped ptr rvalue");
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("utils",
                       "strong_type",
                       test_strong_type,
                       test_container_strong_type,
                       test_integer_strong_type,
                       test_strong_span,
                       test_wrapping_unwrapping);

}  // namespace Botan_Tests
