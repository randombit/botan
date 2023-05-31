/*
 * (C) 2023 Jack Lloyd
 * (C) 2023 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "tests.h"

#include <botan/internal/stl_util.h>

namespace Botan_Tests {

namespace {

using StrongBuffer = Botan::Strong<std::vector<uint8_t>, struct StrongBuffer_>;

std::vector<Test::Result> test_buffer_slicer() {
   return {
      CHECK("Empty BufferSlicer",
            [](auto& result) {
               const std::vector<uint8_t> buffer(0);
               Botan::BufferSlicer s(buffer);
               result.confirm("empty slicer has no remaining bytes", s.remaining() == 0);
               result.confirm("empty slicer is empty()", s.empty());
               result.confirm("empty slicer can take() 0 bytes", s.take(0).empty());

               result.test_throws("empty slicer cannot emit bytes", [&]() { s.take(1); });
               result.test_throws("empty slicer cannot skip bytes", [&]() { s.skip(1); });
               result.test_throws("empty slicer cannot copy bytes", [&]() { s.copy_as_vector(1); });
            }),

      CHECK("Read from BufferSlicer",
            [](auto& result) {
               const std::vector<uint8_t> buffer{'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
               Botan::BufferSlicer s(buffer);

               result.test_eq("non-empty slicer has remaining bytes", s.remaining(), buffer.size());
               result.confirm("non-empty slicer is not empty()", !s.empty());

               const auto hello = s.take(5);
               result.require("has 5 bytes", hello.size() == 5);
               result.test_is_eq("took hello", hello[0], uint8_t('h'));
               result.test_is_eq("took hello", hello[1], uint8_t('e'));
               result.test_is_eq("took hello", hello[2], uint8_t('l'));
               result.test_is_eq("took hello", hello[3], uint8_t('l'));
               result.test_is_eq("took hello", hello[4], uint8_t('o'));

               result.test_eq("remaining bytes", s.remaining(), 6);

               s.skip(1);
               result.test_eq("remaining bytes", s.remaining(), 5);

               const auto wor = s.copy_as_vector(3);
               result.require("has 3 bytes", wor.size() == 3);
               result.test_is_eq("took wor...", wor[0], uint8_t('w'));
               result.test_is_eq("took wor...", wor[1], uint8_t('o'));
               result.test_is_eq("took wor...", wor[2], uint8_t('r'));
               result.test_eq("remaining bytes", s.remaining(), 2);

               std::vector<uint8_t> ld(2);
               s.copy_into(ld);
               result.test_is_eq("took ...ld", ld[0], uint8_t('l'));
               result.test_is_eq("took ...ld", ld[1], uint8_t('d'));

               result.confirm("empty", s.empty());
               result.test_eq("nothing remaining", s.remaining(), 0);

               result.test_throws("empty slicer cannot emit bytes", [&]() { s.take(1); });
               result.test_throws("empty slicer cannot skip bytes", [&]() { s.skip(1); });
               result.test_throws("empty slicer cannot copy bytes", [&]() { s.copy_as_vector(1); });
            }),

      CHECK("Strong type support",
            [](auto& result) {
               const Botan::secure_vector<uint8_t> secure_buffer{'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
               Botan::BufferSlicer s(secure_buffer);

               auto span1 = s.take(1);
               auto span2 = s.take<StrongBuffer>(2);
               auto vec1 = s.copy<StrongBuffer>(2);
               auto vec2 = s.copy_as_vector(2);
               auto vec3 = s.copy_as_secure_vector(2);
               StrongBuffer vec4(s.remaining());
               s.copy_into(vec4);

               const auto reproduce = Botan::concat_as<std::vector<uint8_t>>(span1, span2, vec1, vec2, vec3, vec4);
               result.test_eq("sliced into various types", reproduce, secure_buffer);
            }),
   };
}

std::vector<Test::Result> test_buffer_stuffer() {
   return {
      CHECK("Empty BufferStuffer",
            [](auto& result) {
               std::vector<uint8_t> empty_buffer;
               Botan::BufferStuffer s(empty_buffer);

               result.test_eq("has no capacity", s.remaining_capacity(), 0);
               result.confirm("is immediately full", s.full());
               result.confirm("can next() 0 bytes", s.next(0).empty());

               result.test_throws("cannot next() anything", [&]() { s.next(1); });
               result.test_throws("cannot append bytes", [&]() {
                  std::vector<uint8_t> some_bytes(42);
                  s.append(some_bytes);
               });
            }),

      CHECK("Fill BufferStuffer",
            [](auto& result) {
               std::vector<uint8_t> sink(11);
               Botan::BufferStuffer s(sink);

               result.test_eq("has some capacity", s.remaining_capacity(), sink.size());
               result.confirm("is not full", !s.full());

               auto n1 = s.next(5);
               result.require("got requested bytes", n1.size() == 5);
               n1[0] = 'h';
               n1[1] = 'e';
               n1[2] = 'l';
               n1[3] = 'l';
               n1[4] = 'o';

               auto n2 = s.next<StrongBuffer>(3);
               result.require("got requested bytes", n2.size() == 3);

               n2.get()[0] = ' ';
               n2.get()[1] = 'w';
               n2.get()[2] = 'o';

               result.test_eq("has 3 bytes remaining", s.remaining_capacity(), 3);

               std::vector<uint8_t> rld{'r', 'l', 'd'};
               s.append(rld);

               result.test_eq("has 0 bytes remaining", s.remaining_capacity(), 0);
               result.confirm("is full", s.full());

               result.test_throws("cannot next() anything", [&]() { s.next(1); });
               result.test_throws("cannot append bytes", [&]() {
                  std::vector<uint8_t> some_bytes(42);
                  s.append(some_bytes);
               });
            }),
   };
}

BOTAN_REGISTER_TEST_FN("utils", "buffer_utilities", test_buffer_slicer, test_buffer_stuffer);

}  // namespace

}  // namespace Botan_Tests
