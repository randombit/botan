/*
 * (C) 2023 Jack Lloyd
 * (C) 2023-2024 René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "tests.h"

#include <botan/concepts.h>
#include <botan/mem_ops.h>
#include <botan/internal/alignment_buffer.h>
#include <botan/internal/buffer_transformer.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

#include <array>

namespace Botan_Tests {

namespace {

template <typename T>
std::vector<uint8_t> v(const T& container) {
   return {container.begin(), container.end()};
}

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
               const std::vector<uint8_t> buffer{'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', ' ', '!'};
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

               result.test_eq("remaining bytes", s.remaining(), 8);

               s.skip(1);
               result.test_eq("remaining bytes", s.remaining(), 7);

               const auto wor = s.copy_as_vector(3);
               result.require("has 3 bytes", wor.size() == 3);
               result.test_is_eq("took wor...", wor[0], uint8_t('w'));
               result.test_is_eq("took wor...", wor[1], uint8_t('o'));
               result.test_is_eq("took wor...", wor[2], uint8_t('r'));
               result.test_eq("remaining bytes", s.remaining(), 4);

               std::vector<uint8_t> ld(2);
               s.copy_into(ld);
               result.test_is_eq("took ...ld", ld[0], uint8_t('l'));
               result.test_is_eq("took ...ld", ld[1], uint8_t('d'));
               result.test_eq("remaining bytes", s.remaining(), 2);

               s.skip(1);
               result.test_eq("remaining bytes", s.remaining(), 1);

               const auto exclaim = s.take<1>();
               result.test_is_eq("took ...!", exclaim[0], uint8_t('!'));
               result.confirm("has static extent", decltype(exclaim)::extent != std::dynamic_extent);
               result.confirm("static extent is 1", decltype(exclaim)::extent == 1);

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

               const auto reproduce = Botan::concat<std::vector<uint8_t>>(span1, span2, vec1, vec2, vec3, vec4);
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
               std::vector<uint8_t> sink(13);
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

               result.test_eq("has 5 bytes remaining", s.remaining_capacity(), 5);

               std::vector<uint8_t> rld{'r', 'l', 'd'};
               s.append(rld);

               result.test_eq("has 2 bytes remaining", s.remaining_capacity(), 2);

               auto n3 = s.next<2>();
               result.require("got requested bytes", n3.size() == 2);
               result.require("is static extent", decltype(n3)::extent != std::dynamic_extent);
               result.require("static extent is 2", decltype(n3)::extent == 2);

               n3[0] = ' ';
               n3[1] = '!';

               result.confirm("is full", s.full());

               result.test_throws("cannot next() anything", [&]() { s.next(1); });
               result.test_throws("cannot append bytes", [&]() {
                  std::vector<uint8_t> some_bytes(42);
                  s.append(some_bytes);
               });

               std::string final_string(Botan::cast_uint8_ptr_to_char(sink.data()), sink.size());
               result.test_eq("final buffer is as expected", final_string, "hello world !");
            }),
   };
}

std::vector<Test::Result> test_alignment_buffer() {
   std::array<uint8_t, 32> data = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                                   17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
   std::array<uint8_t, 16> first_half_data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
   std::array<uint8_t, 16> second_half_data = {17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

   return {
      CHECK("Fresh Alignment Buffer",
            [](auto& result) {
               Botan::AlignmentBuffer<uint8_t, 32> b;
               result.test_eq("size()", b.size(), 32);
               result.test_eq("elements_in_buffer()", b.elements_in_buffer(), 0);
               result.test_eq("elements_until_alignment()", b.elements_until_alignment(), 32);
               result.confirm("in_alignment()", b.in_alignment());
               result.confirm("!ready_to_consume()", !b.ready_to_consume());
            }),

      CHECK("Fill Alignment Buffer",
            [=](auto& result) {
               Botan::AlignmentBuffer<uint8_t, 32> b;

               b.append(first_half_data);

               result.test_eq("size()", b.size(), 32);
               result.test_eq("elements_in_buffer()", b.elements_in_buffer(), 16);
               result.test_eq("elements_until_alignment()", b.elements_until_alignment(), 16);
               result.confirm("!in_alignment()", !b.in_alignment());
               result.confirm("!ready_to_consume()", !b.ready_to_consume());

               b.append(second_half_data);

               result.test_eq("size()", b.size(), 32);
               result.test_eq("elements_in_buffer()", b.elements_in_buffer(), 32);
               result.test_eq("elements_until_alignment()", b.elements_until_alignment(), 0);
               result.confirm("!in_alignment()", !b.in_alignment());
               result.confirm("ready_to_consume()", b.ready_to_consume());
            }),

      CHECK("Consume Alignment Buffer",
            [=](auto& result) {
               Botan::AlignmentBuffer<uint8_t, 32> b;

               b.append(data);

               result.require("ready_to_consume()", b.ready_to_consume());
               const auto out = b.consume();

               result.test_eq("size()", b.size(), 32);
               result.test_eq("elements_in_buffer()", b.elements_in_buffer(), 0);
               result.test_eq("elements_until_alignment()", b.elements_until_alignment(), 32);
               result.confirm("in_alignment()", b.in_alignment());
               result.confirm("!ready_to_consume()", !b.ready_to_consume());

               result.test_is_eq("in == out", v(data), v(out));
            }),

      CHECK("Consume partially filled Alignment Buffer",
            [=](auto& result) {
               Botan::AlignmentBuffer<uint8_t, 32> b;

               result.require("!ready_to_consume()", !b.ready_to_consume());
               const auto out_empty = b.consume_partial();
               result.test_eq("consuming nothing resets buffer", b.elements_in_buffer(), 0);
               result.confirm("consumed empty buffer", out_empty.empty());

               b.append(first_half_data);
               result.require("!ready_to_consume()", !b.ready_to_consume());
               const auto out_half = b.consume_partial();
               result.test_eq("consumed half-data resets buffer", b.elements_in_buffer(), 0);
               result.test_is_eq("half-in == half-out", v(out_half), v(first_half_data));

               b.append(data);
               result.require("ready_to_consume()", b.ready_to_consume());
               const auto out_full = b.consume_partial();
               result.test_eq("consumed full-data resets buffer", b.elements_in_buffer(), 0);
               result.test_is_eq("full-in == full-out", v(out_full), v(data));
            }),

      CHECK("Clear Alignment Buffer",
            [=](auto& result) {
               Botan::AlignmentBuffer<uint8_t, 32> b;

               b.append(first_half_data);

               result.require("elements_in_buffer()", b.elements_in_buffer() == 16);
               b.clear();

               result.test_eq("size()", b.size(), 32);
               result.test_eq("elements_in_buffer()", b.elements_in_buffer(), 0);
               result.test_eq("elements_until_alignment()", b.elements_until_alignment(), 32);
               result.confirm("in_alignment()", b.in_alignment());
               result.confirm("!ready_to_consume()", !b.ready_to_consume());
            }),

      CHECK("Add Zero-Padding to Alignment Buffer",
            [=](auto& result) {
               Botan::AlignmentBuffer<uint8_t, 32> b;

               b.append(first_half_data);

               result.require("elements_in_buffer()", b.elements_in_buffer() == 16);
               b.fill_up_with_zeros();

               result.test_eq("size()", b.size(), 32);
               result.test_eq("elements_in_buffer()", b.elements_in_buffer(), 32);
               result.test_eq("elements_until_alignment()", b.elements_until_alignment(), 0);
               result.confirm("!in_alignment()", !b.in_alignment());
               result.confirm("ready_to_consume()", b.ready_to_consume());

               const auto out = b.consume();

               result.test_is_eq("prefix", v(out.first(16)), v(first_half_data));
               result.test_is_eq("zero-padding", v(out.last(16)), std::vector<uint8_t>(16, 0));

               // Regression test for GH #3734
               // fill_up_with_zeros() must work if called on a full (ready to consume) alignment buffer
               b.append(data);
               result.confirm("ready_to_consume()", b.ready_to_consume());
               result.test_eq("elements_until_alignment()", b.elements_until_alignment(), 0);

               b.fill_up_with_zeros();
               const auto out_without_padding = b.consume();

               result.test_is_eq("no padding", v(out_without_padding), v(data));
            }),

      CHECK("Handle unaligned data in Alignment Buffer (no block-defer)",
            [=](auto& result) {
               Botan::AlignmentBuffer<uint8_t, 32> b;

               Botan::BufferSlicer first_half(first_half_data);
               Botan::BufferSlicer second_half(second_half_data);

               const auto r1 = b.handle_unaligned_data(first_half);
               result.confirm("half a block is not returned", !r1.has_value());
               result.confirm("first input is consumed", first_half.empty());

               result.test_eq("elements_in_buffer()", b.elements_in_buffer(), 16);
               result.test_eq("elements_until_alignment()", b.elements_until_alignment(), 16);
               result.confirm("!in_alignment()", !b.in_alignment());
               result.confirm("!ready_to_consume()", !b.ready_to_consume());

               const auto r2 = b.handle_unaligned_data(second_half);
               result.require("second half completes block", r2.has_value());
               result.confirm("second input is consumed", second_half.empty());

               result.test_eq("elements_in_buffer()", b.elements_in_buffer(), 0);
               result.test_eq("elements_until_alignment()", b.elements_until_alignment(), 32);
               result.confirm("in_alignment()", b.in_alignment());
               result.confirm("!ready_to_consume()", !b.ready_to_consume());

               result.test_is_eq("collected block is correct", v(r2.value()), v(data));
            }),

      CHECK("Aligned data is not buffered unneccesarily (no block-defer)",
            [=](auto& result) {
               Botan::AlignmentBuffer<uint8_t, 32> b;

               Botan::BufferSlicer full_block_1(data);
               const auto r1 = b.handle_unaligned_data(full_block_1);
               result.confirm("aligned data is not buffered", !r1.has_value());
               result.confirm("in_alignment()", b.in_alignment());
               result.confirm("!ready_to_consume()", !b.ready_to_consume());
               result.test_eq("aligned data is not consumed", full_block_1.remaining(), 32);

               Botan::BufferSlicer half_block(first_half_data);
               Botan::BufferSlicer full_block_2(data);
               const auto r2 = b.handle_unaligned_data(half_block);
               result.confirm("unaligned data is buffered", !r2.has_value());
               result.confirm("!in_alignment()", !b.in_alignment());
               result.confirm("!ready_to_consume()", !b.ready_to_consume());
               result.confirm("unaligned data is consumed", half_block.empty());

               const auto r3 = b.handle_unaligned_data(full_block_2);
               result.confirm("collected block is consumed", r3.has_value());
               result.confirm("in_alignment()", b.in_alignment());
               result.confirm("!ready_to_consume()", !b.ready_to_consume());
               result.test_eq("input is consumed until alignment", full_block_2.remaining(), 16);
            }),

      CHECK("Handle unaligned data in Alignment Buffer (with block-defer)",
            [=](auto& result) {
               Botan::AlignmentBuffer<uint8_t, 32, Botan::AlignmentBufferFinalBlock::must_be_deferred> b;

               Botan::BufferSlicer first_half(first_half_data);
               Botan::BufferSlicer second_half(second_half_data);
               Botan::BufferSlicer third_half(first_half_data);

               const auto r1 = b.handle_unaligned_data(first_half);
               result.confirm("half a block is not returned", !r1.has_value());
               result.confirm("first input is consumed", first_half.empty());

               result.test_eq("elements_in_buffer()", b.elements_in_buffer(), 16);
               result.test_eq("elements_until_alignment()", b.elements_until_alignment(), 16);
               result.confirm("!in_alignment()", !b.in_alignment());
               result.confirm("!ready_to_consume()", !b.ready_to_consume());

               const auto r2 = b.handle_unaligned_data(second_half);
               result.require("second half completes block but is not returned", !r2.has_value());
               result.confirm("second input is consumed", second_half.empty());

               result.test_eq("elements_in_buffer()", b.elements_in_buffer(), 32);
               result.test_eq("elements_until_alignment()", b.elements_until_alignment(), 0);
               result.confirm("!in_alignment()", !b.in_alignment());
               result.confirm("ready_to_consume()", b.ready_to_consume());

               const auto r3 = b.handle_unaligned_data(third_half);
               result.require("extra data pushes out block", r3.has_value());
               result.test_eq("third input is not consumed", third_half.remaining(), 16);

               result.test_eq("elements_in_buffer()", b.elements_in_buffer(), 0);
               result.test_eq("elements_until_alignment()", b.elements_until_alignment(), 32);
               result.confirm("in_alignment()", b.in_alignment());
               result.confirm("!ready_to_consume()", !b.ready_to_consume());

               result.test_is_eq("collected block is correct", v(r3.value()), v(data));
            }),

      CHECK("Aligned data is not buffered unneccesarily (with block-defer)",
            [=](auto& result) {
               Botan::AlignmentBuffer<uint8_t, 32, Botan::AlignmentBufferFinalBlock::must_be_deferred> b;

               Botan::BufferSlicer full_block_1(data);
               const auto r1 = b.handle_unaligned_data(full_block_1);
               result.confirm("exactly aligned data is buffered", !r1.has_value());
               result.confirm("!in_alignment()", !b.in_alignment());
               result.confirm("ready_to_consume()", b.ready_to_consume());
               result.confirm("exactly aligned block is consumed", full_block_1.empty());

               Botan::BufferSlicer empty_input({});
               const auto r2 = b.handle_unaligned_data(empty_input);
               result.require("empty input does not push out buffer", !r2.has_value());
               result.confirm("!in_alignment()", !b.in_alignment());
               result.confirm("ready_to_consume()", b.ready_to_consume());

               const uint8_t extra_byte = 1;
               Botan::BufferSlicer one_extra_byte({&extra_byte, 1});
               const auto r3 = b.handle_unaligned_data(one_extra_byte);
               result.require("more data pushes out buffer", r3.has_value());
               result.confirm("in_alignment()", b.in_alignment());
               result.confirm("!ready_to_consume()", !b.ready_to_consume());
               result.test_eq("no input data is consumed", one_extra_byte.remaining(), 1);

               result.test_is_eq("collected block is correct", v(r3.value()), v(data));
            }),

      CHECK("Aligned data passthrough (no block-defer)",
            [=](auto& result) {
               Botan::AlignmentBuffer<uint8_t, 32> b;
               result.require("buffer is in alignment", b.in_alignment());

               Botan::BufferSlicer half_block(first_half_data);
               const auto [s1, r1] = b.aligned_data_to_process(half_block);
               result.confirm("not enough data for alignment processing", s1.empty());
               result.test_eq("not enough data for alignment processing", r1, 0);
               result.test_eq("(short) unaligned data is not consumed", half_block.remaining(), 16);

               const auto more_than_one_block = Botan::concat<std::vector<uint8_t>>(data, first_half_data);
               Botan::BufferSlicer one_and_a_half_block(more_than_one_block);
               const auto [s2, r2] = b.aligned_data_to_process(one_and_a_half_block);
               result.test_eq("data of one block for processing", s2.size(), 32);
               result.test_eq("one block for processing", r2, 1);
               result.test_is_eq(v(s2), v(data));
               result.test_eq("(middle) unaligned data is not consumed", one_and_a_half_block.remaining(), 16);

               const auto two_blocks_data = Botan::concat<std::vector<uint8_t>>(data, data);
               Botan::BufferSlicer two_blocks(two_blocks_data);
               const auto [s3, r3] = b.aligned_data_to_process(two_blocks);
               result.test_eq("data of two block for processing", s3.size(), 64);
               result.test_eq("two blocks for processing", r3, 2);
               result.test_is_eq(v(s3), two_blocks_data);
               result.test_eq("aligned data is fully consumed", two_blocks.remaining(), 0);
            }),

      CHECK("Aligned data blockwise (no block-defer)",
            [=](auto& result) {
               Botan::AlignmentBuffer<uint8_t, 32> b;
               result.require("buffer is in alignment", b.in_alignment());

               Botan::BufferSlicer half_block(first_half_data);
               const auto s1 = b.next_aligned_block_to_process(half_block);
               result.confirm("not enough data for alignment processing", !s1.has_value());
               result.test_eq("(short) unaligned data is not consumed", half_block.remaining(), 16);

               const auto more_than_one_block = Botan::concat<std::vector<uint8_t>>(data, first_half_data);
               Botan::BufferSlicer one_and_a_half_block(more_than_one_block);
               const auto s2 = b.next_aligned_block_to_process(one_and_a_half_block);
               result.require("one block for processing", s2.has_value());
               result.test_eq("data of one block for processing", s2->size(), 32);
               result.test_is_eq(v(s2.value()), v(data));
               result.test_eq("(middle) unaligned data is not consumed", one_and_a_half_block.remaining(), 16);

               const auto two_blocks_data = Botan::concat<std::vector<uint8_t>>(data, data);
               Botan::BufferSlicer two_blocks(two_blocks_data);
               const auto s3_1 = b.next_aligned_block_to_process(two_blocks);
               result.require("first block for processing", s3_1.has_value());
               result.test_eq("data of first block for processing", s3_1->size(), 32);
               result.test_is_eq(v(s3_1.value()), v(data));
               result.test_eq("first block is consumed", two_blocks.remaining(), 32);

               const auto s3_2 = b.next_aligned_block_to_process(two_blocks);
               result.require("second block for processing", s3_2.has_value());
               result.test_eq("data of second block for processing", s3_2->size(), 32);
               result.test_is_eq(v(s3_2.value()), v(data));
               result.test_eq("second block is consumed", two_blocks.remaining(), 0);
            }),

      CHECK("Aligned data passthrough (with block-defer)",
            [=](auto& result) {
               Botan::AlignmentBuffer<uint8_t, 32, Botan::AlignmentBufferFinalBlock::must_be_deferred> b;
               result.require("buffer is in alignment", b.in_alignment());

               Botan::BufferSlicer half_block(first_half_data);
               const auto [s1, r1] = b.aligned_data_to_process(half_block);
               result.confirm("not enough data for alignment processing", s1.empty());
               result.test_eq("not enough data for alignment processing", r1, 0);
               result.test_eq("(short) unaligned data is not consumed", half_block.remaining(), 16);

               const auto more_than_one_block = Botan::concat<std::vector<uint8_t>>(data, first_half_data);
               Botan::BufferSlicer one_and_a_half_block(more_than_one_block);
               const auto [s2, r2] = b.aligned_data_to_process(one_and_a_half_block);
               result.test_eq("data of one block for processing", s2.size(), 32);
               result.test_eq("one block for processing", r2, 1);
               result.test_is_eq(v(s2), v(data));
               result.test_eq("(middle) unaligned data is not consumed", one_and_a_half_block.remaining(), 16);

               const auto two_blocks_data = Botan::concat<std::vector<uint8_t>>(data, data);
               Botan::BufferSlicer two_blocks(two_blocks_data);
               const auto [s3, r3] = b.aligned_data_to_process(two_blocks);
               result.test_eq("data of first block for processing", s3.size(), 32);
               result.test_eq("one block for processing", r3, 1);
               result.test_is_eq(v(s3), v(data));
               result.test_eq("aligned data is partially consumed", two_blocks.remaining(), 32);
            }),

      CHECK("Aligned data blockwise (with block-defer)",
            [=](auto& result) {
               Botan::AlignmentBuffer<uint8_t, 32, Botan::AlignmentBufferFinalBlock::must_be_deferred> b;
               result.require("buffer is in alignment", b.in_alignment());

               Botan::BufferSlicer half_block(first_half_data);
               const auto s1 = b.next_aligned_block_to_process(half_block);
               result.confirm("not enough data for alignment processing", !s1.has_value());
               result.test_eq("(short) unaligned data is not consumed", half_block.remaining(), 16);

               const auto more_than_one_block = Botan::concat<std::vector<uint8_t>>(data, first_half_data);
               Botan::BufferSlicer one_and_a_half_block(more_than_one_block);
               const auto s2 = b.next_aligned_block_to_process(one_and_a_half_block);
               result.require("one block for processing", s2.has_value());
               result.test_eq("data of one block for processing", s2->size(), 32);
               result.test_is_eq(v(s2.value()), v(data));
               result.test_eq("(middle) unaligned data is not consumed", one_and_a_half_block.remaining(), 16);

               const auto two_blocks_data = Botan::concat<std::vector<uint8_t>>(data, data);
               Botan::BufferSlicer two_blocks(two_blocks_data);
               const auto s3_1 = b.next_aligned_block_to_process(two_blocks);
               result.require("first block for processing", s3_1.has_value());
               result.test_eq("data of first block for processing", s3_1->size(), 32);
               result.test_is_eq(v(s3_1.value()), v(data));
               result.test_eq("first block is consumed", two_blocks.remaining(), 32);

               const auto s3_2 = b.next_aligned_block_to_process(two_blocks);
               result.confirm("second block is not passed through", !s3_2.has_value());
               result.test_eq("second block is not consumed", two_blocks.remaining(), 32);
            }),
   };
}

std::vector<Test::Result> test_concat() {
   return {
      CHECK("empty concat",
            [](Test::Result& result) {
               // only define a dynamic output type, but no input to be concat'ed
               const auto empty1 = Botan::concat<std::vector<uint8_t>>();
               result.confirm("empty concat 1", empty1.empty());

               // pass an empty input buffer to be concat'ed
               const auto empty2 = Botan::concat(std::vector<uint8_t>());
               result.confirm("empty concat 2", empty2.empty());

               // pass multiple empty input buffers to be concat'ed
               const auto empty3 = Botan::concat(std::vector<uint8_t>(), Botan::secure_vector<uint8_t>());
               result.confirm("empty concat 3", empty3.empty());

               // pass multiple empty input buffers to be concat'ed without auto-detection of the output buffer
               const auto empty4 = Botan::concat<std::array<uint8_t, 0>>(
                  std::vector<uint8_t>(), std::array<uint8_t, 0>(), Botan::secure_vector<uint8_t>());
               result.confirm("empty concat 4", empty4.empty());
            }),

      CHECK(
         "auto-detected output type",
         [](Test::Result& result) {
            // define a static output type without any input parameters
            const auto t0 = Botan::concat<std::array<uint8_t, 0>>();
            result.confirm("type 0", std::is_same_v<std::array<uint8_t, 0>, std::remove_cvref_t<decltype(t0)>>);

            // define a dynamic output type without any input parameters
            const auto t1 = Botan::concat<std::vector<uint8_t>>();
            result.confirm("type 1", std::is_same_v<std::vector<uint8_t>, std::remove_cvref_t<decltype(t1)>>);

            // pass a single dynamic input buffer and auto-detect result type
            const auto t2 = Botan::concat(std::vector<uint8_t>());
            result.confirm("type 2", std::is_same_v<std::vector<uint8_t>, std::remove_cvref_t<decltype(t2)>>);

            // pass multiple dynamic input buffers and auto-detect result type
            const auto t3 = Botan::concat(Botan::secure_vector<uint8_t>(), std::vector<uint8_t>());
            result.confirm("type 3", std::is_same_v<Botan::secure_vector<uint8_t>, std::remove_cvref_t<decltype(t3)>>);

            // pass a mixture of dynamic and static input buffers and auto-detect result type
            const auto t4 =
               Botan::concat(std::vector<uint8_t>(), std::array<uint8_t, 0>(), Botan::secure_vector<uint8_t>());
            result.confirm("type 4", std::is_same_v<std::vector<uint8_t>, std::remove_cvref_t<decltype(t4)>>);

            // pass only static input buffers and auto-detect result type
            const std::array<uint8_t, 5> some_buffer{};
            const auto t5 = Botan::concat(std::array<uint8_t, 1>(), std::array<uint8_t, 3>(), std::span{some_buffer});
            result.confirm("type 5", std::is_same_v<std::array<uint8_t, 9>, std::remove_cvref_t<decltype(t5)>>);
         }),

      CHECK("concatenate",
            [](Test::Result& result) {
               constexpr std::array<uint8_t, 5> a1 = {1, 2, 3, 4, 5};
               const std::vector<uint8_t> v1{6, 7, 8, 9, 10};

               // concatenate a single buffer
               const auto concat0 = Botan::concat<Botan::secure_vector<uint8_t>>(v1);
               result.test_is_eq("concat 0", concat0, {6, 7, 8, 9, 10});

               // concatenate into an dynamically allocated output buffer
               const auto concat1 = Botan::concat<std::vector<uint8_t>>(a1, v1);
               result.test_is_eq("concat 1", concat1, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10});

               // concatenate into a statically sized output buffer
               const auto concat2 = Botan::concat<std::array<uint8_t, 10>>(v1, a1);
               result.test_is_eq("concat 2", concat2, {6, 7, 8, 9, 10, 1, 2, 3, 4, 5});

               // concatenate into a statically sized output buffer, that is auto-detected
               const auto concat3 = Botan::concat(a1, std::span<const uint8_t, 5>(v1));
               result.test_is_eq("concat 3", concat3, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10});
               result.confirm("correct type 3",
                              std::is_same_v<std::array<uint8_t, 10>, std::remove_cvref_t<decltype(concat3)>>);

               // concatenate into a statically sized output buffer, that is auto-detected, at compile time
               constexpr auto concat4 = Botan::concat(a1, a1);
               result.test_is_eq("concat 4", concat4, {1, 2, 3, 4, 5, 1, 2, 3, 4, 5});
               result.confirm("correct type 4",
                              std::is_same_v<std::array<uint8_t, 10>, std::remove_cvref_t<decltype(concat4)>>);
            }),

      CHECK("dynamic length-check",
            [](Test::Result& result) {
               std::vector<uint8_t> v1{1, 2, 3, 4, 5};
               std::vector<uint8_t> v2{6, 7, 8, 9, 10};

               result.test_throws("concatenate into a statically sized type with insufficient space",
                                  [&]() { Botan::concat<std::array<uint8_t, 4>>(v1, v2); });
               result.test_throws("concatenate into a statically sized type with too much space",
                                  [&]() { Botan::concat<std::array<uint8_t, 20>>(v1, v2); });
            }),

      CHECK("concatenate strong types",
            [](Test::Result& result) {
               using StrongV = Botan::Strong<std::vector<uint8_t>, struct StrongV_>;
               using StrongA = Botan::Strong<std::array<uint8_t, 4>, struct StrongA_>;

               StrongV v1(std::vector<uint8_t>{1, 2, 3, 4, 5});
               StrongA a2;
               a2[0] = 6;
               a2[1] = 7;
               a2[2] = 8;
               a2[3] = 9;

               // concat strong types into a verbatim type
               auto concat1 = Botan::concat<std::vector<uint8_t>>(v1, a2);
               result.test_is_eq("concat 1", concat1, {1, 2, 3, 4, 5, 6, 7, 8, 9});

               // concat strong types into a dynamically allocated strong type
               auto concat2 = Botan::concat<StrongV>(a2, v1);
               result.test_is_eq("concat 2", concat2.get(), {6, 7, 8, 9, 1, 2, 3, 4, 5});
            }),
   };
}

std::vector<Test::Result> test_buffer_transformer() {
   return {
      Botan_Tests::CHECK("BufferTransformer basics with arrays",
                         [](Test::Result& result) {
                            const std::array<uint8_t, 8> input = {1, 2, 3, 4, 5, 6, 7, 8};
                            std::array<uint8_t, 8> output = {};

                            Botan::BufferTransformer bt(input, output);
                            auto n1 = bt.next(2);
                            result.require("got requested in bytes (1)", n1.first.size() == 2);
                            result.require("got requested out bytes (1)", n1.second.size() == 2);
                            result.confirm("dynamic extent in", decltype(n1.first)::extent == std::dynamic_extent);
                            result.confirm("dynamic extent out", decltype(n1.second)::extent == std::dynamic_extent);
                            Botan::copy_mem(n1.second, n1.first);

                            auto n2 = bt.next<5>();
                            result.require("got requested in bytes (2)", n2.first.size() == 5);
                            result.require("got requested out bytes (2)", n2.second.size() == 5);
                            result.confirm("static extent in", decltype(n2.first)::extent == 5);
                            result.confirm("static extent out", decltype(n2.second)::extent == 5);
                            Botan::copy_mem(n2.second, n2.first);

                            result.require("not done yet", !bt.done());
                            result.test_eq("has one more bytes", bt.remaining(), 1);

                            bt.skip(1);
                            result.require("done now", bt.done());
                            result.test_eq("has no more bytes", bt.remaining(), 0);

                            result.test_is_eq("output is as expected", output, {1, 2, 3, 4, 5, 6, 7, 0 /* skipped */});

                            result.test_no_throw("empty request is okay (dynamic)", [&] { bt.next(0); });
                            result.test_no_throw("empty request is okay (static)", [&] { bt.next<0>(); });
                            result.test_no_throw("empty skipping request is okay", [&] { bt.skip(0); });
                            result.test_throws("data request will fail (1)", [&] { bt.next(1); });
                            result.test_throws("data request will fail (2)", [&] { bt.next<1>(); });
                            result.test_throws("data skipping request will fail", [&] { bt.skip(1); });
                         }),

      Botan_Tests::CHECK("BufferTransformer basics with vectors",
                         [](Test::Result& result) {
                            const std::vector<uint8_t> input = {1, 2, 3, 4, 5, 6, 7, 8};
                            std::vector<uint8_t> output(input.size());

                            Botan::BufferTransformer bt(input, output);
                            auto n1 = bt.next(4);
                            result.require("got requested in bytes (1)", n1.first.size() == 4);
                            result.require("got requested out bytes (1)", n1.second.size() == 4);
                            result.confirm("dynamic extent in", decltype(n1.first)::extent == std::dynamic_extent);
                            result.confirm("dynamic extent out", decltype(n1.second)::extent == std::dynamic_extent);
                            Botan::copy_mem(n1.second, n1.first);

                            bt.skip(2);
                            result.require("not done yet", !bt.done());
                            result.test_eq("has two more bytes", bt.remaining(), 2);

                            auto n2 = bt.next<2>();
                            result.require("got requested in bytes (2)", n2.first.size() == 2);
                            result.require("got requested out bytes (2)", n2.second.size() == 2);
                            result.confirm("static extent in", decltype(n2.first)::extent == 2);
                            result.confirm("static extent out", decltype(n2.second)::extent == 2);
                            Botan::copy_mem(n2.second, n2.first);

                            result.require("done now", bt.done());
                            result.test_eq("has no more bytes", bt.remaining(), 0);

                            result.test_is_eq("output is as expected", output, {1, 2, 3, 4, 0, 0, 7, 8});

                            result.test_no_throw("empty request is okay (dynamic)", [&] { bt.next(0); });
                            result.test_no_throw("empty request is okay (static)", [&] { bt.next<0>(); });
                            result.test_no_throw("empty skipping request is okay", [&] { bt.skip(0); });
                            result.test_throws("data request will fail (1)", [&] { bt.next(1); });
                            result.test_throws("data request will fail (2)", [&] { bt.next<1>(); });
                            result.test_throws("data skipping request will fail", [&] { bt.skip(1); });
                         }),

      Botan_Tests::CHECK("BufferTransformer::process_blocks_of() with a single block",
                         [](Test::Result& result) {
                            const auto in =
                               Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
                            std::vector<uint8_t> out(in.size());

                            Botan::BufferTransformer bt(in, out);
                            bt.process_blocks_of<8>(
                               [](std::span<const uint8_t, 8> i, std::span<uint8_t, 8> o) { Botan::copy_mem(o, i); });

                            result.require("done now", bt.done());
                            result.test_is_eq("output is as expected", out, in);
                         }),

      Botan_Tests::CHECK("concept strictly_monotonic_decreasing",
                         [](Test::Result& result) {
                            result.confirm("empty is strictly monotonic decreasing by definition",
                                           Botan::detail::strictly_monotonic_decreasing<>);
                            result.confirm("single element is strictly monotonic decreasing by definition",
                                           Botan::detail::strictly_monotonic_decreasing<1>);
                            result.confirm("strictly monotonic decreasing",
                                           Botan::detail::strictly_monotonic_decreasing<3, 2, 1>);
                            result.confirm("not strictly monotonic decreasing because 1 < 2",
                                           !Botan::detail::strictly_monotonic_decreasing<3, 1, 2>);
                            result.confirm("not strictly monotonic decreasing because 2 == 2",
                                           !Botan::detail::strictly_monotonic_decreasing<3, 2, 2>);
                         }),

      Botan_Tests::CHECK(
         "concept block_processing_callback",
         [](Test::Result& result) {
            auto takes_8 = [](std::span<const uint8_t, 8>, std::span<uint8_t, 8>) {};
            auto takes_dynamic = [](std::span<const uint8_t>, std::span<uint8_t>) {};
            auto takes_8_or_16 = Botan::overloaded{
               [](std::span<const uint8_t, 8>, std::span<uint8_t, 8>) {},
               [](std::span<const uint8_t, 16>, std::span<uint8_t, 16>) {},
            };
            auto takes_anything = [](auto, auto) {};
            result.confirm("need just 8", Botan::detail::block_processing_callback<decltype(takes_8), 8>);
            result.confirm("need just 8 but could also take 16",
                           Botan::detail::block_processing_callback<decltype(takes_8_or_16), 8>);
            result.confirm("need both 8 and 16 but can do only 8",
                           !Botan::detail::block_processing_callback<decltype(takes_8), 8, 16>);
            result.confirm("need both 8 and 16, can do dynamic",
                           Botan::detail::block_processing_callback<decltype(takes_dynamic), 8, 16>);
            result.confirm("need both 8 and 16, can do anything",
                           Botan::detail::block_processing_callback<decltype(takes_anything), 8, 16>);
            result.confirm("need 4, can only do 8 or 16",
                           !Botan::detail::block_processing_callback<decltype(takes_8_or_16), 4>);
            result.confirm("need 4, can only do 8", !Botan::detail::block_processing_callback<decltype(takes_8), 4>);
         }),

      Botan_Tests::CHECK(
         "BufferTransformer::process_blocks_of() failure modes with a single block",
         [](Test::Result& result) {
            const auto in = Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
            std::vector<uint8_t> out(in.size());

            Botan::BufferTransformer bt1(in, out);
            result.test_throws("data must be divisible by block size",
                               [&] { bt1.process_blocks_of<3>([](auto, auto) {}); });

            Botan::BufferTransformer bt2(in, out);
            result.test_throws<Botan::Invalid_State>("dynamically requesting data while block processing", [&] {
               bt2.process_blocks_of<8>([&](auto, auto) { bt2.next(8); });
            });

            Botan::BufferTransformer bt3(in, out);
            result.test_throws<Botan::Invalid_State>("statically requesting data while block processing", [&] {
               bt3.process_blocks_of<8>([&](auto, auto) { bt3.next<8>(); });
            });

            Botan::BufferTransformer bt4(in, out);
            result.test_throws<Botan::Invalid_State>("skipping data while block processing", [&] {
               bt4.process_blocks_of<8>([&](auto, auto) { bt4.skip(8); });
            });

            Botan::BufferTransformer bt5(in, out);
            result.test_throws<Botan::Invalid_State>("nested block processing", [&] {
               bt5.process_blocks_of<8>([&](auto, auto) { bt5.process_blocks_of<8>([](auto, auto) {}); });
            });
         }),

      Botan_Tests::CHECK("BufferTransformer::process_blocks_of() with two block sizes",
                         [](Test::Result& result) {
                            const auto in =
                               Botan::hex_decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
                            std::vector<uint8_t> out(in.size());

                            Botan::BufferTransformer bt(in, out);
                            size_t block5 = 0;
                            size_t block2 = 0;

                            bt.process_blocks_of<5, 2>(
                               Botan::overloaded{[&](std::span<const uint8_t, 5> ins, std::span<uint8_t, 5> outs) {
                                                    ++block5;
                                                    Botan::copy_mem(outs, ins);
                                                 },
                                                 [&](std::span<const uint8_t, 2> ins, std::span<uint8_t, 2> outs) {
                                                    ++block2;
                                                    Botan::copy_mem(outs, ins);
                                                 }});

                            result.require("done now", bt.done());
                            result.test_is_eq("output is as expected", out, in);

                            result.test_eq("block size 5 processed", block5, 6);
                            result.test_eq("block size 2 processed", block2, 1);
                         }),

      Botan_Tests::CHECK("BufferTransformer::process_blocks_of() with four block sizes",
                         [](Test::Result& result) {
                            const auto in = Botan::hex_decode("000102030405060708090A0B0C0D0E0FFFFEFDFFFCFBFA");
                            std::vector<uint8_t> out(in.size());

                            // Will be processed in blocks of 8, 4, 2, 1 bytes
                            // 2x8 bytes, 1x4 bytes, 1x2 bytes, 1x1 bytes
                            result.require("sanity check input length", in.size() == 2 * 8 + 1 * 4 + 1 * 2 + 1 * 1);

                            Botan::BufferTransformer bt(in, out);

                            size_t processed_8_bytes = 0;
                            size_t processed_4_bytes = 0;
                            size_t processed_2_bytes = 0;
                            size_t processed_1_bytes = 0;

                            bt.process_blocks_of<8, 4, 2, 1>([&](auto i, auto o) {
                               const auto integer = Botan::load_be(i);
                               Botan::copy_mem(o, Botan::store_be(i));

                               // This is more involved than it has to be to exercise the
                               // ability to use constexpr if in the lambda with the
                               // std::span::size() methods.
                               if constexpr(i.size() == 8) {
                                  result.confirm("uint64_t", std::same_as<const uint64_t, decltype(integer)>);
                                  ++processed_8_bytes;
                               } else if constexpr(i.size() == 4) {
                                  result.confirm("uint32_t", std::same_as<const uint32_t, decltype(integer)>);
                                  ++processed_4_bytes;
                               } else if constexpr(i.size() == 2) {
                                  result.confirm("uint16_t", std::same_as<const uint16_t, decltype(integer)>);
                                  ++processed_2_bytes;
                               } else if constexpr(i.size() == 1) {
                                  result.confirm("uint8_t", std::same_as<const uint8_t, decltype(integer)>);
                                  ++processed_1_bytes;
                               } else {
                                  result.test_failure("unexpected block size");
                               }
                            });

                            result.require("done now", bt.done());
                            result.test_is_eq("output is as expected", out, in);

                            result.test_eq("2x8 bytes processed", processed_8_bytes, 2);
                            result.test_eq("1x4 bytes processed", processed_4_bytes, 1);
                            result.test_eq("1x2 bytes processed", processed_2_bytes, 1);
                            result.test_eq("1x1 bytes processed", processed_1_bytes, 1);
                         }),

      Botan_Tests::CHECK(
         "BufferTransformer::process_blocks_of() failure modes with multiple block sizes",
         [](Test::Result& result) {
            std::array<uint8_t, 11> in1 = {};
            std::array<uint8_t, 11> out1 = {};

            Botan::BufferTransformer bt1(in1, out1);
            result.test_throws<Botan::Invalid_Argument>("data must be processible by the sequence block size", [&] {
               bt1.process_blocks_of<5, 3>([&](auto, auto) { result.test_failure("should not be called"); });
            });

            std::vector<uint8_t> in2;
            std::vector<uint8_t> out2;

            Botan::BufferTransformer bt2(in2, out2);
            result.test_no_throw("empty input should always work", [&] {
               bt2.process_blocks_of<50, 5, 2>([&](auto, auto) { result.test_failure("should not be called"); });
            });
         }),
   };
}

BOTAN_REGISTER_TEST_FN("utils",
                       "buffer_utilities",
                       test_buffer_slicer,
                       test_buffer_stuffer,
                       test_alignment_buffer,
                       test_concat,
                       test_buffer_transformer);

}  // namespace

}  // namespace Botan_Tests
