/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/buf_comp.h>

#include <botan/internal/loadstor.h>

namespace Botan {

void Buffered_Computation::update(std::string_view str) {
   add_data({cast_char_ptr_to_uint8(str.data()), str.size()});
}

void Buffered_Computation::update_be(uint16_t val) {
   uint8_t inb[sizeof(val)];
   store_be(val, inb);
   add_data({inb, sizeof(inb)});
}

void Buffered_Computation::update_be(uint32_t val) {
   uint8_t inb[sizeof(val)];
   store_be(val, inb);
   add_data({inb, sizeof(inb)});
}

void Buffered_Computation::update_be(uint64_t val) {
   uint8_t inb[sizeof(val)];
   store_be(val, inb);
   add_data({inb, sizeof(inb)});
}

void Buffered_Computation::update_le(uint16_t val) {
   uint8_t inb[sizeof(val)];
   store_le(val, inb);
   add_data({inb, sizeof(inb)});
}

void Buffered_Computation::update_le(uint32_t val) {
   uint8_t inb[sizeof(val)];
   store_le(val, inb);
   add_data({inb, sizeof(inb)});
}

void Buffered_Computation::update_le(uint64_t val) {
   uint8_t inb[sizeof(val)];
   store_le(val, inb);
   add_data({inb, sizeof(inb)});
}

void Buffered_Computation::final(std::span<uint8_t> out) {
   BOTAN_ARG_CHECK(out.size() >= output_length(), "provided output buffer has insufficient capacity");
   final_result(out);
}

}  // namespace Botan
