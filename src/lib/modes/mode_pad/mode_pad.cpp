/*
* CBC Padding Methods
* (C) 1999-2007,2013,2018,2020 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
* (C) 2025 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mode_pad.h>

#include <botan/internal/ct_utils.h>

namespace Botan {

/**
* Get a block cipher padding method by name
*/
std::unique_ptr<BlockCipherModePaddingMethod> BlockCipherModePaddingMethod::create(std::string_view algo_spec) {
   if(algo_spec == "NoPadding") {
      return std::make_unique<Null_Padding>();
   }

   if(algo_spec == "PKCS7") {
      return std::make_unique<PKCS7_Padding>();
   }

   if(algo_spec == "OneAndZeros") {
      return std::make_unique<OneAndZeros_Padding>();
   }

   if(algo_spec == "X9.23") {
      return std::make_unique<ANSI_X923_Padding>();
   }

   if(algo_spec == "ESP") {
      return std::make_unique<ESP_Padding>();
   }

   return nullptr;
}

void BlockCipherModePaddingMethod::add_padding(std::span<uint8_t> buffer, size_t last_byte_pos, size_t BS) const {
   BOTAN_ASSERT_NOMSG(valid_blocksize(BS));
   BOTAN_ASSERT_NOMSG(last_byte_pos < BS);
   BOTAN_ASSERT_NOMSG(buffer.size() % BS == 0);
   BOTAN_ASSERT_NOMSG(buffer.size() >= BS);

   auto poison = CT::scoped_poison(last_byte_pos, buffer);
   apply_padding(buffer.last(BS), last_byte_pos);
}

size_t BlockCipherModePaddingMethod::unpad(std::span<const uint8_t> last_block) const {
   if(!valid_blocksize(last_block.size())) {
      return last_block.size();
   }

   auto poison = CT::scoped_poison(last_block);
   return CT::driveby_unpoison(remove_padding(last_block));
}

/*
* Pad with PKCS #7 Method
*/
void PKCS7_Padding::apply_padding(std::span<uint8_t> last_block, size_t padding_start_pos) const {
   /*
   Padding format is
   01
   0202
   030303
   ...
   */
   const uint8_t BS = static_cast<uint8_t>(last_block.size());
   const uint8_t start_pos = static_cast<uint8_t>(padding_start_pos);
   const uint8_t padding_len = BS - start_pos;
   for(uint8_t i = 0; i < BS; ++i) {
      auto needs_padding = CT::Mask<uint8_t>::is_gte(i, start_pos);
      last_block[i] = needs_padding.select(padding_len, last_block[i]);
   }
}

/*
* Unpad with PKCS #7 Method
*/
size_t PKCS7_Padding::remove_padding(std::span<const uint8_t> input) const {
   const size_t BS = input.size();
   const uint8_t last_byte = input.back();

   /*
   The input should == the block size so if the last byte exceeds
   that then the padding is certainly invalid
   */
   auto bad_input = CT::Mask<size_t>::is_gt(last_byte, BS);

   const size_t pad_pos = BS - last_byte;

   for(size_t i = 0; i != BS - 1; ++i) {
      // Does this byte equal the expected pad byte?
      const auto pad_eq = CT::Mask<size_t>::is_equal(input[i], last_byte);

      // Ignore values that are not part of the padding
      const auto in_range = CT::Mask<size_t>::is_gte(i, pad_pos);
      bad_input |= in_range & (~pad_eq);
   }

   return bad_input.select(BS, pad_pos);
}

/*
* Pad with ANSI X9.23 Method
*/
void ANSI_X923_Padding::apply_padding(std::span<uint8_t> last_block, size_t padding_start_pos) const {
   /*
   Padding format is
   01
   0002
   000003
   ...
   */
   const uint8_t BS = static_cast<uint8_t>(last_block.size());
   const uint8_t start_pos = static_cast<uint8_t>(padding_start_pos);
   const uint8_t padding_len = BS - start_pos;
   for(uint8_t i = 0; i != BS - 1; ++i) {
      auto needs_padding = CT::Mask<uint8_t>::is_gte(i, start_pos);
      last_block[i] = needs_padding.select(0, last_block[i]);
   }

   last_block.back() = padding_len;
}

/*
* Unpad with ANSI X9.23 Method
*/
size_t ANSI_X923_Padding::remove_padding(std::span<const uint8_t> input) const {
   const size_t BS = input.size();
   const size_t last_byte = input.back();

   auto bad_input = CT::Mask<size_t>::is_gt(last_byte, BS);

   const size_t pad_pos = BS - last_byte;

   for(size_t i = 0; i != BS - 1; ++i) {
      // Ignore values that are not part of the padding
      const auto in_range = CT::Mask<size_t>::is_gte(i, pad_pos);
      const auto pad_is_nonzero = CT::Mask<size_t>::expand(input[i]);
      bad_input |= pad_is_nonzero & in_range;
   }

   return bad_input.select(BS, pad_pos);
}

/*
* Pad with One and Zeros Method
*/
void OneAndZeros_Padding::apply_padding(std::span<uint8_t> last_block, size_t padding_start_pos) const {
   /*
   Padding format is
   80
   8000
   800000
   ...
   */
   for(size_t i = 0; i != last_block.size(); ++i) {
      auto needs_80 = CT::Mask<uint8_t>(CT::Mask<size_t>::is_equal(i, padding_start_pos));
      auto needs_00 = CT::Mask<uint8_t>(CT::Mask<size_t>::is_gt(i, padding_start_pos));
      last_block[i] = needs_00.select(0x00, needs_80.select(0x80, last_block[i]));
   }
}

/*
* Unpad with One and Zeros Method
*/
size_t OneAndZeros_Padding::remove_padding(std::span<const uint8_t> input) const {
   const size_t BS = input.size();
   auto bad_input = CT::Mask<uint8_t>::cleared();
   auto seen_0x80 = CT::Mask<uint8_t>::cleared();

   size_t pad_pos = BS - 1;

   for(size_t i = BS; i != 0; --i) {
      const auto is_0x80 = CT::Mask<uint8_t>::is_equal(input[i - 1], 0x80);
      const auto is_zero = CT::Mask<uint8_t>::is_zero(input[i - 1]);

      seen_0x80 |= is_0x80;
      pad_pos -= seen_0x80.if_not_set_return(1);
      bad_input |= ~seen_0x80 & ~is_zero;
   }
   bad_input |= ~seen_0x80;

   return CT::Mask<size_t>::expand(bad_input).select(BS, pad_pos);
}

/*
* Pad with ESP Padding Method
*/
void ESP_Padding::apply_padding(std::span<uint8_t> last_block, size_t padding_start_pos) const {
   /*
   Padding format is
   01
   0102
   010203
   ...
   */
   const uint8_t BS = static_cast<uint8_t>(last_block.size());
   const uint8_t start_pos = static_cast<uint8_t>(padding_start_pos);

   uint8_t pad_ctr = 0x01;
   for(uint8_t i = 0; i != BS; ++i) {
      auto needs_padding = CT::Mask<uint8_t>::is_gte(i, start_pos);
      last_block[i] = needs_padding.select(pad_ctr, last_block[i]);
      pad_ctr = needs_padding.select(pad_ctr + 1, pad_ctr);
   }
}

/*
* Unpad with ESP Padding Method
*/
size_t ESP_Padding::remove_padding(std::span<const uint8_t> input) const {
   const size_t BS = input.size();
   const uint8_t last_byte = input.back();

   auto bad_input = CT::Mask<size_t>::is_zero(last_byte) | CT::Mask<size_t>::is_gt(last_byte, BS);

   const size_t pad_pos = BS - last_byte;
   for(size_t i = BS - 1; i != 0; --i) {
      const auto in_range = CT::Mask<size_t>::is_gt(i, pad_pos);
      const auto incrementing = CT::Mask<size_t>::is_equal(input[i - 1], input[i] - 1);

      bad_input |= CT::Mask<size_t>(in_range) & ~incrementing;
   }

   return bad_input.select(BS, pad_pos);
}

}  // namespace Botan
