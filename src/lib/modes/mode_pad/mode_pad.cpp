/*
* CBC Padding Methods
* (C) 1999-2007,2013,2018,2020 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/mode_pad.h>
#include <botan/exceptn.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

/**
* Get a block cipher padding method by name
*/
BlockCipherModePaddingMethod* get_bc_pad(const std::string& algo_spec)
   {
   if(algo_spec == "NoPadding")
      return new Null_Padding;

   if(algo_spec == "PKCS7")
      return new PKCS7_Padding;

   if(algo_spec == "OneAndZeros")
      return new OneAndZeros_Padding;

   if(algo_spec == "X9.23")
      return new ANSI_X923_Padding;

   if(algo_spec == "ESP")
      return new ESP_Padding;

   return nullptr;
   }

/*
* Pad with PKCS #7 Method
*/
void PKCS7_Padding::add_padding(secure_vector<uint8_t>& buffer,
                                size_t last_byte_pos,
                                size_t BS) const
   {
   /*
   Padding format is
   01
   0202
   030303
   ...
   */
   BOTAN_DEBUG_ASSERT(last_byte_pos < BS);

   const uint8_t padding_len = static_cast<uint8_t>(BS - last_byte_pos);

   buffer.resize(buffer.size() + padding_len);

   CT::poison(&last_byte_pos, 1);
   CT::poison(buffer.data(), buffer.size());

   BOTAN_DEBUG_ASSERT(buffer.size() % BS == 0);
   BOTAN_DEBUG_ASSERT(buffer.size() >= BS);

   const size_t start_of_last_block = buffer.size() - BS;
   const size_t end_of_last_block = buffer.size();
   const size_t start_of_padding = buffer.size() - padding_len;

   for(size_t i = start_of_last_block; i != end_of_last_block; ++i)
      {
      auto needs_padding = CT::Mask<uint8_t>(CT::Mask<size_t>::is_gte(i, start_of_padding));
      buffer[i] = needs_padding.select(padding_len, buffer[i]);
      }

   CT::unpoison(buffer.data(), buffer.size());
   CT::unpoison(last_byte_pos);
   }

/*
* Unpad with PKCS #7 Method
*/
size_t PKCS7_Padding::unpad(const uint8_t input[], size_t input_length) const
   {
   if(!valid_blocksize(input_length))
      return input_length;

   CT::poison(input, input_length);

   const uint8_t last_byte = input[input_length-1];

   /*
   The input should == the block size so if the last byte exceeds
   that then the padding is certainly invalid
   */
   auto bad_input = CT::Mask<size_t>::is_gt(last_byte, input_length);

   const size_t pad_pos = input_length - last_byte;

   for(size_t i = 0; i != input_length - 1; ++i)
      {
      // Does this byte equal the expected pad byte?
      const auto pad_eq = CT::Mask<size_t>::is_equal(input[i], last_byte);

      // Ignore values that are not part of the padding
      const auto in_range = CT::Mask<size_t>::is_gte(i, pad_pos);
      bad_input |= in_range & (~pad_eq);
      }

   CT::unpoison(input, input_length);

   return bad_input.select_and_unpoison(input_length, pad_pos);
   }

/*
* Pad with ANSI X9.23 Method
*/
void ANSI_X923_Padding::add_padding(secure_vector<uint8_t>& buffer,
                                    size_t last_byte_pos,
                                    size_t BS) const
   {
   /*
   Padding format is
   01
   0002
   000003
   ...
   */
   BOTAN_DEBUG_ASSERT(last_byte_pos < BS);

   const uint8_t padding_len = static_cast<uint8_t>(BS - last_byte_pos);

   buffer.resize(buffer.size() + padding_len);

   CT::poison(&last_byte_pos, 1);
   CT::poison(buffer.data(), buffer.size());

   BOTAN_DEBUG_ASSERT(buffer.size() % BS == 0);
   BOTAN_DEBUG_ASSERT(buffer.size() >= BS);

   const size_t start_of_last_block = buffer.size() - BS;
   const size_t end_of_zero_padding = buffer.size() - 1;
   const size_t start_of_padding = buffer.size() - padding_len;

   for(size_t i = start_of_last_block; i != end_of_zero_padding; ++i)
      {
      auto needs_padding = CT::Mask<uint8_t>(CT::Mask<size_t>::is_gte(i, start_of_padding));
      buffer[i] = needs_padding.select(0, buffer[i]);
      }

   buffer[buffer.size()-1] = padding_len;
   CT::unpoison(buffer.data(), buffer.size());
   CT::unpoison(last_byte_pos);
   }

/*
* Unpad with ANSI X9.23 Method
*/
size_t ANSI_X923_Padding::unpad(const uint8_t input[], size_t input_length) const
   {
   if(!valid_blocksize(input_length))
      return input_length;

   CT::poison(input, input_length);

   const size_t last_byte = input[input_length-1];

   auto bad_input = CT::Mask<size_t>::is_gt(last_byte, input_length);

   const size_t pad_pos = input_length - last_byte;

   for(size_t i = 0; i != input_length - 1; ++i)
      {
      // Ignore values that are not part of the padding
      const auto in_range = CT::Mask<size_t>::is_gte(i, pad_pos);
      const auto pad_is_nonzero = CT::Mask<size_t>::expand(input[i]);
      bad_input |= pad_is_nonzero & in_range;
      }

   CT::unpoison(input, input_length);

   return bad_input.select_and_unpoison(input_length, pad_pos);
   }

/*
* Pad with One and Zeros Method
*/
void OneAndZeros_Padding::add_padding(secure_vector<uint8_t>& buffer,
                                      size_t last_byte_pos,
                                      size_t BS) const
   {
   /*
   Padding format is
   80
   8000
   800000
   ...
   */

   BOTAN_DEBUG_ASSERT(last_byte_pos < BS);

   const uint8_t padding_len = static_cast<uint8_t>(BS - last_byte_pos);

   buffer.resize(buffer.size() + padding_len);

   CT::poison(&last_byte_pos, 1);
   CT::poison(buffer.data(), buffer.size());

   BOTAN_DEBUG_ASSERT(buffer.size() % BS == 0);
   BOTAN_DEBUG_ASSERT(buffer.size() >= BS);

   const size_t start_of_last_block = buffer.size() - BS;
   const size_t end_of_last_block = buffer.size();
   const size_t start_of_padding = buffer.size() - padding_len;

   for(size_t i = start_of_last_block; i != end_of_last_block; ++i)
      {
      auto needs_80 = CT::Mask<uint8_t>(CT::Mask<size_t>::is_equal(i, start_of_padding));
      auto needs_00 = CT::Mask<uint8_t>(CT::Mask<size_t>::is_gt(i, start_of_padding));
      buffer[i] = needs_00.select(0x00, needs_80.select(0x80, buffer[i]));
      }

   CT::unpoison(buffer.data(), buffer.size());
   CT::unpoison(last_byte_pos);
   }

/*
* Unpad with One and Zeros Method
*/
size_t OneAndZeros_Padding::unpad(const uint8_t input[], size_t input_length) const
   {
   if(!valid_blocksize(input_length))
      return input_length;

   CT::poison(input, input_length);

   auto bad_input = CT::Mask<uint8_t>::cleared();
   auto seen_0x80 = CT::Mask<uint8_t>::cleared();

   size_t pad_pos = input_length - 1;
   size_t i = input_length;

   while(i)
      {
      const auto is_0x80 = CT::Mask<uint8_t>::is_equal(input[i-1], 0x80);
      const auto is_zero = CT::Mask<uint8_t>::is_zero(input[i-1]);

      seen_0x80 |= is_0x80;
      pad_pos -= seen_0x80.if_not_set_return(1);
      bad_input |= ~seen_0x80 & ~is_zero;
      i--;
      }
   bad_input |= ~seen_0x80;

   CT::unpoison(input, input_length);

   return CT::Mask<size_t>::expand(bad_input).select_and_unpoison(input_length, pad_pos);
   }

/*
* Pad with ESP Padding Method
*/
void ESP_Padding::add_padding(secure_vector<uint8_t>& buffer,
                              size_t last_byte_pos,
                              size_t BS) const
   {
   /*
   Padding format is
   01
   0102
   010203
   ...
   */
   BOTAN_DEBUG_ASSERT(last_byte_pos < BS);

   const uint8_t padding_len = static_cast<uint8_t>(BS - last_byte_pos);

   buffer.resize(buffer.size() + padding_len);

   CT::poison(&last_byte_pos, 1);
   CT::poison(buffer.data(), buffer.size());

   BOTAN_DEBUG_ASSERT(buffer.size() % BS == 0);
   BOTAN_DEBUG_ASSERT(buffer.size() >= BS);

   const size_t start_of_last_block = buffer.size() - BS;
   const size_t end_of_last_block = buffer.size();
   const size_t start_of_padding = buffer.size() - padding_len;

   uint8_t pad_ctr = 0x01;

   for(size_t i = start_of_last_block; i != end_of_last_block; ++i)
      {
      auto needs_padding = CT::Mask<uint8_t>(CT::Mask<size_t>::is_gte(i, start_of_padding));
      buffer[i] = needs_padding.select(pad_ctr, buffer[i]);
      pad_ctr = needs_padding.select(pad_ctr + 1, pad_ctr);
      }

   CT::unpoison(buffer.data(), buffer.size());
   CT::unpoison(last_byte_pos);
   }

/*
* Unpad with ESP Padding Method
*/
size_t ESP_Padding::unpad(const uint8_t input[], size_t input_length) const
   {
   if(!valid_blocksize(input_length))
      return input_length;

   CT::poison(input, input_length);

   const uint8_t input_length_8 = static_cast<uint8_t>(input_length);
   const uint8_t last_byte = input[input_length-1];

   auto bad_input = CT::Mask<uint8_t>::is_zero(last_byte) |
      CT::Mask<uint8_t>::is_gt(last_byte, input_length_8);

   const uint8_t pad_pos = input_length_8 - last_byte;
   size_t i = input_length_8 - 1;
   while(i)
      {
      const auto in_range = CT::Mask<size_t>::is_gt(i, pad_pos);
      const auto incrementing = CT::Mask<uint8_t>::is_equal(input[i-1], input[i]-1);

      bad_input |= CT::Mask<uint8_t>(in_range) & ~incrementing;
      --i;
      }

   CT::unpoison(input, input_length);
   return bad_input.select_and_unpoison(input_length_8, pad_pos);
   }


}
