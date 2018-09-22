/*
* CBC Padding Methods
* (C) 1999-2007,2013,2018 Jack Lloyd
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
                                size_t block_size) const
   {
   const uint8_t pad_value = static_cast<uint8_t>(block_size - last_byte_pos);

   for(size_t i = 0; i != pad_value; ++i)
      buffer.push_back(pad_value);
   }

/*
* Unpad with PKCS #7 Method
*/
size_t PKCS7_Padding::unpad(const uint8_t input[], size_t input_length) const
   {
   if(input_length <= 2)
      return input_length;

   CT::poison(input, input_length);
   size_t bad_input = 0;
   const uint8_t last_byte = input[input_length-1];

   bad_input |= CT::expand_mask<size_t>(last_byte > input_length);

   const size_t pad_pos = input_length - last_byte;

   for(size_t i = 0; i != input_length - 1; ++i)
      {
      const uint8_t in_range = CT::expand_mask<uint8_t>(i >= pad_pos);
      bad_input |= in_range & (~CT::is_equal(input[i], last_byte));
      }

   CT::unpoison(input, input_length);
   return CT::conditional_return(bad_input, input_length, pad_pos);
   }

/*
* Pad with ANSI X9.23 Method
*/
void ANSI_X923_Padding::add_padding(secure_vector<uint8_t>& buffer,
                                    size_t last_byte_pos,
                                    size_t block_size) const
   {
   const uint8_t pad_value = static_cast<uint8_t>(block_size - last_byte_pos);

   for(size_t i = last_byte_pos; i < block_size-1; ++i)
      {
      buffer.push_back(0);
      }
   buffer.push_back(pad_value);
   }

/*
* Unpad with ANSI X9.23 Method
*/
size_t ANSI_X923_Padding::unpad(const uint8_t input[], size_t input_length) const
   {
   if(input_length <= 2)
      return input_length;

   CT::poison(input, input_length);
   const size_t last_byte = input[input_length-1];

   uint8_t bad_input = 0;
   bad_input |= CT::expand_mask<uint8_t>(last_byte > input_length);

   const size_t pad_pos = input_length - last_byte;

   for(size_t i = 0; i != input_length - 1; ++i)
      {
      const uint8_t in_range = CT::expand_mask<uint8_t>(i >= pad_pos);
      bad_input |= CT::expand_mask(input[i]) & in_range;
      }

   CT::unpoison(input, input_length);
   return CT::conditional_return(bad_input, input_length, pad_pos);
   }

/*
* Pad with One and Zeros Method
*/
void OneAndZeros_Padding::add_padding(secure_vector<uint8_t>& buffer,
                                      size_t last_byte_pos,
                                      size_t block_size) const
   {
   buffer.push_back(0x80);

   for(size_t i = last_byte_pos + 1; i % block_size; ++i)
      buffer.push_back(0x00);
   }

/*
* Unpad with One and Zeros Method
*/
size_t OneAndZeros_Padding::unpad(const uint8_t input[], size_t input_length) const
   {
   if(input_length <= 2)
      return input_length;

   CT::poison(input, input_length);

   uint8_t bad_input = 0;
   uint8_t seen_one = 0;
   size_t pad_pos = input_length - 1;
   size_t i = input_length;

   while(i)
      {
      seen_one |= CT::is_equal<uint8_t>(input[i-1], 0x80);
      pad_pos -= CT::select<uint8_t>(~seen_one, 1, 0);
      bad_input |= ~CT::is_zero<uint8_t>(input[i-1]) & ~seen_one;
      i--;
      }
   bad_input |= ~seen_one;

   CT::unpoison(input, input_length);
   return CT::conditional_return(bad_input, input_length, pad_pos);
   }

/*
* Pad with ESP Padding Method
*/
void ESP_Padding::add_padding(secure_vector<uint8_t>& buffer,
                              size_t last_byte_pos,
                              size_t block_size) const
   {
   uint8_t pad_value = 0x01;

   for(size_t i = last_byte_pos; i < block_size; ++i)
      {
      buffer.push_back(pad_value++);
      }
   }

/*
* Unpad with ESP Padding Method
*/
size_t ESP_Padding::unpad(const uint8_t input[], size_t input_length) const
   {
   if(input_length <= 2)
      return input_length;

   CT::poison(input, input_length);

   const size_t last_byte = input[input_length-1];
   uint8_t bad_input = 0;
   bad_input |= CT::is_zero(last_byte) | CT::expand_mask<uint8_t>(last_byte > input_length);

   const size_t pad_pos = input_length - last_byte;
   size_t i = input_length - 1;
   while(i)
      {
      const uint8_t in_range = CT::expand_mask<uint8_t>(i > pad_pos);
      bad_input |= (~CT::is_equal<uint8_t>(input[i-1], input[i]-1)) & in_range;
      --i;
      }

   CT::unpoison(input, input_length);
   return CT::conditional_return(bad_input, input_length, pad_pos);
   }


}
