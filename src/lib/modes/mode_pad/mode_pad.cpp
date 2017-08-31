/*
* CBC Padding Methods
* (C) 1999-2007,2013 Jack Lloyd
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
size_t PKCS7_Padding::unpad(const uint8_t block[], size_t size) const
   {
   CT::poison(block,size);
   size_t bad_input = 0;
   const uint8_t last_byte = block[size-1];

   bad_input |= CT::expand_mask<size_t>(last_byte > size);

   size_t pad_pos = size - last_byte;
   size_t i = size - 2;
   while(i)
      {
      bad_input |= (~CT::is_equal(block[i],last_byte)) & CT::expand_mask<uint8_t>(i >= pad_pos);
      --i;
      }

   CT::conditional_copy_mem(bad_input,&pad_pos,&size,&pad_pos,1);
   CT::unpoison(block,size);
   CT::unpoison(pad_pos);
   return pad_pos;
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
size_t ANSI_X923_Padding::unpad(const uint8_t block[], size_t size) const
   {
   CT::poison(block,size);
   size_t bad_input = 0;
   const size_t last_byte = block[size-1];

   bad_input |= CT::expand_mask<size_t>(last_byte > size);

   size_t pad_pos = size - last_byte;
   size_t i = size - 2;
   while(i)
      {
      bad_input |= (~CT::is_zero(block[i])) & CT::expand_mask<uint8_t>(i >= pad_pos);
      --i;
      }
   CT::conditional_copy_mem(bad_input,&pad_pos,&size,&pad_pos,1);
   CT::unpoison(block,size);
   CT::unpoison(pad_pos);
   return pad_pos;
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
size_t OneAndZeros_Padding::unpad(const uint8_t block[], size_t size) const
   {
   CT::poison(block, size);
   uint8_t bad_input = 0;
   uint8_t seen_one = 0;
   size_t pad_pos = size - 1;
   size_t i = size;

   while(i)
      {
      seen_one |= CT::is_equal<uint8_t>(block[i-1],0x80);
      pad_pos -= CT::select<uint8_t>(~seen_one, 1, 0);
      bad_input |= ~CT::is_zero<uint8_t>(block[i-1]) & ~seen_one;
      i--;
      }
   bad_input |= ~seen_one;

   CT::conditional_copy_mem(size_t(bad_input),&pad_pos,&size,&pad_pos,1);
   CT::unpoison(block, size);
   CT::unpoison(pad_pos);

   return pad_pos;
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
size_t ESP_Padding::unpad(const uint8_t block[], size_t size) const
   {
   CT::poison(block,size);

   const size_t last_byte = block[size-1];
   size_t bad_input = 0;
   bad_input |= CT::expand_mask<size_t>(last_byte > size);

   size_t pad_pos = size - last_byte;
   size_t i = size - 1;
   while(i)
      {
      bad_input |= ~CT::is_equal<uint8_t>(size_t(block[i-1]),size_t(block[i])-1) & CT::expand_mask<uint8_t>(i > pad_pos);
      --i;
      }
   CT::conditional_copy_mem(bad_input,&pad_pos,&size,&pad_pos,1);
   CT::unpoison(block, size);
   CT::unpoison(pad_pos);
   return pad_pos;
   }


}
