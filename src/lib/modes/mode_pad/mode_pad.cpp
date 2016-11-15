/*
* CBC Padding Methods
* (C) 1999-2007,2013 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/mode_pad.h>
#include <botan/exceptn.h>

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
void PKCS7_Padding::add_padding(secure_vector<byte>& buffer,
                                size_t last_byte_pos,
                                size_t block_size) const
   {
   const byte pad_value = static_cast<byte>(block_size - last_byte_pos);

   for(size_t i = 0; i != pad_value; ++i)
      buffer.push_back(pad_value);
   }

/*
* Unpad with PKCS #7 Method
*/
size_t PKCS7_Padding::unpad(const byte block[], size_t size) const
   {
   size_t position = block[size-1];

   if(position > size)
      throw Decoding_Error("Bad padding in " + name());

   for(size_t j = size-position; j != size-1; ++j)
      if(block[j] != position)
         throw Decoding_Error("Bad padding in " + name());

   return (size-position);
   }

/*
* Pad with ANSI X9.23 Method
*/
void ANSI_X923_Padding::add_padding(secure_vector<byte>& buffer,
                                    size_t last_byte_pos,
                                    size_t block_size) const
   {
   const byte pad_value = static_cast<byte>(block_size - last_byte_pos);

   for(size_t i = last_byte_pos; i < block_size-1; ++i)
      {
      buffer.push_back(0);
      }
   buffer.push_back(pad_value);
   }

/*
* Unpad with ANSI X9.23 Method
*/
size_t ANSI_X923_Padding::unpad(const byte block[], size_t size) const
   {
   size_t position = block[size-1];
   if(position > size)
      throw Decoding_Error(name());
   for(size_t j = size-position; j != size-1; ++j)
      if(block[j] != 0)
         throw Decoding_Error(name());
   return (size-position);
   }

/*
* Pad with One and Zeros Method
*/
void OneAndZeros_Padding::add_padding(secure_vector<byte>& buffer,
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
size_t OneAndZeros_Padding::unpad(const byte block[], size_t size) const
   {
   while(size)
      {
      if(block[size-1] == 0x80)
         break;
      if(block[size-1] != 0x00)
         throw Decoding_Error(name());
      size--;
      }
   if(!size)
      throw Decoding_Error(name());
   return (size-1);
   }

/*
* Pad with ESP Padding Method
*/
void ESP_Padding::add_padding(secure_vector<byte>& buffer,
                                      size_t last_byte_pos,
                                      size_t block_size) const
   {
   byte pad_value = 0x01;

   for(size_t i = last_byte_pos; i < block_size; ++i)
      {
      buffer.push_back(pad_value++);
      }
   }

/*
* Unpad with ESP Padding Method
*/
size_t ESP_Padding::unpad(const byte block[], size_t size) const
   {
   const byte last_byte = block[size-1];
   if(last_byte > size)
      {
      throw Decoding_Error(name());
      }

   // try to do this in const time by looping over the entire block
   const size_t pad_pos = size - last_byte;
   size_t i = size - 1;
   while(i)
      {
      if(block[i-1] != block[i]-1)
         {
         if(i > pad_pos)
            {
            throw Decoding_Error(name());
            }
         }
      --i;
      }
   return pad_pos;
   }


}
