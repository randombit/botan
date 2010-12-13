/*
* CBC Padding Methods
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/mode_pad.h>
#include <botan/exceptn.h>
#include <botan/internal/assert.h>

namespace Botan {

/*
* Default amount of padding
*/
size_t BlockCipherModePaddingMethod::pad_bytes(size_t bs, size_t pos) const
   {
   return (bs - pos);
   }

/*
* Pad with PKCS #7 Method
*/
void PKCS7_Padding::pad(byte block[], size_t size, size_t position) const
   {
   const size_t bytes_remaining = size - position;
   const byte pad_value = static_cast<byte>(bytes_remaining);

   BOTAN_ASSERT_EQUAL(pad_value, bytes_remaining,
                      "Overflow in PKCS7_Padding");

   for(size_t j = 0; j != size; ++j)
      block[j] = pad_value;
   }

/*
* Unpad with PKCS #7 Method
*/
size_t PKCS7_Padding::unpad(const byte block[], size_t size) const
   {
   size_t position = block[size-1];
   if(position > size)
      throw Decoding_Error(name());
   for(size_t j = size-position; j != size-1; ++j)
      if(block[j] != position)
         throw Decoding_Error(name());
   return (size-position);
   }

/*
* Query if the size is valid for this method
*/
bool PKCS7_Padding::valid_blocksize(size_t size) const
   {
   if(size > 0 && size < 256)
      return true;
   else
      return false;
   }

/*
* Pad with ANSI X9.23 Method
*/
void ANSI_X923_Padding::pad(byte block[], size_t size, size_t position) const
   {
   for(size_t j = 0; j != size-position; ++j)
      block[j] = 0;
   block[size-position-1] = static_cast<byte>(size-position);
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
* Query if the size is valid for this method
*/
bool ANSI_X923_Padding::valid_blocksize(size_t size) const
   {
   if(size > 0 && size < 256)
      return true;
   else
      return false;
   }

/*
* Pad with One and Zeros Method
*/
void OneAndZeros_Padding::pad(byte block[], size_t size, size_t) const
   {
   block[0] = 0x80;
   for(size_t j = 1; j != size; ++j)
      block[j] = 0x00;
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
* Query if the size is valid for this method
*/
bool OneAndZeros_Padding::valid_blocksize(size_t size) const
   {
   return (size > 0);
   }

}
