/*
* Base64 Encoding and Decoding
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/base64.h>
#include <botan/mem_ops.h>
#include <botan/internal/rounding.h>
#include <botan/internal/assert.h>
#include <stdexcept>

namespace Botan {

namespace {

static const byte BIN_TO_BASE64[64] = {
   'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
   'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
   'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
   'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
   '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

void do_base64_encode(char out[4], const byte in[3])
   {
   out[0] = BIN_TO_BASE64[((in[0] & 0xFC) >> 2)];
   out[1] = BIN_TO_BASE64[((in[0] & 0x03) << 4) | (in[1] >> 4)];
   out[2] = BIN_TO_BASE64[((in[1] & 0x0F) << 2) | (in[2] >> 6)];
   out[3] = BIN_TO_BASE64[((in[2] & 0x3F)     )];
   }

}

size_t base64_encode(char out[],
                     const byte in[],
                     size_t input_length,
                     size_t& input_consumed,
                     bool final_inputs)
   {
   input_consumed = 0;

   size_t input_remaining = input_length;
   size_t output_produced = 0;

   while(input_remaining >= 3)
      {
      do_base64_encode(out + output_produced, in + input_consumed);

      input_consumed += 3;
      output_produced += 4;
      input_remaining -= 3;
      }

   if(final_inputs && input_remaining)
      {
      byte remainder[3] = { 0 };
      for(size_t i = 0; i != input_remaining; ++i)
         remainder[i] = in[input_consumed + i];

      do_base64_encode(out + output_produced, remainder);

      size_t empty_bits = 8 * (3 - input_remaining);
      size_t index = output_produced + 4 - 1;
      while(empty_bits >= 8)
         {
         out[index--] = '=';
         empty_bits -= 6;
         }

      input_consumed += input_remaining;
      output_produced += 4;
      }

   return output_produced;
   }

std::string base64_encode(const byte input[],
                          size_t input_length)
   {
   std::string output((round_up<size_t>(input_length, 3) / 3) * 4, 0);

   size_t consumed = 0;
   size_t produced = base64_encode(&output[0],
                                   input, input_length,
                                   consumed, true);

   BOTAN_ASSERT_EQUAL(consumed, input_length, "Did not consume all input");
   BOTAN_ASSERT_EQUAL(produced, output.size(), "Did not produce right amount");

   return output;
   }

std::string base64_encode(const MemoryRegion<byte>& input)
   {
   return base64_encode(&input[0], input.size());
   }


}
