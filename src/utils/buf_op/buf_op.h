/**
* Buffering Central
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BUFFERED_OPTION_H__
#define BOTAN_BUFFERED_OPTION_H__

#include <botan/types.h>
#include <tr1/functional>
#include <vector>

namespace Botan {

class BOTAN_DLL Buffered_Operation
   {
   public:
      typedef std::tr1::function<void (const byte[], size_t)> callback_fn;

      void write(const byte input[], size_t input_size);

      void final();

      void reset();

      size_t current_position() const { return buffer_pos; }

      Buffered_Operation(callback_fn main_block,
                         callback_fn final_block,
                         size_t main_buf_mod,
                         size_t final_minimum = 0);

   private:
      callback_fn main_fn, final_fn;
      size_t final_minimum, main_block_mod;

      std::vector<byte> buffer;
      size_t buffer_pos;
   };

}

#endif
