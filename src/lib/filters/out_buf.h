/*
* Output Buffer
* (C) 1999-2007 Jack Lloyd
*     2012 Markus Wanner
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_OUTPUT_BUFFER_H_
#define BOTAN_OUTPUT_BUFFER_H_

#include <botan/pipe.h>
#include <botan/types.h>
#include <deque>

namespace Botan {

class SecureQueue;

/**
* Container of output buffers for Pipe
*/
class Output_Buffers final {
   public:
      size_t read(uint8_t output[], size_t length, Pipe::message_id msg);
      size_t peek(uint8_t output[], size_t length, size_t stream_offset, Pipe::message_id msg) const;
      size_t get_bytes_read(Pipe::message_id msg) const;
      size_t remaining(Pipe::message_id msg) const;

      void add(SecureQueue* queue);
      void retire();

      Pipe::message_id message_count() const;

      Output_Buffers() = default;

   private:
      SecureQueue* get(Pipe::message_id msg) const;

      std::deque<std::unique_ptr<SecureQueue>> m_buffers;
      Pipe::message_id m_offset = 0;
};

}  // namespace Botan

#endif
