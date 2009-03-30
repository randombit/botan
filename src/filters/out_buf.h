/*
* Output Buffer
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_OUTPUT_BUFFER_H__
#define BOTAN_OUTPUT_BUFFER_H__

#include <botan/types.h>
#include <botan/pipe.h>
#include <deque>

namespace Botan {

/*
* Container of output buffers for Pipe
*/
class BOTAN_DLL Output_Buffers
   {
   public:
      u32bit read(byte[], u32bit, Pipe::message_id);
      u32bit peek(byte[], u32bit, u32bit, Pipe::message_id) const;
      u32bit remaining(Pipe::message_id) const;

      void add(class SecureQueue*);
      void retire();

      Pipe::message_id message_count() const;

      Output_Buffers();
      ~Output_Buffers();
   private:
      class SecureQueue* get(Pipe::message_id) const;

      std::deque<SecureQueue*> buffers;
      Pipe::message_id offset;
   };

}

#endif
