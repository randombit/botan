/*************************************************
* Output Buffer Header File                      *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_OUTPUT_BUFFER_H__
#define BOTAN_OUTPUT_BUFFER_H__

#include <botan/types.h>
#include <deque>

namespace Botan {

/*************************************************
* Container of output buffers for Pipe           *
*************************************************/
class Output_Buffers
   {
   public:
      u32bit read(byte[], u32bit, u32bit);
      u32bit peek(byte[], u32bit, u32bit, u32bit) const;
      u32bit remaining(u32bit) const;

      void add(class SecureQueue*);
      void retire();

      u32bit message_count() const;

      Output_Buffers();
      ~Output_Buffers();
   private:
      class SecureQueue* get(u32bit) const;

      std::deque<SecureQueue*> buffers;
      u32bit offset;
   };

}

#endif
