/*************************************************
* Buffered EntropySource Header File             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_BUFFERED_ES_H__
#define BOTAN_BUFFERED_ES_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* Buffered EntropySource                         *
*************************************************/
class Buffered_EntropySource : public EntropySource
   {
   public:
      u32bit slow_poll(byte[], u32bit);
      u32bit fast_poll(byte[], u32bit);
   protected:
      Buffered_EntropySource();
      u32bit copy_out(byte[], u32bit, u32bit);

      void add_bytes(const void*, u32bit);
      void add_bytes(u64bit);
      void add_timestamp();

      virtual void do_slow_poll() = 0;
      virtual void do_fast_poll();
   private:
      SecureVector<byte> buffer;
      u32bit write_pos, read_pos;
      bool done_slow_poll;
   };

}

#endif
