/*************************************************
* Buffered EntropySource Header File             *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_BUFFERED_ES_H__
#define BOTAN_BUFFERED_ES_H__

#include <botan/rng.h>
#include <botan/secmem.h>

namespace Botan {

/*************************************************
* Buffered EntropySource                         *
*************************************************/
class BOTAN_DLL Buffered_EntropySource : public EntropySource
   {
   public:
      u32bit slow_poll(byte[], u32bit);
      u32bit fast_poll(byte[], u32bit);
   protected:
      Buffered_EntropySource();
      u32bit copy_out(byte[], u32bit, u32bit);

      void add_bytes(const void*, u32bit);
      void add_bytes(u64bit);

      virtual void do_slow_poll() = 0;
      virtual void do_fast_poll();
   private:
      SecureVector<byte> buffer;
      u32bit write_pos, read_pos;
      bool done_slow_poll;
   };

}

#endif
