/*************************************************
* Buffered EntropySource Source File             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/buf_es.h>
#include <botan/bit_ops.h>
#include <botan/util.h>
#include <algorithm>

namespace Botan {

/*************************************************
* Buffered_EntropySource Constructor             *
*************************************************/
Buffered_EntropySource::Buffered_EntropySource() : buffer(256)
   {
   read_pos = write_pos = 0;
   done_slow_poll = false;
   }

/*************************************************
* Fast Poll                                      *
*************************************************/
u32bit Buffered_EntropySource::fast_poll(byte out[], u32bit length)
   {
   if(!done_slow_poll) { do_slow_poll(); done_slow_poll = true; }

   do_fast_poll();
   return copy_out(out, length, buffer.size() / 4);
   }

/*************************************************
* Slow Poll                                      *
*************************************************/
u32bit Buffered_EntropySource::slow_poll(byte out[], u32bit length)
   {
   do_slow_poll();
   return copy_out(out, length, buffer.size());
   }

/*************************************************
* Default fast poll operation                    *
*************************************************/
void Buffered_EntropySource::do_fast_poll()
   {
   return do_slow_poll();
   }

/*************************************************
* Add entropy to the internal buffer             *
*************************************************/
void Buffered_EntropySource::add_bytes(const void* entropy_ptr, u32bit length)
   {
   const byte* bytes = (const byte*)entropy_ptr;
   while(length)
      {
      u32bit copied = std::min(length, buffer.size() - write_pos);
      xor_buf(buffer + write_pos, bytes, copied);
      bytes += copied;
      length -= copied;
      write_pos = (write_pos + copied) % buffer.size();
      }
   }

/*************************************************
* Add entropy to the internal buffer             *
*************************************************/
void Buffered_EntropySource::add_bytes(u64bit entropy)
   {
   add_bytes((const void*)&entropy, 8);
   }

/*************************************************
* Add entropy to the internal buffer             *
*************************************************/
void Buffered_EntropySource::add_timestamp()
   {
   add_bytes(system_clock());
   }

/*************************************************
* Take entropy from the internal buffer          *
*************************************************/
u32bit Buffered_EntropySource::copy_out(byte out[], u32bit length,
                                        u32bit max_read)
   {
   length = std::min(length, max_read);
   u32bit copied = std::min(length, buffer.size() - read_pos);
   xor_buf(out, buffer + read_pos, copied);
   read_pos = (read_pos + copied) % buffer.size();
   return copied;
   }

}
