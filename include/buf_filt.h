/*************************************************
* Buffering Filter Header File                   *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_BUFFERING_FILTER_H__
#define BOTAN_BUFFERING_FILTER_H__

#include <botan/filter.h>

namespace Botan {

/*************************************************
* Buffering Filter                               *
*************************************************/
class Buffering_Filter : public Filter
   {
   public:
      void write(const byte[], u32bit);
      virtual void end_msg();
      Buffering_Filter(u32bit, u32bit = 0);
      virtual ~Buffering_Filter() {}
   protected:
      virtual void initial_block(const byte[]) {}
      virtual void main_block(const byte[]) = 0;
      virtual void final_block(const byte[], u32bit) = 0;
   private:
      const u32bit INITIAL_BLOCK_SIZE, BLOCK_SIZE;
      SecureVector<byte> initial, block;
      u32bit initial_block_pos, block_pos;
   };

}

#endif
