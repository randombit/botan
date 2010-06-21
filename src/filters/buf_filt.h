/*
* Buffered Filter
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BUFFERED_FILTER_H__
#define BOTAN_BUFFERED_FILTER_H__

#include <botan/secmem.h>

namespace Botan {

/**
* Filter mixin that breaks input into blocks, useful for
* cipher modes
*/
class BOTAN_DLL Buffered_Filter
   {
   public:
      void write(const byte[], u32bit);
      void end_msg();

      Buffered_Filter(u32bit block_size, u32bit final_minimum);

      virtual ~Buffered_Filter() {}
   protected:
      /**
      * @return name of this filter object
      */
      virtual std::string name() const = 0;

      virtual void buffered_block(const byte input[], u32bit length) = 0;
      virtual void buffered_final(const byte input[], u32bit length) = 0;

      /**
      * @return block size of inputs
      */
      u32bit buffered_block_size() const { return main_block_mod; }

      /**
      * @return current position in the buffer
      */
      u32bit current_position() const { return buffer_pos; }

      /**
      * Reset the buffer position
      */
      void buffer_reset() { buffer_pos = 0; }
   private:
      u32bit main_block_mod, final_minimum;

      SecureVector<byte> buffer;
      u32bit buffer_pos;
   };

}

#endif
