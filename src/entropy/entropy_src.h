/**
* EntropySource Header File
* (C) 2008-2009 Jack Lloyd
*/

#ifndef BOTAN_ENTROPY_SOURCE_BASE_H__
#define BOTAN_ENTROPY_SOURCE_BASE_H__

#include <botan/buf_comp.h>
#include <string>
#include <utility>

namespace Botan {

/**
* Class used to accumulate the poll results of EntropySources
*/
class Entropy_Accumulator
   {
   public:
      Entropy_Accumulator(u32bit entropy_goal)
         { reset_goal(entropy_goal); }

      const MemoryRegion<byte>& get_entropy_buffer() const
         { return entropy_buf; }

      MemoryRegion<byte>& get_io_buffer(u32bit size);

      void reset_goal(u32bit entropy_goal);

      u32bit bits_collected() const { return collected_bits; }

      bool polling_goal_achieved() const;

      u32bit desired_remaining_bits() const;

      void add(const void* bytes, u32bit length, double bits_per_byte);

      template<typename T>
      void add(const T& v, double bits_per_byte)
         {
         add(&v, sizeof(T), bits_per_byte);
         }
   private:
      SecureVector<byte> io_buffer, entropy_buf;
      u32bit collected_bits, goal_bits;
   };

/**
* Abstract interface to a source of (hopefully unpredictable) system entropy
*/
class BOTAN_DLL EntropySource
   {
   public:
      virtual std::string name() const = 0;
      virtual void poll(Entropy_Accumulator& accum) = 0;
      virtual ~EntropySource() {}
   };

}

#endif
