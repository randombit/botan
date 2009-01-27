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
      Entropy_Accumulator(BufferedComputation& sink, u32bit goal) :
         entropy_sink(sink), entropy_goal(goal), collected_bits(0) {}

      /**
      @return cached I/O buffer for repeated polls
      */
      MemoryRegion<byte>& get_io_buffer(u32bit size)
         { io_buffer.create(size); return io_buffer; }

      u32bit bits_collected() const { return collected_bits; }

      bool polling_goal_achieved() const
         { return (collected_bits >= entropy_goal); }

      u32bit desired_remaining_bits() const
         {
         return (collected_bits >= entropy_goal) ? 0 : (entropy_goal - collected_bits);
         }

      void add(const void* bytes, u32bit length, u32bit estimated_entropy)
         {
         entropy_sink.update(reinterpret_cast<const byte*>(bytes), length);
         collected_bits += std::min(estimated_entropy, length * 8);
         }

      template<typename T>
      void add(const T& v, u32bit estimated_entropy)
         {
         add(&v, sizeof(T), estimated_entropy);
         }
   private:
      BufferedComputation& entropy_sink;
      SecureVector<byte> io_buffer;
      u32bit entropy_goal, collected_bits;
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
