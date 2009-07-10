/**
* EntropySource
* (C) 2008-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
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
      Entropy_Accumulator(u32bit goal) :
         entropy_goal(goal), collected_bits(0) {}

      virtual ~Entropy_Accumulator() {}

      /**
      @return cached I/O buffer for repeated polls
      */
      MemoryRegion<byte>& get_io_buffer(u32bit size)
         { io_buffer.create(size); return io_buffer; }

      u32bit bits_collected() const
         { return static_cast<u32bit>(collected_bits); }

      bool polling_goal_achieved() const
         { return (collected_bits >= entropy_goal); }

      u32bit desired_remaining_bits() const
         {
         if(collected_bits >= entropy_goal)
            return 0;
         return static_cast<u32bit>(entropy_goal - collected_bits);
         }

      void add(const void* bytes, u32bit length, double entropy_bits_per_byte)
         {
         add_bytes(reinterpret_cast<const byte*>(bytes), length);
         collected_bits += entropy_bits_per_byte * length;
         }

      template<typename T>
      void add(const T& v, double entropy_bits_per_byte)
         {
         add(&v, sizeof(T), entropy_bits_per_byte);
         }
   private:
      virtual void add_bytes(const byte bytes[], u32bit length) = 0;

      SecureVector<byte> io_buffer;
      u32bit entropy_goal;
      double collected_bits;
   };

class Entropy_Accumulator_BufferedComputation : public Entropy_Accumulator
   {
   public:
      Entropy_Accumulator_BufferedComputation(BufferedComputation& sink,
                                              u32bit goal) :
         Entropy_Accumulator(goal), entropy_sink(sink) {}

   private:
      virtual void add_bytes(const byte bytes[], u32bit length)
         {
         entropy_sink.update(bytes, length);
         }

      BufferedComputation& entropy_sink;
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
