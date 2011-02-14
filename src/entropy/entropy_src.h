/*
* EntropySource
* (C) 2008-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENTROPY_SOURCE_BASE_H__
#define BOTAN_ENTROPY_SOURCE_BASE_H__

#include <botan/buf_comp.h>
#include <string>

namespace Botan {

/**
* Class used to accumulate the poll results of EntropySources
*/
class BOTAN_DLL Entropy_Accumulator
   {
   public:
      /**
      * Initialize an Entropy_Accumulator
      * @param goal is how many bits we would like to collect
      */
      Entropy_Accumulator(size_t goal) :
         entropy_goal(goal), collected_bits(0) {}

      virtual ~Entropy_Accumulator() {}

      /**
      * Get a cached I/O buffer (purely for minimizing allocation
      * overhead to polls)
      *
      * @param size requested size for the I/O buffer
      * @return cached I/O buffer for repeated polls
      */
      MemoryRegion<byte>& get_io_buffer(size_t size)
         { io_buffer.resize(size); return io_buffer; }

      /**
      * @return number of bits collected so far
      */
      size_t bits_collected() const
         { return static_cast<size_t>(collected_bits); }

      /**
      * @return if our polling goal has been achieved
      */
      bool polling_goal_achieved() const
         { return (collected_bits >= entropy_goal); }

      /**
      * @return how many bits we need to reach our polling goal
      */
      size_t desired_remaining_bits() const
         {
         if(collected_bits >= entropy_goal)
            return 0;
         return static_cast<size_t>(entropy_goal - collected_bits);
         }

      /**
      * Add entropy to the accumulator
      * @param bytes the input bytes
      * @param length specifies how many bytes the input is
      * @param entropy_bits_per_byte is a best guess at how much
      * entropy per byte is in this input
      */
      void add(const void* bytes, size_t length, double entropy_bits_per_byte)
         {
         add_bytes(reinterpret_cast<const byte*>(bytes), length);
         collected_bits += entropy_bits_per_byte * length;
         }

      /**
      * Add entropy to the accumulator
      * @param v is some value
      * @param entropy_bits_per_byte is a best guess at how much
      * entropy per byte is in this input
      */
      template<typename T>
      void add(const T& v, double entropy_bits_per_byte)
         {
         add(&v, sizeof(T), entropy_bits_per_byte);
         }
   private:
      virtual void add_bytes(const byte bytes[], size_t length) = 0;

      SecureVector<byte> io_buffer;
      size_t entropy_goal;
      double collected_bits;
   };

/**
* Entropy accumulator that puts the input into a Buffered_Computation
*/
class BOTAN_DLL Entropy_Accumulator_BufferedComputation :
   public Entropy_Accumulator
   {
   public:
      /**
      * @param sink the hash or MAC we are feeding the poll data into
      * @param goal is how many bits we want to collect in this poll
      */
      Entropy_Accumulator_BufferedComputation(Buffered_Computation& sink,
                                              size_t goal) :
         Entropy_Accumulator(goal), entropy_sink(sink) {}

   private:
      virtual void add_bytes(const byte bytes[], size_t length)
         {
         entropy_sink.update(bytes, length);
         }

      Buffered_Computation& entropy_sink;
   };

/**
* Abstract interface to a source of (hopefully unpredictable) system entropy
*/
class BOTAN_DLL EntropySource
   {
   public:
      /**
      * @return name identifying this entropy source
      */
      virtual std::string name() const = 0;

      /**
      * Perform an entropy gathering poll
      * @param accum is an accumulator object that will be given entropy
      */
      virtual void poll(Entropy_Accumulator& accum) = 0;

      virtual ~EntropySource() {}
   };

}

#endif
