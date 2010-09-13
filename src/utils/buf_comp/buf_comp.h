/*
* BufferedComputation
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BUFFERED_COMPUTATION_H__
#define BOTAN_BUFFERED_COMPUTATION_H__

#include <botan/secmem.h>

namespace Botan {

/**
* This class represents any kind of computation which
* uses an internal state,
* such as hash functions.
*/
class BOTAN_DLL BufferedComputation
   {
   public:

      /**
      * The length of the output of this function in bytes.
      */
      const u32bit OUTPUT_LENGTH;

      /**
      * Add new input to process.
      * @param in the input to process as a byte array
      * @param length of param in in bytes
      */
      void update(const byte in[], u32bit length) { add_data(in, length); }

      /**
      * Add new input to process.
      * @param in the input to process as a MemoryRegion
      */
      void update(const MemoryRegion<byte>& in)
         {
         add_data(&in[0], in.size());
         }

      /**
      * Add new input to process.
      * @param str the input to process as a std::string. Will be interpreted
      * as a byte array based on
      * the strings encoding.
      */
      void update(const std::string& str)
         {
         add_data(reinterpret_cast<const byte*>(str.data()), str.size());
         }

      /**
      * Process a single byte.
      * @param in the byte to process
      */
      void update(byte in) { add_data(&in, 1); }

      /**
      * Complete the computation and retrieve the
      * final result.
      * @param out The byte array to be filled with the result.
      * Must be of length OUTPUT_LENGTH.
      */
      void final(byte out[]) { final_result(out); }

      /**
      * Complete the computation and retrieve the
      * final result.
      * @return SecureVector holding the result
      */
      SecureVector<byte> final()
         {
         SecureVector<byte> output(OUTPUT_LENGTH);
         final_result(&output[0]);
         return output;
         }

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process as a byte array
      * @param length the length of the byte array
      * @result the result of the call to final()
      */
      SecureVector<byte> process(const byte in[], u32bit length)
         {
         add_data(in, length);
         return final();
         }

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process
      * @result the result of the call to final()
      */
      SecureVector<byte> process(const MemoryRegion<byte>& in)
         {
         add_data(&in[0], in.size());
         return final();
         }

      /**
      * Update and finalize computation. Does the same as calling update()
      * and final() consecutively.
      * @param in the input to process as a string
      * @result the result of the call to final()
      */
      SecureVector<byte> process(const std::string& in)
         {
         update(in);
         return final();
         }

      /**
      * @param out_len the output length of this computation
      */
      BufferedComputation(u32bit out_len) : OUTPUT_LENGTH(out_len) {}

      virtual ~BufferedComputation() {}
   private:
      BufferedComputation& operator=(const BufferedComputation&);

      /**
      * Add more data to the computation
      * @param input is an input buffer
      * @param length is the length of input in bytes
      */
      virtual void add_data(const byte input[], u32bit length) = 0;

      /**
      * Write the final output to out
      * @param out is an output buffer of OUTPUT_LENGTH
      */
      virtual void final_result(byte out[]) = 0;
   };

}

#endif
