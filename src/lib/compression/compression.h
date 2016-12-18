/*
* Compression Transform
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_COMPRESSION_TRANSFORM_H__
#define BOTAN_COMPRESSION_TRANSFORM_H__

#include <botan/secmem.h>
#include <string>

namespace Botan {

/*
* Interface for a compression algorithm.
*/
class BOTAN_DLL Compression_Algorithm
   {
   public:
      /**
      * Begin compressing. Most compression algorithms offer a tunable
      * time/compression tradeoff parameter generally represented by
      * an integer in the range of 1 to 9.
      *
      * If 0 or a value out of range is provided, a compression algorithm
      * specific default is used.
      */
      virtual void start(size_t comp_level = 0) = 0;

      /**
      * Process some data. Input must be in size update_granularity() uint8_t blocks.
      * @param buf in/out parameter which will possibly be resized or swapped
      * @param offset an offset into blocks to begin processing
      * @param flush if true the compressor will be told to flush state
      */
      virtual void update(secure_vector<uint8_t>& buf, size_t offset = 0, bool flush = false) = 0;

      /**
      * Finish compressing
      *
      * @param final_block in/out parameter
      * @param offset an offset into final_block to begin processing
      */
      virtual void finish(secure_vector<uint8_t>& final_block, size_t offset = 0) = 0;

      /**
      * @return name of the compression algorithm
      */
      virtual std::string name() const = 0;

      /**
      * Reset the state and abort the current message; start can be
      * called again to process a new message.
      */
      virtual void clear() = 0;

      virtual ~Compression_Algorithm() {}
   };

/*
* Interface for a decompression algorithm.
*/
class BOTAN_DLL Decompression_Algorithm
   {
   public:
      /**
      * Begin decompressing.
      * Decompression does not support levels, as compression does.
      */
      virtual void start() = 0;

      /**
      * Process some data. Input must be in size update_granularity() uint8_t blocks.
      * @param buf in/out parameter which will possibly be resized or swapped
      * @param offset an offset into blocks to begin processing
      */
      virtual void update(secure_vector<uint8_t>& buf, size_t offset = 0) = 0;

      /**
      * Finish decompressing
      *
      * @param final_block in/out parameter
      * @param offset an offset into final_block to begin processing
      */
      virtual void finish(secure_vector<uint8_t>& final_block, size_t offset = 0) = 0;

      /**
      * @return name of the decompression algorithm
      */
      virtual std::string name() const = 0;

      /**
      * Reset the state and abort the current message; start can be
      * called again to process a new message.
      */
      virtual void clear() = 0;

      virtual ~Decompression_Algorithm() {}
   };

BOTAN_DLL Compression_Algorithm* make_compressor(const std::string& type);
BOTAN_DLL Decompression_Algorithm* make_decompressor(const std::string& type);

/**
* Adapts a zlib style API
*/
class Compression_Stream
   {
   public:
      virtual ~Compression_Stream() {}

      virtual void next_in(uint8_t* b, size_t len) = 0;

      virtual void next_out(uint8_t* b, size_t len) = 0;

      virtual size_t avail_in() const = 0;

      virtual size_t avail_out() const = 0;

      virtual uint32_t run_flag() const = 0;
      virtual uint32_t flush_flag() const = 0;
      virtual uint32_t finish_flag() const = 0;

      virtual bool run(uint32_t flags) = 0;
   };

/**
* Used to implement compression using Compression_Stream
*/
class Stream_Compression : public Compression_Algorithm
   {
   public:
      void update(secure_vector<uint8_t>& buf, size_t offset, bool flush) final override;

      void finish(secure_vector<uint8_t>& buf, size_t offset) final override;

      void clear() final override;

   private:
      void start(size_t level) final override;

      void process(secure_vector<uint8_t>& buf, size_t offset, uint32_t flags);

      virtual Compression_Stream* make_stream(size_t level) const = 0;

      secure_vector<uint8_t> m_buffer;
      std::unique_ptr<Compression_Stream> m_stream;
   };

/**
* FIXME add doc
*/
class Stream_Decompression : public Decompression_Algorithm
   {
   public:
      void update(secure_vector<uint8_t>& buf, size_t offset) final override;

      void finish(secure_vector<uint8_t>& buf, size_t offset) final override;

      void clear() final override;

   private:
      void start() final override;

      void process(secure_vector<uint8_t>& buf, size_t offset, uint32_t flags);

      virtual Compression_Stream* make_stream() const = 0;

      secure_vector<uint8_t> m_buffer;
      std::unique_ptr<Compression_Stream> m_stream;
   };

}

#endif
