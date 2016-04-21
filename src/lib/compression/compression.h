/*
* Compression Transform
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_COMPRESSION_TRANSFORM_H__
#define BOTAN_COMPRESSION_TRANSFORM_H__

#include <botan/secmem.h>
#include <botan/scan_name.h>

namespace Botan {

class BOTAN_DLL Compression_Algorithm
   {
   public:
      typedef SCAN_Name Spec;

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
      * Process some data. Input must be in size update_granularity() byte blocks.
      * @param blocks in/out parameter which will possibly be resized or swapped
      * @param offset an offset into blocks to begin processing
      * @param flush if true the compressor will be told to flush state
      */
      virtual void update(secure_vector<byte>& buf, size_t offset = 0, bool flush = false) = 0;

      /**
      * Finish compressing
      *
      * @param final_block in/out parameter
      * @param offset an offset into final_block to begin processing
      */
      virtual void finish(secure_vector<byte>& final_block, size_t offset = 0) = 0;

      virtual std::string name() const = 0;

      /**
      * Reset the state and abort the current message; start can be
      * called again to process a new message.
      */
      virtual void clear() = 0;

      virtual ~Compression_Algorithm() {}
   };

class BOTAN_DLL Decompression_Algorithm
   {
   public:
      typedef SCAN_Name Spec;

      /**
      * Decompression does not support levels
      */
      virtual void start() = 0;

      virtual void update(secure_vector<byte>& buf, size_t offset = 0) = 0;

      virtual void finish(secure_vector<byte>& final_block, size_t offset = 0) = 0;

      virtual std::string name() const = 0;

      virtual void clear() = 0;

      virtual ~Decompression_Algorithm() {}
   };

BOTAN_DLL Compression_Algorithm* make_compressor(const std::string& type);
BOTAN_DLL Decompression_Algorithm* make_decompressor(const std::string& type);

class Compression_Stream
   {
   public:
      virtual ~Compression_Stream() {}

      virtual void next_in(byte* b, size_t len) = 0;

      virtual void next_out(byte* b, size_t len) = 0;

      virtual size_t avail_in() const = 0;

      virtual size_t avail_out() const = 0;

      virtual u32bit run_flag() const = 0;
      virtual u32bit flush_flag() const = 0;
      virtual u32bit finish_flag() const = 0;

      virtual bool run(u32bit flags) = 0;
   };

class Stream_Compression : public Compression_Algorithm
   {
   public:
      void update(secure_vector<byte>& buf, size_t offset, bool flush) final override;

      void finish(secure_vector<byte>& buf, size_t offset) final override;

      void clear() final override;

   private:
      void start(size_t level) final override;

      void process(secure_vector<byte>& buf, size_t offset, u32bit flags);

      virtual Compression_Stream* make_stream(size_t level) const = 0;

      secure_vector<byte> m_buffer;
      std::unique_ptr<Compression_Stream> m_stream;
   };

class Stream_Decompression : public Decompression_Algorithm
   {
   public:
      void update(secure_vector<byte>& buf, size_t offset) final override;

      void finish(secure_vector<byte>& buf, size_t offset) final override;

      void clear() final override;

   private:
      void start() final override;

      void process(secure_vector<byte>& buf, size_t offset, u32bit flags);

      virtual Compression_Stream* make_stream() const = 0;

      secure_vector<byte> m_buffer;
      std::unique_ptr<Compression_Stream> m_stream;
   };

}

#endif
