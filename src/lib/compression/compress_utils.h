/*
* Compression utility header
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_COMPRESSION_UTILS_H_
#define BOTAN_COMPRESSION_UTILS_H_

#include <botan/compression.h>

#include <botan/mem_ops.h>
#include <memory>
#include <unordered_map>

namespace Botan {

/*
* Allocation Size Tracking Helper for Zlib/Bzlib/LZMA
*/
class Compression_Alloc_Info final {
   public:
      template <typename T>
      static void* malloc(void* self, T n, T size) {
         return static_cast<Compression_Alloc_Info*>(self)->do_malloc(n, size);
      }

      static void free(void* self, void* ptr) { static_cast<Compression_Alloc_Info*>(self)->do_free(ptr); }

   private:
      void* do_malloc(size_t n, size_t size);
      void do_free(void* ptr);

      std::unordered_map<void*, size_t> m_current_allocs;
};

/**
* Wrapper for Zlib/Bzlib/LZMA stream types
*/
template <typename Stream, typename ByteType, typename StreamLenType = size_t>
class Zlib_Style_Stream : public Compression_Stream {
   public:
      void next_in(uint8_t* b, size_t len) override {
         m_stream.next_in = reinterpret_cast<ByteType*>(b);
         m_stream.avail_in = static_cast<StreamLenType>(len);
      }

      void next_out(uint8_t* b, size_t len) override {
         m_stream.next_out = reinterpret_cast<ByteType*>(b);
         m_stream.avail_out = static_cast<StreamLenType>(len);
      }

      size_t avail_in() const override { return m_stream.avail_in; }

      size_t avail_out() const override { return m_stream.avail_out; }

      Zlib_Style_Stream() : m_allocs(std::make_unique<Compression_Alloc_Info>()) { clear_mem(&m_stream, 1); }

      Zlib_Style_Stream(const Zlib_Style_Stream& other) = delete;
      Zlib_Style_Stream(Zlib_Style_Stream&& other) = delete;
      Zlib_Style_Stream& operator=(const Zlib_Style_Stream& other) = delete;
      Zlib_Style_Stream& operator=(Zlib_Style_Stream&& other) = delete;

      ~Zlib_Style_Stream() override { clear_mem(&m_stream, 1); }

   protected:
      typedef Stream stream_t;

      stream_t* streamp() { return &m_stream; }

      Compression_Alloc_Info* alloc() { return m_allocs.get(); }

   private:
      stream_t m_stream;
      std::unique_ptr<Compression_Alloc_Info> m_allocs;
};

}  // namespace Botan

#endif
