/*
* Zlib Compressor
* (C) 2001 Peter J Jones
*     2001-2007,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ZLIB_H_
#define BOTAN_ZLIB_H_

#include <botan/compression.h>

namespace Botan {

/**
* Zlib Compression
*/
class BOTAN_PUBLIC_API(2,0) Zlib_Compression final : public Stream_Compression
   {
   public:
      std::string name() const override { return "Zlib_Compression"; }
   private:
      Compression_Stream* make_stream(size_t level) const override;
   };

/**
* Zlib Decompression
*/
class BOTAN_PUBLIC_API(2,0) Zlib_Decompression final : public Stream_Decompression
   {
   public:
      std::string name() const override { return "Zlib_Decompression"; }
   private:
      Compression_Stream* make_stream() const override;
   };

/**
* Deflate Compression
*/
class BOTAN_PUBLIC_API(2,0) Deflate_Compression final : public Stream_Compression
   {
   public:
      std::string name() const override { return "Deflate_Compression"; }
   private:
      Compression_Stream* make_stream(size_t level) const override;
   };

/**
* Deflate Decompression
*/
class BOTAN_PUBLIC_API(2,0) Deflate_Decompression final : public Stream_Decompression
   {
   public:
      std::string name() const override { return "Deflate_Decompression"; }
   private:
      Compression_Stream* make_stream() const override;
   };

/**
* Gzip Compression
*/
class BOTAN_PUBLIC_API(2,0) Gzip_Compression final : public Stream_Compression
   {
   public:
      explicit Gzip_Compression(uint8_t os_code = 255, uint64_t hdr_time = 0) :
         m_hdr_time(hdr_time), m_os_code(os_code) {}

      std::string name() const override { return "Gzip_Compression"; }
   private:
      Compression_Stream* make_stream(size_t level) const override;
      const uint64_t m_hdr_time;
      const uint8_t m_os_code;
   };

/**
* Gzip Decompression
*/
class BOTAN_PUBLIC_API(2,0) Gzip_Decompression final : public Stream_Decompression
   {
   public:
      std::string name() const override { return "Gzip_Decompression"; }
   private:
      Compression_Stream* make_stream() const override;
   };

}

#endif
