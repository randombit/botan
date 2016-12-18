/*
* Zlib Compressor
* (C) 2001 Peter J Jones
*     2001-2007,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ZLIB_H__
#define BOTAN_ZLIB_H__

#include <botan/compression.h>

namespace Botan {

/**
* Zlib Compression
*/
class BOTAN_DLL Zlib_Compression final : public Stream_Compression
   {
   public:
      std::string name() const override { return "Zlib_Compression"; }
   private:
      Compression_Stream* make_stream(size_t level) const override;
   };

/**
* Zlib Decompression
*/
class BOTAN_DLL Zlib_Decompression final : public Stream_Decompression
   {
   public:
      std::string name() const override { return "Zlib_Decompression"; }
   private:
      Compression_Stream* make_stream() const override;
   };

/**
* Deflate Compression
*/
class BOTAN_DLL Deflate_Compression final : public Stream_Compression
   {
   public:
      std::string name() const override { return "Deflate_Compression"; }
   private:
      Compression_Stream* make_stream(size_t level) const override;
   };

/**
* Deflate Decompression
*/
class BOTAN_DLL Deflate_Decompression final : public Stream_Decompression
   {
   public:
      std::string name() const override { return "Deflate_Decompression"; }
   private:
      Compression_Stream* make_stream() const override;
   };

/**
* Gzip Compression
*/
class BOTAN_DLL Gzip_Compression final : public Stream_Compression
   {
   public:
      Gzip_Compression(uint8_t os_code = 255) : m_os_code(os_code) {}

      std::string name() const override { return "Gzip_Compression"; }
   private:
      Compression_Stream* make_stream(size_t level) const override;
      const uint8_t m_os_code;
   };

/**
* Gzip Decompression
*/
class BOTAN_DLL Gzip_Decompression final : public Stream_Decompression
   {
   public:
      std::string name() const override { return "Gzip_Decompression"; }
   private:
      Compression_Stream* make_stream() const override;
   };

}

#endif
