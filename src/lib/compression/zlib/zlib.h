/*
* Zlib Compressor
* (C) 2001 Peter J Jones
*     2001-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ZLIB_H__
#define BOTAN_ZLIB_H__

#include <botan/compression.h>

namespace Botan {

/**
* Zlib Compression
*/
class BOTAN_DLL Zlib_Compression : public Stream_Compression
   {
   public:
      /**
      * @param level how much effort to use on compressing (0 to 9);
      *        higher levels are slower but tend to give better
      *        compression
      * @param raw_deflate if true no zlib header/trailer will be used
      */
      Zlib_Compression(size_t level = 6, bool raw_deflate = false) :
         m_level(level), m_raw_deflate(raw_deflate) {}

      std::string name() const override { return "Zlib_Compression"; }

   private:
      Compression_Stream* make_stream() const;

      const size_t m_level;
      const bool m_raw_deflate;
   };

/**
* Zlib Deccompression
*/
class BOTAN_DLL Zlib_Decompression : public Stream_Decompression
   {
   public:
      /**
      * @param raw_deflate if true no zlib header/trailer will be used
      */
      Zlib_Decompression(bool raw_deflate = false) : m_raw_deflate(raw_deflate) {}

      std::string name() const override { return "Zlib_Decompression"; }

   private:
      Compression_Stream* make_stream() const;

      const bool m_raw_deflate;
   };

/**
* Gzip Compression
*/
class BOTAN_DLL Gzip_Compression : public Stream_Compression
   {
   public:
      /**
      * @param level how much effort to use on compressing (0 to 9);
      *        higher levels are slower but tend to give better
      *        compression
      */
      Gzip_Compression(size_t level = 6, byte os_code = 255) :
         m_level(level), m_os_code(os_code) {}

      std::string name() const override { return "Gzip_Compression"; }

   private:
      Compression_Stream* make_stream() const;

      const size_t m_level;
      const byte m_os_code;
   };

/**
* Gzip Decompression
*/
class BOTAN_DLL Gzip_Decompression : public Stream_Compression
   {
   public:
      std::string name() const override { return "Gzip_Decompression"; }

   private:
      Compression_Stream* make_stream() const;
   };

}

#endif
