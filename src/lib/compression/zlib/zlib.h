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
* Zlib Compression as definded in RFC 1950
*/
class BOTAN_DLL Zlib_Compression : public Stream_Compression
   {
   public:
      /**
      * @param level how much effort to use on compressing (0 to 9);
      *        higher levels are slower but tend to give better
      *        compression
      */

      Zlib_Compression(size_t level = 6) : m_level(level) {}

      std::string name() const override { return "Zlib_Compression"; }

   private:
      Compression_Stream* make_stream() const override;

      const size_t m_level;
   };

/**
* Zlib Decompression as definded in RFC 1950
*/
class BOTAN_DLL Zlib_Decompression : public Stream_Decompression
   {
   public:
      std::string name() const override { return "Zlib_Decompression"; }

   private:
      Compression_Stream* make_stream() const override;
   };

/**
* Deflate Compression as defined in RFC 1951
*/
class BOTAN_DLL Deflate_Compression : public Stream_Compression
   {
   public:
      /**
      * @param level how much effort to use on compressing (0 to 9);
      *        higher levels are slower but tend to give better
      *        compression
      */
      Deflate_Compression(size_t level = 6) : m_level(level) {}

      std::string name() const override { return "Deflate_Compression"; }

   private:
      Compression_Stream* make_stream() const override;

      const size_t m_level;
   };

/**
* Deflate Decompression as defined in RFC 1951
*/
class BOTAN_DLL Deflate_Decompression : public Stream_Decompression
   {
   public:
      std::string name() const override { return "Deflate_Decompression"; }

   private:
      Compression_Stream* make_stream() const override;
   };

/**
* Gzip Compression as defined in RFC 1952
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
      Compression_Stream* make_stream() const override;

      const size_t m_level;
      const byte m_os_code;
   };

/**
* Gzip Decompression as defined in RFC 1952
*/
class BOTAN_DLL Gzip_Decompression : public Stream_Decompression
   {
   public:
      std::string name() const override { return "Gzip_Decompression"; }

   private:
      Compression_Stream* make_stream() const override;
   };

}

#endif
