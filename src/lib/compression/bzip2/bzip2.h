/*
* Bzip Compressor
* (C) 2001 Peter J Jones
*     2001-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BZIP2_H__
#define BOTAN_BZIP2_H__

#include <botan/compression.h>

namespace Botan {

/**
* Bzip Compression
*/
class BOTAN_DLL Bzip_Compression : public Stream_Compression
   {
   public:
      /**
      * @param level how much effort to use on compressing (0 to 9);
      *        higher levels are slower but tend to give better
      *        compression
      */
      Bzip_Compression(size_t level = 6) : m_level(level) {}

      std::string name() const override { return "Bzip_Compression"; }

   private:
      Compression_Stream* make_stream() const;

      const size_t m_level;
   };

/**
* Bzip Deccompression
*/
class BOTAN_DLL Bzip_Decompression : public Stream_Decompression
   {
   public:
      std::string name() const override { return "Bzip_Decompression"; }
   private:
      Compression_Stream* make_stream() const;
   };

}

#endif
