/*
* Lzma Compressor
* (C) 2001 Peter J Jones
*     2001-2007 Jack Lloyd
*     2012 Vojtech Kral
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_LZMA_H__
#define BOTAN_LZMA_H__

#include <botan/compression.h>

namespace Botan {

/**
* LZMA Compression
*/
class BOTAN_DLL LZMA_Compression : public Stream_Compression
   {
   public:
      /**
      * @param level how much effort to use on compressing (0 to 9);
      *        higher levels are slower but tend to give better
      *        compression
      */
      LZMA_Compression(size_t level = 6) : m_level(level) {}

      std::string name() const override { return "LZMA_Compression"; }

   private:
      Compression_Stream* make_stream() const override;

      const size_t m_level;
   };

/**
* LZMA Deccompression
*/
class BOTAN_DLL LZMA_Decompression : public Stream_Decompression
   {
   public:
      std::string name() const override { return "LZMA_Decompression"; }
   private:
      Compression_Stream* make_stream() const override;
   };

}

#endif
