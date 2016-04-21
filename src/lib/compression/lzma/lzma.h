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
class BOTAN_DLL LZMA_Compression final : public Stream_Compression
   {
   public:
      std::string name() const override { return "LZMA_Compression"; }

   private:
      Compression_Stream* make_stream(size_t level) const override;
   };

/**
* LZMA Deccompression
*/
class BOTAN_DLL LZMA_Decompression final : public Stream_Decompression
   {
   public:
      std::string name() const override { return "LZMA_Decompression"; }
   private:
      Compression_Stream* make_stream() const override;
   };

}

#endif
