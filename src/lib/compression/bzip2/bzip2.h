/*
* Bzip2 Compressor
* (C) 2001 Peter J Jones
*     2001-2007,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BZIP2_H__
#define BOTAN_BZIP2_H__

#include <botan/compression.h>

namespace Botan {

/**
* Bzip2 Compression
*/
class BOTAN_DLL Bzip2_Compression final : public Stream_Compression
   {
   public:
      std::string name() const override { return "Bzip2_Compression"; }
   private:
      Compression_Stream* make_stream(size_t comp_level) const override;
   };

/**
* Bzip2 Deccompression
*/
class BOTAN_DLL Bzip2_Decompression final : public Stream_Decompression
   {
   public:
      std::string name() const override { return "Bzip2_Decompression"; }
   private:
      Compression_Stream* make_stream() const override;
   };

}

#endif
