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
class BOTAN_DLL Bzip2_Compression : public Stream_Compression
   {
   public:
      /**
      * @param block_size in 1024 KiB increments, in range from 1 to 9.
      *
      * Lowering this does not noticably modify the compression or
      * decompression speed, though less memory is required for both
      * compression and decompression.
      */
      Bzip2_Compression(size_t block_size = 9) : m_block_size(block_size) {}

      std::string name() const override { return "Bzip2_Compression"; }

   private:
      Compression_Stream* make_stream() const override;

      const size_t m_block_size;
   };

/**
* Bzip2 Deccompression
*/
class BOTAN_DLL Bzip2_Decompression : public Stream_Decompression
   {
   public:
      std::string name() const override { return "Bzip2_Decompression"; }
   private:
      Compression_Stream* make_stream() const override;
   };

}

#endif
