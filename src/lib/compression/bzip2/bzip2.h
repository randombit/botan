/*
* Bzip2 Compressor
* (C) 2001 Peter J Jones
*     2001-2007,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BZIP2_H_
#define BOTAN_BZIP2_H_

#include <botan/compression.h>

namespace Botan {

/**
* Bzip2 Compression
*/
class BOTAN_PUBLIC_API(2, 0) Bzip2_Compression final : public Stream_Compression {
   public:
      std::string name() const override { return "Bzip2_Compression"; }

   private:
      std::unique_ptr<Compression_Stream> make_stream(size_t comp_level) const override;
};

/**
* Bzip2 Deccompression
*/
class BOTAN_PUBLIC_API(2, 0) Bzip2_Decompression final : public Stream_Decompression {
   public:
      std::string name() const override { return "Bzip2_Decompression"; }

   private:
      std::unique_ptr<Compression_Stream> make_stream() const override;
};

}  // namespace Botan

#endif
