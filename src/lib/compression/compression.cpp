/*
* Compression Factory
* (C) 2014,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/compression.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <cstdlib>

#if defined(BOTAN_HAS_ZLIB)
   #include <botan/zlib.h>
#endif

#if defined(BOTAN_HAS_BZIP2)
   #include <botan/bzip2.h>
#endif

#if defined(BOTAN_HAS_LZMA)
   #include <botan/lzma.h>
#endif

namespace Botan {

//static
std::unique_ptr<Compression_Algorithm> Compression_Algorithm::create(std::string_view name) {
#if defined(BOTAN_HAS_ZLIB)
   if(name == "Zlib" || name == "zlib") {
      return std::make_unique<Zlib_Compression>();
   }
   if(name == "Gzip" || name == "gzip" || name == "gz") {
      return std::make_unique<Gzip_Compression>();
   }
   if(name == "Deflate" || name == "deflate") {
      return std::make_unique<Deflate_Compression>();
   }
#endif

#if defined(BOTAN_HAS_BZIP2)
   if(name == "bzip2" || name == "bz2" || name == "Bzip2") {
      return std::make_unique<Bzip2_Compression>();
   }
#endif

#if defined(BOTAN_HAS_LZMA)
   if(name == "lzma" || name == "xz" || name == "LZMA") {
      return std::make_unique<LZMA_Compression>();
   }
#endif

   BOTAN_UNUSED(name);
   return nullptr;
}

//static
std::unique_ptr<Compression_Algorithm> Compression_Algorithm::create_or_throw(std::string_view algo) {
   if(auto compressor = Compression_Algorithm::create(algo)) {
      return compressor;
   }
   throw Lookup_Error("Compression", algo, "");
}

//static
std::unique_ptr<Decompression_Algorithm> Decompression_Algorithm::create(std::string_view name) {
#if defined(BOTAN_HAS_ZLIB)
   if(name == "Zlib" || name == "zlib") {
      return std::make_unique<Zlib_Decompression>();
   }
   if(name == "Gzip" || name == "gzip" || name == "gz") {
      return std::make_unique<Gzip_Decompression>();
   }
   if(name == "Deflate" || name == "deflate") {
      return std::make_unique<Deflate_Decompression>();
   }
#endif

#if defined(BOTAN_HAS_BZIP2)
   if(name == "bzip2" || name == "bz2" || name == "Bzip2") {
      return std::make_unique<Bzip2_Decompression>();
   }
#endif

#if defined(BOTAN_HAS_LZMA)
   if(name == "lzma" || name == "xz" || name == "LZMA") {
      return std::make_unique<LZMA_Decompression>();
   }
#endif

   BOTAN_UNUSED(name);
   return nullptr;
}

//static
std::unique_ptr<Decompression_Algorithm> Decompression_Algorithm::create_or_throw(std::string_view algo) {
   if(auto decompressor = Decompression_Algorithm::create(algo)) {
      return decompressor;
   }
   throw Lookup_Error("Decompression", algo, "");
}

}  // namespace Botan
