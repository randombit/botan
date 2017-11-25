/*
* Compression Factory
* (C) 2014,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/compression.h>
#include <botan/mem_ops.h>
#include <botan/exceptn.h>
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

Compression_Algorithm* make_compressor(const std::string& name)
   {
#if defined(BOTAN_HAS_ZLIB)
   if(name == "Zlib" || name == "zlib")
      return new Zlib_Compression;
   if(name == "Gzip" || name == "gzip" || name == "gz")
      return new Gzip_Compression;
   if(name == "Deflate" || name == "deflate")
      return new Deflate_Compression;
#endif

#if defined(BOTAN_HAS_BZIP2)
   if(name == "bzip2" || name == "bz2" || name == "Bzip2")
      return new Bzip2_Compression;
#endif

#if defined(BOTAN_HAS_LZMA)
   if(name == "lzma" || name == "xz" || name == "LZMA")
      return new LZMA_Compression;
#endif

   BOTAN_UNUSED(name);
   return nullptr;
   }

//static
std::unique_ptr<Compression_Algorithm>
Compression_Algorithm::create(const std::string& algo)
   {
   std::unique_ptr<Compression_Algorithm> compressor(make_compressor(algo));
   return compressor;
   }

//static
std::unique_ptr<Compression_Algorithm>
Compression_Algorithm::create_or_throw(const std::string& algo)
   {
   if(auto compressor = Compression_Algorithm::create(algo))
      {
      return compressor;
      }
   throw Lookup_Error("Compression", algo, "");
   }

Decompression_Algorithm* make_decompressor(const std::string& name)
   {
#if defined(BOTAN_HAS_ZLIB)
   if(name == "Zlib" || name == "zlib")
      return new Zlib_Decompression;
   if(name == "Gzip" || name == "gzip" || name == "gz")
      return new Gzip_Decompression;
   if(name == "Deflate" || name == "deflate")
      return new Deflate_Decompression;
#endif

#if defined(BOTAN_HAS_BZIP2)
   if(name == "bzip2" || name == "bz2" || name == "Bzip2")
      return new Bzip2_Decompression;
#endif

#if defined(BOTAN_HAS_LZMA)
   if(name == "lzma" || name == "xz" || name == "LZMA")
      return new LZMA_Decompression;
#endif

   BOTAN_UNUSED(name);
   return nullptr;
   }

//static
std::unique_ptr<Decompression_Algorithm>
Decompression_Algorithm::create(const std::string& algo)
   {
   std::unique_ptr<Decompression_Algorithm> decompressor(make_decompressor(algo));
   return decompressor;
   }

//static
std::unique_ptr<Decompression_Algorithm>
Decompression_Algorithm::create_or_throw(const std::string& algo)
   {
   if(auto decompressor = Decompression_Algorithm::create(algo))
      {
      return decompressor;
      }
   throw Lookup_Error("Decompression", algo, "");
   }

}

