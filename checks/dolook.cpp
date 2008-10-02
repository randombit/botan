#include <vector>
#include <string>

#include <botan/lookup.h>
#include <botan/filters.h>
#include <botan/libstate.h>

#ifdef BOTAN_HAS_COMPRESSOR_BZIP2
#include <botan/bzip2.h>
#endif

#ifdef BOTAN_HAS_COMPRESSOR_GZIP
#include <botan/gzip.h>
#endif

#ifdef BOTAN_HAS_COMPRESSOR_ZLIB
#include <botan/zlib.h>
#endif

using namespace Botan;

#include "common.h"

Filter* lookup(const std::string& algname,
               const std::vector<std::string>& params,
               const std::string& section)
   {
   std::string key = params[0];
   std::string iv = params[1];
   Filter* filter = 0;

   // The order of the lookup has to change based on how the names are
   // formatted and parsed.
   filter = lookup_kdf(algname, key, iv);
   if(filter) return filter;

   if(section == "Cipher Modes (Decryption)")
      filter = lookup_cipher(algname, key, iv, false);
   else
      filter = lookup_cipher(algname, key, iv, true);
   if(filter) return filter;

   filter = lookup_block(algname, key);
   if(filter) return filter;

   filter = lookup_rng(algname, key);
   if(filter) return filter;

   filter = lookup_encoder(algname);
   if(filter) return filter;

   filter = lookup_hash(algname);
   if(filter) return filter;

   filter = lookup_mac(algname, key);
   if(filter) return filter;

   filter = lookup_s2k(algname, params);
   if(filter) return filter;

   return 0;
   }

Filter* lookup_hash(const std::string& algname)
   {
   Filter* hash = 0;

   try {
      hash = new Hash_Filter(algname);
      }
   catch(Algorithm_Not_Found) {}

   return hash;
   }

Filter* lookup_mac(const std::string& algname, const std::string& key)
   {
   Filter* mac = 0;
   try {
      mac = new MAC_Filter(algname, key);
      }
   catch(Algorithm_Not_Found) {}

   return mac;
   }

Filter* lookup_cipher(const std::string& algname, const std::string& key,
                    const std::string& iv, bool encrypt)
   {
   try {
      if(encrypt)
         return get_cipher(algname, key, iv, ENCRYPTION);
      else
         return get_cipher(algname, key, iv, DECRYPTION);
      }
   catch(Algorithm_Not_Found) {}
   catch(Invalid_Algorithm_Name) {}
   return 0;
   }

Filter* lookup_encoder(const std::string& algname)
   {
   if(algname == "Base64_Encode")
      return new Base64_Encoder;
   if(algname == "Base64_Decode")
      return new Base64_Decoder;

#ifdef BOTAN_HAS_COMPRESSOR_BZIP2
   if(algname == "Bzip_Compression")
      return new Bzip_Compression(9);
   if(algname == "Bzip_Decompression")
      return new Bzip_Decompression;
#endif

#ifdef BOTAN_HAS_COMPRESSOR_GZIP
   if(algname == "Gzip_Compression")
      return new Gzip_Compression(9);
   if(algname == "Gzip_Decompression")
      return new Gzip_Decompression;
#endif

#ifdef BOTAN_HAS_COMPRESSOR_ZLIB
   if(algname == "Zlib_Compression")
      return new Zlib_Compression(9);
   if(algname == "Zlib_Decompression")
      return new Zlib_Decompression;
#endif

   return 0;
   }
