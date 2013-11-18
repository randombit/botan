/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <vector>
#include <string>

#include <botan/lookup.h>
#include <botan/filters.h>
#include <botan/libstate.h>
#include <botan/hmac.h>
#include <botan/sha2_32.h>
#include <botan/sha2_64.h>
#include <botan/parsing.h>

#ifdef BOTAN_HAS_COMPRESSOR_BZIP2
#include <botan/bzip2.h>
#endif

#ifdef BOTAN_HAS_COMPRESSOR_GZIP
#include <botan/gzip.h>
#endif

#ifdef BOTAN_HAS_COMPRESSOR_ZLIB
#include <botan/zlib.h>
#endif

#if defined(BOTAN_HAS_RANDPOOL)
  #include <botan/randpool.h>
#endif

#if defined(BOTAN_HAS_HMAC_RNG)
  #include <botan/hmac_rng.h>
#endif

#if defined(BOTAN_HAS_AES)
  #include <botan/aes.h>
#endif

#if defined(BOTAN_HAS_DES)
  #include <botan/des.h>
#endif

#if defined(BOTAN_HAS_X931_RNG)
  #include <botan/x931_rng.h>
#endif

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   #include <botan/auto_rng.h>
#endif

using namespace Botan;

#include "common.h"

namespace {

/* Not too useful generally; just dumps random bits for benchmarking */
class RNG_Filter : public Filter
   {
   public:
      std::string name() const { return rng->name(); }

      void write(const byte[], size_t);

      RNG_Filter(RandomNumberGenerator* r) : rng(r) {}
      ~RNG_Filter() { delete rng; }
   private:
      RandomNumberGenerator* rng;
   };

void RNG_Filter::write(const byte[], size_t length)
   {
   if(length)
      {
      send(rng->random_vec(length));
      }
   }

Filter* lookup_rng(const std::string& algname,
                   const std::string& key)
   {
   if(algname.find("X9.31-RNG(") == std::string::npos)
      return nullptr;

   RandomNumberGenerator* prng = nullptr;

#if defined(BOTAN_HAS_X931_RNG)

#if defined(BOTAN_HAS_DES)
   if(algname == "X9.31-RNG(TripleDES)")
      prng = new ANSI_X931_RNG(new TripleDES,
                               new Fixed_Output_RNG(hex_decode(key)));
#endif

#if defined(BOTAN_HAS_AES)
   if(algname == "X9.31-RNG(AES-128)")
      prng = new ANSI_X931_RNG(new AES_128,
                               new Fixed_Output_RNG(hex_decode(key)));
   else if(algname == "X9.31-RNG(AES-192)")
      prng = new ANSI_X931_RNG(new AES_192,
                               new Fixed_Output_RNG(hex_decode(key)));
   else if(algname == "X9.31-RNG(AES-256)")
      prng = new ANSI_X931_RNG(new AES_256,
                               new Fixed_Output_RNG(hex_decode(key)));
#endif

#endif

   if(prng)
      {
      prng->add_entropy(reinterpret_cast<const byte*>(key.c_str()),
                        key.length());
      return new RNG_Filter(prng);
      }

   return nullptr;
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

   return nullptr;
   }

}

Filter* lookup(const std::string& algname,
               const std::vector<std::string>& params)
   {
   std::string key = params[0];
   std::string iv = params[1];
   Filter* filter = nullptr;

   // The order of the lookup has to change based on how the names are
   // formatted and parsed.
   filter = lookup_rng(algname, key);
   if(filter) return filter;

   filter = lookup_encoder(algname);
   if(filter) return filter;

   return nullptr;
   }

