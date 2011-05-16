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

/* A weird little hack to fit PBKDF algorithms into the validation
* suite You probably wouldn't ever want to actually use the PBKDF
* algorithms like this, the raw PBKDF interface is more convenient
* for actually using them
*/
class PBKDF_Filter : public Filter
   {
   public:
      std::string name() const { return pbkdf->name(); }

      void write(const byte in[], size_t len)
         { passphrase += std::string(reinterpret_cast<const char*>(in), len); }

      void end_msg()
         {
         SymmetricKey x = pbkdf->derive_key(outlen, passphrase,
                                          &salt[0], salt.size(),
                                          iterations);
         send(x.bits_of());
         }

      PBKDF_Filter(PBKDF* algo, const SymmetricKey& s, u32bit o, u32bit i)
         {
         pbkdf = algo;
         outlen = o;
         iterations = i;
         salt = s.bits_of();
         }

      ~PBKDF_Filter() { delete pbkdf; }
   private:
      std::string passphrase;
      PBKDF* pbkdf;
      SecureVector<byte> salt;
      u32bit outlen, iterations;
   };

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

class KDF_Filter : public Filter
   {
   public:
      std::string name() const { return "KDF_Filter"; }

      void write(const byte in[], size_t len)
         { secret += std::make_pair(in, len); }

      void end_msg()
         {
         SymmetricKey x = kdf->derive_key(outlen, secret, salt);
         send(x.bits_of(), x.length());
         }

      KDF_Filter(KDF* algo, const SymmetricKey& s, u32bit o)
         {
         kdf = algo;
         outlen = o;
         salt = s.bits_of();
         }
      ~KDF_Filter() { delete kdf; }
   private:
      SecureVector<byte> secret;
      SecureVector<byte> salt;
      KDF* kdf;
      u32bit outlen;
   };

Filter* lookup_pbkdf(const std::string& algname,
                   const std::vector<std::string>& params)
   {
   PBKDF* pbkdf = 0;

   try {
      pbkdf = get_pbkdf(algname);
      }
   catch(...) { }

   if(pbkdf)
      return new PBKDF_Filter(pbkdf, params[0], to_u32bit(params[1]),
                              to_u32bit(params[2]));
   return 0;
   }

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
   RandomNumberGenerator* prng = 0;

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   if(algname == "AutoSeeded")
      prng = new AutoSeeded_RNG;
#endif

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

#if defined(BOTAN_HAS_RANDPOOL) && defined(BOTAN_HAS_AES)
   if(algname == "Randpool")
      {
      prng = new Randpool(new AES_256, new HMAC(new SHA_256));

      prng->add_entropy(reinterpret_cast<const byte*>(key.c_str()),
                        key.length());
      }
#endif

#if defined(BOTAN_HAS_X931_RNG)
   // these are used for benchmarking: AES-256/SHA-256 matches library
   // defaults, so benchmark reflects real-world performance (maybe)
   if(algname == "X9.31-RNG")
      {
      RandomNumberGenerator* rng =
#if defined(BOTAN_HAS_HMAC_RNG)
         new HMAC_RNG(new HMAC(new SHA_512), new HMAC(new SHA_256));
#elif defined(BOTAN_HAS_RANDPOOL)
         new Randpool(new AES_256, new HMAC(new SHA_256));
#endif

      prng = new ANSI_X931_RNG(new AES_256, rng);

      }
#endif

#if defined(BOTAN_HAS_HMAC_RNG)
   if(algname == "HMAC_RNG")
      {
      prng = new HMAC_RNG(new HMAC(new SHA_512), new HMAC(new SHA_256));
      }
#endif

   if(prng)
      {
      prng->add_entropy(reinterpret_cast<const byte*>(key.c_str()),
                        key.length());
      return new RNG_Filter(prng);
      }

   return 0;
   }

Filter* lookup_kdf(const std::string& algname, const std::string& salt,
                   const std::string& params)
   {
   KDF* kdf = 0;
   try {
      kdf = get_kdf(algname);
      }
   catch(...) { return 0; }

   if(kdf)
      return new KDF_Filter(kdf, salt, to_u32bit(params));
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

}

Filter* lookup(const std::string& algname,
               const std::vector<std::string>& params)
   {
   std::string key = params[0];
   std::string iv = params[1];
   Filter* filter = 0;

   // The order of the lookup has to change based on how the names are
   // formatted and parsed.
   filter = lookup_kdf(algname, key, iv);
   if(filter) return filter;

   filter = lookup_rng(algname, key);
   if(filter) return filter;

   filter = lookup_encoder(algname);
   if(filter) return filter;

   filter = lookup_pbkdf(algname, params);
   if(filter) return filter;

   return 0;
   }

