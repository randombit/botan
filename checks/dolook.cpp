#include <vector>
#include <string>

#include <botan/lookup.h>
#include <botan/filters.h>
#include <botan/engine.h>
#include <botan/filter.h>
#include <assert.h>
#ifdef BOTAN_EXT_COMPRESSOR_BZIP2
#include <botan/bzip2.h>
#endif

#ifdef BOTAN_EXT_COMPRESSOR_GZIP
#include <botan/gzip.h>
#endif

#ifdef BOTAN_EXT_COMPRESSOR_ZLIB
#include <botan/zlib.h>
#endif

using namespace Botan;

Filter::AutoFilterPtr lookup_block(const std::string&, const std::string&);
Filter::SharedFilterPtr lookup_cipher(const std::string&, const std::string&,
                    const std::string&, bool);
Filter::SharedFilterPtr lookup_hash(const std::string&);
Filter::SharedFilterPtr lookup_mac(const std::string&, const std::string&);
Filter::SharedFilterPtr lookup_rng(const std::string&);
Filter::SharedFilterPtr lookup_encoder(const std::string&);
//Filter::SharedFilterPtr lookup_s2k(const std::string&, const std::vector<std::string>&);
Filter::SharedFilterPtr lookup_kdf(const std::string&, const std::string&,
                   const std::string&);

//Filter::SharedFilterPtr lookup(const std::string& algname,
//               const std::vector<std::string>& params,
//               const std::string& section)
               Filter::SharedFilterPtr lookup(const std::string& algname,
               const std::vector<std::string>& params,
               const std::string& section)

   {
   assert(params.size() >= 2);
   std::string key = params[0];
   std::string iv = params[1];
   Filter::SharedFilterPtr filter;

   // The order of the lookup has to change based on how the names are
   // formatted and parsed.
   filter = lookup_kdf(algname, key, iv);
   if(filter.get()) return filter;

   if(section == "Cipher Modes (Decryption)")
      filter = lookup_cipher(algname, key, iv, false);
   else
      filter = lookup_cipher(algname, key, iv, true);
   if(filter.get()) return filter;

   Filter::AutoFilterPtr autoFilterPtr(lookup_block(algname, key));
   filter = Filter::SharedFilterPtr(autoFilterPtr);
   if(filter.get()) return filter;

   filter = lookup_rng(algname);
   if(filter.get()) return filter;

   filter = lookup_encoder(algname);
   if(filter.get()) return filter;

   filter = lookup_hash(algname);
   if(filter.get()) return filter;

   filter = lookup_mac(algname, key);
   if(filter.get()) return filter;

/*
   filter = lookup_s2k(algname, params);
   if(filter.get()) return filter;
*/
   return filter;
   }

Filter::SharedFilterPtr lookup_hash(const std::string& algname)
   {
   Filter::SharedFilterPtr hash;

   try {
      hash = create_shared_ptr<Hash_Filter>(algname);
      }
   catch(Algorithm_Not_Found) {}

   return hash;
   }

Filter::SharedFilterPtr lookup_mac(const std::string& algname, const std::string& key)
   {
   Filter::SharedFilterPtr mac;
   try {
      mac = create_shared_ptr<MAC_Filter>(algname, key);
      }
   catch(Algorithm_Not_Found) {}

   return mac;
   }

Filter::SharedFilterPtr lookup_cipher(const std::string& algname, const std::string& key,
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
   return Filter::SharedFilterPtr();
   }

Filter::SharedFilterPtr lookup_encoder(const std::string& algname)
   {
   if(algname == "Base64_Encode")
      return create_shared_ptr<Base64_Encoder>();
   if(algname == "Base64_Decode")
      return create_shared_ptr<Base64_Decoder>();

#ifdef BOTAN_EXT_COMPRESSOR_BZIP2
   if(algname == "Bzip_Compression")
      return create_shared_ptr<Bzip_Compression>(9);
   if(algname == "Bzip_Decompression")
      return create_shared_ptr<Bzip_Decompression>();
#endif

#ifdef BOTAN_EXT_COMPRESSOR_GZIP
   if(algname == "Gzip_Compression")
      return create_shared_ptr<Gzip_Compression>(9);
   if(algname == "Gzip_Decompression")
      return create_shared_ptr<Gzip_Decompression>();
#endif

#ifdef BOTAN_EXT_COMPRESSOR_ZLIB
   if(algname == "Zlib_Compression")
      return create_shared_ptr<Zlib_Compression>(9);
   if(algname == "Zlib_Decompression")
      return create_shared_ptr<Zlib_Decompression>();
#endif

   return Filter::SharedFilterPtr();
   }
