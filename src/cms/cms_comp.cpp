/*
* CMS Compression
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cms_enc.h>
#include <botan/cms_dec.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>
#include <botan/pipe.h>

#if defined(BOTAN_HAS_COMPRESSOR_ZLIB)
  #include <botan/zlib.h>
#endif

namespace Botan {

/*
* Compress a message
*/
void CMS_Encoder::compress(const std::string& algo)
   {
   if(!CMS_Encoder::can_compress_with(algo))
      throw Invalid_Argument("CMS_Encoder: Cannot compress with " + algo);

   Filter* compressor = 0;

#if defined(BOTAN_HAS_COMPRESSOR_ZLIB)
   if(algo == "Zlib") compressor = new Zlib_Compression;
#endif

   if(compressor == 0)
      throw Internal_Error("CMS: Couldn't get ahold of a compressor");

   Pipe pipe(compressor);
   pipe.process_msg(data);
   SecureVector<byte> compressed = pipe.read_all();

   DER_Encoder encoder;
   encoder.start_cons(SEQUENCE).
      encode((u32bit)0).
      encode(AlgorithmIdentifier("Compression." + algo,
                                 MemoryVector<byte>())).
      raw_bytes(make_econtent(compressed, type)).
   end_cons();

   add_layer("CMS.CompressedData", encoder);
   }

/*
* See if the named compression algo is available
*/
bool CMS_Encoder::can_compress_with(const std::string& algo)
   {
   if(algo == "")
      throw Invalid_Algorithm_Name("Empty string to can_compress_with");

#if defined(BOTAN_HAS_COMPRESSOR_ZLIB)
   if(algo == "Zlib")
      return true;
#endif

   return false;
   }

/*
* Decompress a message
*/
void CMS_Decoder::decompress(BER_Decoder& decoder)
   {
   u32bit version;
   AlgorithmIdentifier comp_algo;

   BER_Decoder comp_info = decoder.start_cons(SEQUENCE);

   comp_info.decode(version);
   if(version != 0)
      throw Decoding_Error("CMS: Unknown version for CompressedData");

   comp_info.decode(comp_algo);
   read_econtent(comp_info);
   comp_info.end_cons();

   Filter* decompressor = 0;

   info = comp_algo.oid.as_string();

#if defined(BOTAN_HAS_COMPRESSOR_ZLIB)
   if(comp_algo.oid == OIDS::lookup("Compression.Zlib"))
      {
      decompressor = new Zlib_Decompression;
      info = "Zlib";
      }
#endif

   if(!decompressor)
      status = FAILURE;

   Pipe pipe(decompressor);
   pipe.process_msg(data);
   data = pipe.read_all();
   }

}
