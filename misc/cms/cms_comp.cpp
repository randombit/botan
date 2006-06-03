/*************************************************
* CMS Compression Source File                    *
* (C) 1999-2003 The Botan Project                *
*************************************************/

#include <botan/cms_enc.h>
#include <botan/cms_dec.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>
#include <botan/pipe.h>

#if defined(BOTAN_EXT_COMPRESSOR_ZLIB)
  #include <botan/zlib.h>
  #define HAVE_ZLIB 1
#else
  #define HAVE_ZLIB 0
#endif

namespace Botan {

/*************************************************
* Compress a message                             *
*************************************************/
void CMS_Encoder::compress(const std::string& algo)
   {
   if(!CMS_Encoder::can_compress_with(algo))
      throw Invalid_Argument("CMS_Encoder: Cannot compress with " + algo);

   Filter* compressor = 0;

#if HAVE_ZLIB
   if(algo == "Zlib") compressor = new Zlib_Compression;
#endif

   if(compressor == 0)
      throw Internal_Error("CMS: Couldn't get ahold of a compressor");

   Pipe pipe(compressor);
   pipe.process_msg(data);
   SecureVector<byte> compressed = pipe.read_all();

   DER_Encoder encoder;
   encoder.start_sequence();
     DER::encode(encoder, 0);
     DER::encode(encoder, AlgorithmIdentifier("Compression." + algo, false));
     encoder.add_raw_octets(make_econtent(compressed, type));
   encoder.end_sequence();

   add_layer("CMS.CompressedData", encoder);
   }

/*************************************************
* See if the named compression algo is available *
*************************************************/
bool CMS_Encoder::can_compress_with(const std::string& algo)
   {
   if(HAVE_ZLIB && algo == "Zlib")
      return true;
   return false;
   }

/*************************************************
* Decompress a message                           *
*************************************************/
void CMS_Decoder::decompress(BER_Decoder& decoder)
   {
   u32bit version;
   AlgorithmIdentifier comp_algo;

   BER_Decoder comp_info = BER::get_subsequence(decoder);
   BER::decode(comp_info, version);
   if(version != 0)
      throw Decoding_Error("CMS: Unknown version for CompressedData");
   BER::decode(comp_info, comp_algo);
   read_econtent(comp_info);
   comp_info.verify_end();

   Filter* decompressor = 0;

   info = comp_algo.oid.as_string();
#if HAVE_ZLIB
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
