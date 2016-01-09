/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#include <botan/transform.h>

#if defined(BOTAN_HAS_COMPRESSION)
  #include <botan/compression.h>
#endif

namespace Botan_CLI {

namespace {

void do_compress(Botan::Transform& comp,
                 std::ifstream& in,
                 std::ostream& out,
                 size_t buf_size)
   {
   Botan::secure_vector<uint8_t> buf;

   comp.start();

   while(in.good())
      {
      buf.resize(buf_size);
      in.read(reinterpret_cast<char*>(&buf[0]), buf.size());
      buf.resize(in.gcount());

      comp.update(buf);

      out.write(reinterpret_cast<const char*>(&buf[0]), buf.size());
      }

   buf.clear();
   comp.finish(buf);
   out.write(reinterpret_cast<const char*>(&buf[0]), buf.size());
   }

}

/**
* Compress input data using one of the following formats
* - zlib (RFC 1950): a stream compression format not to be confused with .zip files
* - gzip (RFC 1952): similar to zlib but uses CRC checksums instead of Adler32
* - bzip2 (there is no RFC for bzip2): see http://bzip.org/ or Wikipedia
* - lzma
*/
class Compress : public Command
   {
   public:
      Compress() : Command("compress --type=gzip --level=6 --buf-size=8192 file") {}

      std::string output_filename(const std::string& input_fsname,
                                  const std::string& comp_type)
         {
         const std::map<std::string, std::string> suffixes = {
            { "zlib", "zlib" },
            { "gzip", "gz" },
            { "bzip2", "bz2" },
            { "lzma", "xz" },
         };

         auto suffix_info = suffixes.find(comp_type);
         if(suffixes.count(comp_type) == 0)
            {
            throw CLI_Error_Unsupported("Compressing", comp_type);
            }

         return input_fsname + "." + suffix_info->second;
         }

      void go() override
         {
         const std::string comp_type = get_arg("type");

         std::unique_ptr<Botan::Transform> compress;

#if defined(BOTAN_HAS_COMPRESSION)
         compress.reset(Botan::make_compressor(comp_type, get_arg_sz("level")));
#endif

         if(!compress)
            {
            throw CLI_Error_Unsupported("Compression", comp_type);
            }

         const std::string in_file = get_arg("file");
         std::ifstream in(in_file);

         if(!in.good())
            {
            throw CLI_IO_Error("reading", in_file);
            }

         const std::string out_file = output_filename(in_file, comp_type);
         std::ofstream out(out_file);
         if(!in.good())
            {
            throw CLI_IO_Error("writing", out_file);
            }

         do_compress(*compress, in, out, get_arg_sz("buf-size"));
         }
   };

BOTAN_REGISTER_COMMAND("compress", Compress);

class Decompress : public Command
   {
   public:
      Decompress() : Command("decompress --buf-size=8192 file") {}

      void parse_extension(const std::string& in_file,
                           std::string& out_file,
                           std::string& suffix)
         {
         auto last_dot = in_file.find_last_of('.');
         if(last_dot == std::string::npos || last_dot == 0)
            throw CLI_Error("No extension detected in filename '" + in_file + "'");

         out_file = in_file.substr(0, last_dot);
         suffix = in_file.substr(last_dot+1, std::string::npos);
         }

      void go() override
         {
         const std::string in_file = get_arg("file");
         std::string out_file, suffix;
         parse_extension(in_file, out_file, suffix);

         std::ifstream in(in_file);

         if(!in.good())
            throw CLI_IO_Error("reading", in_file);

         std::unique_ptr<Botan::Transform> decompress;

#if defined(BOTAN_HAS_COMPRESSION)
         decompress.reset(Botan::make_decompressor(suffix));
#endif

         if(!decompress)
            throw CLI_Error_Unsupported("Decompression", suffix);

         std::ofstream out(out_file);
         if(!out.good())
            throw CLI_IO_Error("writing", out_file);

         do_compress(*decompress, in, out, get_arg_sz("buf-size"));
         }
   };

BOTAN_REGISTER_COMMAND("decompress", Decompress);

}
