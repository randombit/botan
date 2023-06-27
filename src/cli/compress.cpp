/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_COMPRESSION)
   #include <botan/compression.h>
   #include <fstream>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_COMPRESSION)

class Compress final : public Command {
   public:
      Compress() : Command("compress --type=gzip --level=6 --buf-size=8192 file") {}

      std::string output_filename(const std::string& input_fsname, const std::string& comp_type) {
         const std::map<std::string, std::string> suffixes = {
            {"zlib", "zlib"},
            {"gzip", "gz"},
            {"bzip2", "bz2"},
            {"lzma", "xz"},
         };

         auto suffix_info = suffixes.find(comp_type);
         if(!suffixes.contains(comp_type)) {
            throw CLI_Error_Unsupported("Compressing", comp_type);
         }

         return input_fsname + "." + suffix_info->second;
      }

      std::string group() const override { return "compression"; }

      std::string description() const override { return "Compress a given file"; }

      void go() override {
         const std::string comp_type = get_arg("type");
         const size_t buf_size = get_arg_sz("buf-size");
         const size_t comp_level = get_arg_sz("level");

         auto compress = Botan::Compression_Algorithm::create(comp_type);
         if(!compress) {
            throw CLI_Error_Unsupported("Compression", comp_type);
         }

         const std::string in_file = get_arg("file");
         std::ifstream in(in_file, std::ios::binary);

         if(!in.good()) {
            throw CLI_IO_Error("reading", in_file);
         }

         const std::string out_file = output_filename(in_file, comp_type);
         std::ofstream out(out_file, std::ios::binary);
         if(!out.good()) {
            throw CLI_IO_Error("writing", out_file);
         }

         Botan::secure_vector<uint8_t> buf;

         compress->start(comp_level);

         while(in.good()) {
            buf.resize(buf_size);
            in.read(reinterpret_cast<char*>(buf.data()), buf.size());
            buf.resize(in.gcount());

            compress->update(buf);

            out.write(reinterpret_cast<const char*>(buf.data()), buf.size());
         }

         buf.clear();
         compress->finish(buf);
         out.write(reinterpret_cast<const char*>(buf.data()), buf.size());
         out.close();
      }
};

BOTAN_REGISTER_COMMAND("compress", Compress);

class Decompress final : public Command {
   public:
      Decompress() : Command("decompress --buf-size=8192 file") {}

      void parse_extension(const std::string& in_file, std::string& out_file, std::string& suffix) {
         auto last_dot = in_file.find_last_of('.');
         if(last_dot == std::string::npos || last_dot == 0) {
            throw CLI_Error("No extension detected in filename '" + in_file + "'");
         }

         out_file = in_file.substr(0, last_dot);
         suffix = in_file.substr(last_dot + 1, std::string::npos);
      }

      std::string group() const override { return "compression"; }

      std::string description() const override { return "Decompress a given compressed archive"; }

      void go() override {
         const size_t buf_size = get_arg_sz("buf-size");
         const std::string in_file = get_arg("file");
         std::string out_file, suffix;
         parse_extension(in_file, out_file, suffix);

         std::ifstream in(in_file, std::ios::binary);

         if(!in.good()) {
            throw CLI_IO_Error("reading", in_file);
         }

         auto decompress = Botan::Decompression_Algorithm::create(suffix);

         if(!decompress) {
            throw CLI_Error_Unsupported("Decompression", suffix);
         }

         std::ofstream out(out_file, std::ios::binary);
         if(!out.good()) {
            throw CLI_IO_Error("writing", out_file);
         }

         Botan::secure_vector<uint8_t> buf;

         decompress->start();

         while(in.good()) {
            buf.resize(buf_size);
            in.read(reinterpret_cast<char*>(buf.data()), buf.size());
            buf.resize(in.gcount());

            decompress->update(buf);

            out.write(reinterpret_cast<const char*>(buf.data()), buf.size());
         }

         buf.clear();
         decompress->finish(buf);
         out.write(reinterpret_cast<const char*>(buf.data()), buf.size());
         out.close();
      }
};

BOTAN_REGISTER_COMMAND("decompress", Decompress);

#endif

}  // namespace Botan_CLI
