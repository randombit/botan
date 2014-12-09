
#include "apps.h"

#include <botan/compression.h>
#include <fstream>

namespace {

void do_compress(Transformation& comp, std::ifstream& in, std::ostream& out)
   {
   secure_vector<byte> buf;

   comp.start();

   while(in.good())
      {
      buf.resize(64*1024);
      in.read(reinterpret_cast<char*>(&buf[0]), buf.size());
      buf.resize(in.gcount());

      comp.update(buf);

      out.write(reinterpret_cast<const char*>(&buf[0]), buf.size());
      }

   buf.clear();
   comp.finish(buf);
   out.write(reinterpret_cast<const char*>(&buf[0]), buf.size());
   }

int compress(int argc, char* argv[])
   {
   if(argc != 2 && argc != 3)
      {
      std::cout << "Usage: " << argv[0] << " input [type]\n";
      return 1;
      }

   const std::string in_file = argv[1];
   std::ifstream in(in_file.c_str());

   if(!in.good())
      {
      std::cout << "Couldn't read " << in_file << "\n";
      return 1;
      }

   const size_t level = 9;
   const std::string suffix = argc == 3 ? argv[2] : "gz";

   std::unique_ptr<Transformation> compress(make_compressor(suffix, level));

   const std::string out_file = in_file + "." + suffix;
   std::ofstream out(out_file.c_str());

   do_compress(*compress, in, out);

   return 0;
   }

void parse_extension(const std::string& in_file,
                     std::string& out_file,
                     std::string& suffix)
   {
   auto last_dot = in_file.find_last_of('.');
   if(last_dot == std::string::npos || last_dot == 0)
      throw std::runtime_error("No extension detected in filename '" + in_file + "'");

   out_file = in_file.substr(0, last_dot);
   suffix = in_file.substr(last_dot+1, std::string::npos);
   }

int uncompress(int argc, char* argv[])
   {
   const std::string in_file = argv[1];
   std::ifstream in(in_file.c_str());

   if(!in.good())
      {
      std::cout << "Couldn't read " << argv[1] << "\n";
      return 1;
      }

   std::string out_file, suffix;
   parse_extension(in_file, out_file, suffix);

   std::ofstream out(out_file.c_str());

   std::unique_ptr<Transformation> decompress(make_decompressor(suffix));

   do_compress(*decompress, in, out);

   return 0;
   }

REGISTER_APP(compress);
REGISTER_APP(uncompress);

}
