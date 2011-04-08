/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/botan.h>

#if defined(BOTAN_HAS_COMPRESSOR_BZIP2)
  #include <botan/bzip2.h>
#endif

#if defined(BOTAN_HAS_COMPRESSOR_ZLIB)
  #include <botan/zlib.h>
#endif

#include <iostream>
#include <fstream>

using namespace Botan;

#include "../../checks/getopt.h"

class Encoder_Decoder
   {
   public:
      Encoder_Decoder(const std::string& command,
                      bool decode,
                      const std::vector<std::string>& args) :
         type(command),
         args(args),
         decode(decode)
         { }

      void run(std::istream& in, std::ostream& out)
         {
         Filter* filt = decode ? decoder(type) : encoder(type);

         DataSource_Stream src(in);
         Pipe pipe(filt, new DataSink_Stream(out));
         pipe.process_msg(src);
         }

      Filter* encoder(const std::string& type) const
         {
         if(type == "hex") return new Hex_Encoder;
         if(type == "base64") return new Base64_Encoder;

#if defined(BOTAN_HAS_COMPRESSOR_BZIP2)
         if(type == "bzip2") return new Bzip_Compression;
#endif

#if defined(BOTAN_HAS_COMPRESSOR_ZLIB)
         if(type == "zlib") return new Zlib_Compression;
#endif
         return 0;
         }

      Filter* decoder(const std::string& type) const
         {
         if(type == "hex") return new Hex_Decoder;
         if(type == "base64") return new Base64_Decoder;

#if defined(BOTAN_HAS_COMPRESSOR_BZIP2)
         if(type == "bzip2") return new Bzip_Decompression;
#endif

#if defined(BOTAN_HAS_COMPRESSOR_ZLIB)
         if(type == "zlib") return new Zlib_Decompression;
#endif

         return 0;
         }

   private:
      std::string type;
      std::vector<std::string> args;
      bool decode;
   };

void run_command(const std::string& command,
                 const std::vector<std::string>& arguments,
                 const OptionParser& opts)
   {
   if(command == "hex" ||
      command == "base64" ||
      command == "bzip2" ||
      command == "zlib")
      {
      bool decode = opts.is_set("decode");

      std::string output = opts.value_or_else("output", "-");
      std::string input = opts.value_or_else("input", "-");

      Encoder_Decoder enc_dec(command, decode, arguments);

      try
         {
         if(output == "-")
            {
            if(input == "-")
               enc_dec.run(std::cin, std::cout);
            else
               {
               std::ifstream in(input.c_str());
               enc_dec.run(in, std::cout);
               }
            }
         else // output != "-"
            {
            std::ofstream out(output.c_str());

            if(input == "-")
               enc_dec.run(std::cin, out);
            else
               {
               std::ifstream in(input.c_str());
               enc_dec.run(in, out);
               }
            }
         }
      catch(Botan::Stream_IO_Error& e)
         {
         std::cout << "I/O failure - " << e.what() << '\n';
         }
      }
   else if(command == "hash" ||
           command == "sha1" ||
           command == "md5")
      {
      std::string hash;

      if(command == "md5")
         hash = "MD5";
      if(command == "sha1")
         hash = "SHA-160";
      else
         hash = opts.value_or_else("hash", "SHA-160"); // sha1 is default

      Pipe pipe(new Hash_Filter(get_hash(hash)),
                new Hex_Encoder(false, 0, Hex_Encoder::Lowercase));

      for(size_t i = 0; i != arguments.size(); ++i)
         {
         std::string file_name = arguments[i];

         u32bit previously = pipe.message_count();

         if(file_name == "-")
            {
            pipe.start_msg();
            std::cin >> pipe;
            pipe.end_msg();
            }
         else
            {
            std::ifstream in(file_name.c_str());
            if(in)
               {
               pipe.start_msg();
               in >> pipe;
               pipe.end_msg();
               }
            else
               std::cerr << "Could not read " << file_name << '\n';
            }

         if(pipe.message_count() > previously)
            std::cout << pipe.read_all_as_string(Pipe::LAST_MESSAGE) << "  "
                      << file_name << '\n';
         }

      }
   else
      {
      std::cerr << "Command " << command << " not known\n";
      }
   }

int main(int argc, char* argv[])
   {
   LibraryInitializer init;

   OptionParser opts("help|version|seconds=|"
                     "input=|output=|decode|"
                     "hash=|key=");

   try
      {
      opts.parse(argv);
      }
   catch(std::runtime_error& e)
      {
      std::cout << "Command line problem: " << e.what() << '\n';
      return 2;
      }

   if(opts.is_set("version") || argc <= 1)
      {
      std::cerr << "Botan Toolbox v" << version_string() << '\n';
      std::cerr << "Commands: hash hex base64 ";
#if defined(BOTAN_HAS_COMPRESSOR_BZIP2)
      std::cerr << "bzip2 ";
#endif

#if defined(BOTAN_HAS_COMPRESSOR_ZLIB)
      std::cerr << "zlib ";
#endif

      std::cerr << "\n";

      return 0;
      }

   if(opts.is_set("help"))
      {
      std::vector<std::string> what = opts.leftovers();

      for(size_t i = 0; i != what.size(); ++i)
         std::cerr << what[i] << "? Never heard of it\n";
      return 0;
      }

   std::vector<std::string> args = opts.leftovers();

   if(args.size() == 0)
      return 0;

   std::string command = args[0];
   args.erase(args.begin());

   run_command(command, args, opts);

   return 0;
   }
