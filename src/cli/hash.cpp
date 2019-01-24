/*
* (C) 2009,2010,2014,2015,2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_HASH) && defined(BOTAN_HAS_HEX_CODEC)
   #include <botan/hash.h>
   #include <botan/hex.h>
#endif

#if defined(BOTAN_HAS_BASE64_CODEC)
   #include <botan/base64.h>
#endif

#if defined(BOTAN_HAS_BASE58_CODEC)
   #include <botan/base58.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_HASH)

class Hash final : public Command
   {
   public:
      Hash() : Command("hash --algo=SHA-256 --buf-size=4096 --no-fsname --format=hex *files") {}

      std::string group() const override
         {
         return "hash";
         }

      std::string description() const override
         {
         return "Compute the message digest of given file(s)";
         }

      template<typename Alloc>
      static std::string format_digest(const std::string& format,
                                       const std::vector<uint8_t, Alloc>& vec)
         {
         if(format == "hex")
            {
            return Botan::hex_encode(vec);
            }
#if defined(BOTAN_HAS_BASE64_CODEC)
         else if(format == "base64")
            {
            return Botan::base64_encode(vec);
            }
#endif
#if defined(BOTAN_HAS_BASE58_CODEC)
         else if(format == "base58")
            {
            return Botan::base58_encode(vec);
            }
         else if(format == "base58check")
            {
            return Botan::base58_check_encode(vec);
            }
#endif
         else
            {
            throw CLI_Usage_Error("Unknown format for encoding digests");
            }
         }

      void go() override
         {
         const std::string hash_algo = get_arg("algo");
         const std::string format = get_arg("format");
         const size_t buf_size = get_arg_sz("buf-size");
         const bool no_fsname = flag_set("no-fsname");

         std::unique_ptr<Botan::HashFunction> hash_fn(Botan::HashFunction::create(hash_algo));

         if(!hash_fn)
            {
            throw CLI_Error_Unsupported("hashing", hash_algo);
            }

         std::vector<std::string> files = get_arg_list("files");
         if(files.empty())
            {
            files.push_back("-");
            } // read stdin if no arguments on command line

         for(const std::string& fsname : files)
            {
            try
               {
               auto update_hash = [&](const uint8_t b[], size_t l) { hash_fn->update(b, l); };
               read_file(fsname, update_hash, buf_size);

               const std::string digest = format_digest(format, hash_fn->final());

               if(no_fsname)
                  output() << digest << "\n";
               else
                  output() << digest << " " << fsname << "\n";
               }
            catch(CLI_IO_Error& e)
               {
               error_output() << e.what() << "\n";
               }
            }
         }
   };

BOTAN_REGISTER_COMMAND("hash", Hash);

#endif

}
