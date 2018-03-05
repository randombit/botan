/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_ASN1)

#include <botan/asn1_print.h>

#if defined(BOTAN_HAS_PEM_CODEC)
  #include <botan/pem.h>
#endif

namespace Botan_CLI {

class ASN1_Printer final : public Command
   {
   public:
      ASN1_Printer() : Command("asn1print --print-context-specific --print-limit=4096 --bin-limit=2048 --max-depth=64 --pem file") {}

      std::string group() const override
         {
         return "misc";
         }

      std::string description() const override
         {
         return "Decode and print file with ASN.1 Basic Encoding Rules (BER)";
         }

      void go() override
         {
         const std::string input = get_arg("file");
         const size_t print_limit = get_arg_sz("print-limit");
         const size_t bin_limit = get_arg_sz("bin-limit");
         const bool print_context_specific = flag_set("print-context-specific");
         const size_t max_depth = get_arg_sz("max-depth");

         const size_t value_column = 60;
         const size_t initial_level = 0;

         std::vector<uint8_t> contents;

         if(flag_set("pem") || (input.size() > 4 && input.substr(input.size() - 4) == ".pem"))
            {
#if defined(BOTAN_HAS_PEM_CODEC)
            std::string pem_label;
            contents = unlock(Botan::PEM_Code::decode(slurp_file_as_str(input), pem_label));
#else
            throw CLI_Error_Unsupported("PEM decoding not available in this build");
#endif
            }
         else
            {
            contents = slurp_file(input);
            }

         Botan::ASN1_Pretty_Printer printer(print_limit, bin_limit, print_context_specific,
                                            initial_level, value_column, max_depth);

         printer.print_to_stream(output(), contents.data(), contents.size());
         }
   };

BOTAN_REGISTER_COMMAND("asn1print", ASN1_Printer);

}

#endif // BOTAN_HAS_ASN1 && BOTAN_HAS_PEM_CODEC
