/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_ASN1) && defined(BOTAN_HAS_PEM_CODEC)

#include <botan/pem.h>
#include <botan/asn1_print.h>

namespace Botan_CLI {

class ASN1_Printer final : public Command
   {
   public:
      ASN1_Printer() : Command("asn1print --pem file") {}

      void go() override
         {
         const std::string input = get_arg("file");

         std::vector<uint8_t> contents;

         if(flag_set("pem"))
            {
            std::string pem_label;
            contents = unlock(Botan::PEM_Code::decode(slurp_file_as_str(input), pem_label));
            }
         else
            {
            contents = slurp_file(input);
            }

         // TODO make these configurable
         const size_t LIMIT = 4 * 1024;
         const size_t BIN_LIMIT = 1024;
         const bool PRINT_CONTEXT_SPECIFIC = true;

         Botan::ASN1_Pretty_Printer printer(LIMIT, BIN_LIMIT, PRINT_CONTEXT_SPECIFIC);
         printer.print_to_stream(output(), contents.data(), contents.size());
         }
   };

BOTAN_REGISTER_COMMAND("asn1print", ASN1_Printer);

}

#endif // BOTAN_HAS_ASN1 && BOTAN_HAS_PEM_CODEC
