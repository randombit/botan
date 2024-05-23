/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_ASN1)

   #include <botan/asn1_print.h>
   #include <botan/data_src.h>

   #if defined(BOTAN_HAS_PEM_CODEC)
      #include <botan/pem.h>
   #endif

namespace Botan_CLI {

class ASN1_Printer final : public Command {
   public:
      ASN1_Printer() :
            Command("asn1print --skip-context-specific --print-limit=4096 --bin-limit=2048 --max-depth=64 --pem file") {
      }

      std::string group() const override { return "asn1"; }

      std::string description() const override { return "Decode and print file with ASN.1 Basic Encoding Rules (BER)"; }

      static bool first_n(const std::vector<uint8_t>& data, size_t n, uint8_t b) {
         if(data.size() < n) {
            return false;
         }

         for(size_t i = 0; i != n; ++i) {
            if(data[i] != b) {
               return false;
            }
         }

         return true;
      }

      void go() override {
         const std::string input = get_arg("file");
         const size_t print_limit = get_arg_sz("print-limit");
         const size_t bin_limit = get_arg_sz("bin-limit");
         const bool print_context_specific = flag_set("skip-context-specific") == false;
         const size_t max_depth = get_arg_sz("max-depth");

         const size_t value_column = 60;
         const size_t initial_level = 0;

         std::vector<uint8_t> file_contents = slurp_file(input);
         std::vector<uint8_t> data;

         if(flag_set("pem") || (input.size() > 4 && input.substr(input.size() - 4) == ".pem") ||
            (file_contents.size() > 20 && first_n(file_contents, 5, '-'))) {
   #if defined(BOTAN_HAS_PEM_CODEC)
            std::string pem_label;
            Botan::DataSource_Memory src(file_contents);
            data = unlock(Botan::PEM_Code::decode(src, pem_label));
   #else
            throw CLI_Error_Unsupported("PEM decoding not available in this build");
   #endif
         } else {
            data.swap(file_contents);
         }

         Botan::ASN1_Pretty_Printer printer(
            print_limit, bin_limit, print_context_specific, initial_level, value_column, max_depth);

         printer.print_to_stream(output(), data.data(), data.size());
      }
};

BOTAN_REGISTER_COMMAND("asn1print", ASN1_Printer);

class OID_Info final : public Command {
   public:
      OID_Info() : Command("oid_info oid") {}

      std::string group() const override { return "asn1"; }

      std::string description() const override { return "Provide information about an object identifier"; }

      void go() override {
         const std::string oid_str = get_arg("oid");

         if(oid_str.empty()) {
            throw CLI_Usage_Error("Must provide non-empty OID string");
         }

         try {
            Botan::OID oid(oid_str);

            std::string name = oid.human_name_or_empty();
            if(name.empty()) {
               output() << "OID " << oid_str << " is not recognized\n";
            } else {
               output() << "OID " << oid_str << " is associated with " << name << "\n";
            }

            return;
         } catch(Botan::Exception&) {}

         // This throws if the string is not known
         Botan::OID oid = Botan::OID::from_string(oid_str);
         output() << "The string '" << oid_str << "' is associated with OID " << oid.to_string() << "\n";
      }
};

BOTAN_REGISTER_COMMAND("oid_info", OID_Info);

}  // namespace Botan_CLI

#endif  // BOTAN_HAS_ASN1
