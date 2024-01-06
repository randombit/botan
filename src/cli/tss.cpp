/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_THRESHOLD_SECRET_SHARING)
   #include <botan/hex.h>
   #include <botan/mem_ops.h>
   #include <botan/rng.h>
   #include <botan/tss.h>
   #include <botan/internal/fmt.h>
   #include <fstream>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_THRESHOLD_SECRET_SHARING)

class TSS_Split final : public Command {
   public:
      TSS_Split() : Command("tss_split M N input --id= --share-prefix=share --share-suffix=tss --hash=SHA-256") {}

      std::string group() const override { return "tss"; }

      std::string description() const override { return "Split a secret into parts"; }

      void go() override {
         const std::string hash_algo = get_arg("hash");
         const std::string input = get_arg("input");
         const std::string id_str = get_arg("id");
         const std::string share_prefix = get_arg("share-prefix");
         const std::string share_suffix = get_arg("share-suffix");
         const size_t N = get_arg_sz("N");
         const size_t M = get_arg_sz("M");

         if(M <= 1 || N <= 1 || M > N || N >= 255) {
            throw CLI_Usage_Error("Invalid N/M parameters for secret splitting");
         }

         Botan::secure_vector<uint8_t> secret = slurp_file_lvec(input);

         if(secret.size() > 0xFFFF) {
            throw CLI_Usage_Error("Secret is too large for this TSS format");
         }

         std::vector<uint8_t> id = Botan::hex_decode(id_str);

         if(id.empty()) {
            id.resize(16);
            rng().randomize(id.data(), id.size());
         }

         std::vector<Botan::RTSS_Share> shares = Botan::RTSS_Share::split(static_cast<uint8_t>(M),
                                                                          static_cast<uint8_t>(N),
                                                                          secret.data(),
                                                                          static_cast<uint16_t>(secret.size()),
                                                                          id,
                                                                          hash_algo,
                                                                          rng());

         for(size_t i = 0; i != shares.size(); ++i) {
            const std::string share_name = Botan::fmt("{}{}.{}", share_prefix, i + 1, share_suffix);
            std::ofstream out(share_name.c_str(), std::ios::binary);
            if(!out) {
               throw CLI_Error("Failed to open output file " + share_name);
            }

            out.write(reinterpret_cast<const char*>(shares[i].data().data()), shares[i].data().size());
         }
      }

   private:
      Botan::secure_vector<uint8_t> slurp_file_lvec(const std::string& input_file) {
         Botan::secure_vector<uint8_t> buf;
         auto insert_fn = [&](const uint8_t b[], size_t l) { buf.insert(buf.end(), b, b + l); };
         Command::read_file(input_file, insert_fn, 4096);
         return buf;
      }
};

BOTAN_REGISTER_COMMAND("tss_split", TSS_Split);

class TSS_Recover final : public Command {
   public:
      TSS_Recover() : Command("tss_recover *shares") {}

      std::string group() const override { return "tss"; }

      std::string description() const override { return "Recover a split secret"; }

      void go() override {
         const std::vector<std::string> share_names = get_arg_list("shares");

         if(share_names.empty()) {
            output() << help_text() << "\n";
            this->set_return_code(1);
            return;
         }

         std::vector<Botan::RTSS_Share> shares;

         for(const std::string& share_fsname : get_arg_list("shares")) {
            auto v = slurp_file(share_fsname);
            shares.push_back(Botan::RTSS_Share(v.data(), v.size()));
         }

         Botan::secure_vector<uint8_t> rec = Botan::RTSS_Share::reconstruct(shares);

         output().write(Botan::cast_uint8_ptr_to_char(rec.data()), rec.size());
      }
};

BOTAN_REGISTER_COMMAND("tss_recover", TSS_Recover);

#endif

}  // namespace Botan_CLI
