/*
* (C) 2015,2017 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if (defined(BOTAN_HAS_AES) || defined(BOTAN_HAS_AEAD_CHACHA20_POLY1305)) && defined(BOTAN_HAS_AEAD_MODES)

#include <botan/aead.h>
#include <botan/hex.h>
#include <sstream>

namespace Botan_CLI {

namespace {

auto VALID_MODES = std::map<std::string, std::string>{
         // Don't add algorithms here without extending tests
         // in `src/scripts/test_cli_crypt.py`
         { "aes-128-cfb", "AES-128/CFB" },
         { "aes-192-cfb", "AES-192/CFB" },
         { "aes-256-cfb", "AES-256/CFB" },
         { "aes-128-gcm", "AES-128/GCM" },
         { "aes-192-gcm", "AES-192/GCM" },
         { "aes-256-gcm", "AES-256/GCM" },
         { "aes-128-ocb", "AES-128/OCB" },
         { "aes-128-xts", "AES-128/XTS" },
         { "aes-256-xts", "AES-256/XTS" },
         { "chacha20poly1305", "ChaCha20Poly1305" },
};

Botan::secure_vector<uint8_t>
do_crypt(const std::string &cipher,
         const std::vector<uint8_t> &input,
         const Botan::SymmetricKey &key,
         const Botan::InitializationVector &iv,
         const std::vector<uint8_t>& ad,
         Botan::Cipher_Dir direction)
   {
   if(iv.size() == 0)
      throw CLI_Usage_Error("IV must not be empty");

   // TODO: implement streaming

   std::unique_ptr<Botan::Cipher_Mode> processor(Botan::Cipher_Mode::create(cipher, direction));
   if(!processor)
      throw CLI_Error("Cipher algorithm not found");

   // Set key
   processor->set_key(key);

   if(Botan::AEAD_Mode* aead = dynamic_cast<Botan::AEAD_Mode*>(processor.get()))
      {
      aead->set_ad(ad);
      }
   else if(ad.size() != 0)
      {
      throw CLI_Usage_Error("Cannot specify associated data with non-AEAD mode");
      }

   // Set IV
   processor->start(iv.bits_of());

   Botan::secure_vector<uint8_t> buf(input.begin(), input.end());
   processor->finish(buf);

   return buf;
   }

}

class Encryption final : public Command
   {
   public:
      Encryption() : Command("encryption --buf-size=4096 --decrypt --mode= --key= --iv= --ad=") {}

      std::string group() const override
         {
         return "encryption";
         }

      std::string description() const override
         {
         return "Encrypt or decrypt a given file";
         }

      void go() override
         {
         std::string mode = get_arg_or("mode", "");
         if (!VALID_MODES.count(mode))
            {
            std::ostringstream error;
            error << "Invalid mode: '" << mode << "'\n"
                  << "valid modes are:";
            for (auto valid_mode : VALID_MODES) error << " " << valid_mode.first;

            throw CLI_Usage_Error(error.str());
            }

         const std::string key_hex = get_arg("key");
         const std::string iv_hex  = get_arg("iv");
         const std::string ad_hex  = get_arg_or("ad", "");
         const size_t buf_size = get_arg_sz("buf-size");

         const std::vector<uint8_t> input = this->slurp_file("-", buf_size);

         if (verbose())
            {
            error_output() << "Got " << input.size() << " bytes of input data.\n";
            }

         const Botan::SymmetricKey key(key_hex);
         const Botan::InitializationVector iv(iv_hex);
         const std::vector<uint8_t> ad = Botan::hex_decode(ad_hex);

         auto direction = flag_set("decrypt") ? Botan::Cipher_Dir::DECRYPTION : Botan::Cipher_Dir::ENCRYPTION;
         write_output(do_crypt(VALID_MODES[mode], input, key, iv, ad, direction));
         }
   };

BOTAN_REGISTER_COMMAND("encryption", Encryption);

}

#endif
