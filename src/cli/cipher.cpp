/*
* (C) 2015,2017 Simon Warta (Kullo GmbH)
* (C) 2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_CIPHER_MODES)

   #include <botan/cipher_mode.h>
   #include <botan/hex.h>
   #include <sstream>

   #if defined(BOTAN_HAS_AEAD_MODES)
      #include <botan/aead.h>
   #endif

namespace Botan_CLI {

class Cipher final : public Command {
   public:
      Cipher() : Command("cipher --cipher=AES-256/GCM --decrypt --key= --nonce= --ad= --buf-size=4096 input-file") {}

      std::string group() const override { return "crypto"; }

      std::string description() const override { return "Encrypt or decrypt with a symmetric cipher"; }

      void go() override {
         const std::string cipher_algo = get_arg_or("cipher", "");
         const std::string key_hex = get_arg("key");
         const std::string nonce_hex = get_arg("nonce");
         const std::string ad_hex = get_arg_or("ad", "");
         const std::string input_file = get_arg_or("input-file", "-");
         const size_t buf_size = get_arg_sz("buf-size");

         const Botan::SymmetricKey key(key_hex);
         const Botan::InitializationVector nonce(nonce_hex);
         const std::vector<uint8_t> ad = Botan::hex_decode(ad_hex);

         auto direction = flag_set("decrypt") ? Botan::Cipher_Dir::Decryption : Botan::Cipher_Dir::Encryption;

         auto cipher = Botan::Cipher_Mode::create(cipher_algo, direction);
         if(!cipher) {
            throw CLI_Error_Unsupported("Cipher algorithm '" + cipher_algo + "' not available");
         }

         // Set key
         cipher->set_key(key);

         // Set associated data
         if(!ad.empty()) {
   #if defined(BOTAN_HAS_AEAD_MODES)
            if(Botan::AEAD_Mode* aead = dynamic_cast<Botan::AEAD_Mode*>(cipher.get())) {
               aead->set_associated_data(ad);
            } else
   #endif
            {
               throw CLI_Usage_Error("Cannot specify associated data with non-AEAD mode");
            }
         }

         // Set nonce
         cipher->start(nonce.bits_of());

         const std::vector<uint8_t> input = this->slurp_file(input_file, buf_size);

         Botan::secure_vector<uint8_t> buf(input.begin(), input.end());
         cipher->finish(buf);

         write_output(buf);
      }
};

BOTAN_REGISTER_COMMAND("cipher", Cipher);

}  // namespace Botan_CLI

#endif
