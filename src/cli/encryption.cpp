/*
* (C) 2015,2017 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_AEAD_MODES)

#include <botan/aes.h>
#include <botan/aead.h>

#include <iostream>
#include <iterator>
#include <sstream>

using namespace Botan;

namespace Botan_CLI {

namespace {

auto VALID_MODES = std::map<std::string, std::string>{
         // Don't add algorithms here without extending tests
         // in `src/scripts/cli_tests.py`
         { "aes-128-cfb", "AES-128/CFB" },
         { "aes-192-cfb", "AES-192/CFB" },
         { "aes-256-cfb", "AES-256/CFB" },
         { "aes-128-gcm", "AES-128/GCM" },
         { "aes-192-gcm", "AES-192/GCM" },
         { "aes-256-gcm", "AES-256/GCM" },
         { "aes-128-ocb", "AES-128/OCB" },
         { "aes-128-xts", "AES-128/XTS" },
         { "aes-256-xts", "AES-256/XTS" },
};

bool is_aead(const std::string &cipher)
   {
   return cipher.find("/GCM") != std::string::npos
          || cipher.find("/OCB") != std::string::npos;
   }

secure_vector<byte> do_crypt(const std::string &cipher,
                             const secure_vector<byte> &input,
                             const SymmetricKey &key,
                             const InitializationVector &iv,
                             const OctetString &ad,
                             Cipher_Dir direction)
   {
   if (iv.size() == 0) throw std::invalid_argument("IV must not be empty");

   // TODO: implement streaming

   std::shared_ptr<Botan::Cipher_Mode> processor(Botan::get_cipher_mode(cipher, direction));
   if(!processor) throw std::runtime_error("Cipher algorithm not found");

   // Set key
   processor->set_key(key);

   // Set associated data
   if (is_aead(cipher))
      {
      auto aead_processor = std::dynamic_pointer_cast<AEAD_Mode>(processor);
      if(!aead_processor) throw std::runtime_error("Cipher algorithm not could not be converted to AEAD");
      aead_processor->set_ad(ad.bits_of());
      }

   // Set IV
   processor->start(iv.bits_of());

   secure_vector<byte> buf(input.begin(), input.end());
   processor->finish(buf);

   return buf;
   }

secure_vector<byte> get_stdin()
   {
   secure_vector<byte> out;
   std::streamsize reserved_size = 1048576; // 1 MiB
   out.reserve(reserved_size);

   std::istreambuf_iterator<char> iterator(std::cin.rdbuf()); // stdin iterator
   std::istreambuf_iterator<char> EOS;                    // end-of-range iterator
   std::copy(iterator, EOS, std::back_inserter(out));
   return out;
   }

void to_stdout(const secure_vector<byte> &data)
   {
   std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(std::cout));
   }

}

class Encryption : public Command
   {
   public:
      Encryption() : Command("encryption --decrypt --mode= --key= --iv= --ad=") {}

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

         std::string key_hex = get_arg("key");
         std::string iv_hex  = get_arg("iv");
         std::string ad_hex  = get_arg_or("ad", "");

         auto input = get_stdin();
         if (verbose())
            {
            std::cerr << "Got " << input.size() << " bytes of input data." << std::endl;
            }

         auto key = SymmetricKey(key_hex);
         auto iv = InitializationVector(iv_hex);
         auto ad = OctetString(ad_hex);

         auto direction = flag_set("decrypt") ? Cipher_Dir::DECRYPTION : Cipher_Dir::ENCRYPTION;
         auto out = do_crypt(VALID_MODES[mode], input, key, iv, ad, direction);
         to_stdout(out);
         }
   };

BOTAN_REGISTER_COMMAND("encryption", Encryption);

}

#endif
