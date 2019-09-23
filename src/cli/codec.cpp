/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_HEX_CODEC)
   #include <botan/hex.h>
#endif

#if defined(BOTAN_HAS_BASE32_CODEC)
   #include <botan/base32.h>
#endif

#if defined(BOTAN_HAS_BASE58_CODEC)
   #include <botan/base58.h>
#endif

#if defined(BOTAN_HAS_BASE64_CODEC)
   #include <botan/base64.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_HEX_CODEC)

class Hex_Encode final : public Command
   {
   public:
      Hex_Encode() : Command("hex_enc file") {}

      std::string group() const override
         {
         return "codec";
         }

      std::string description() const override
         {
         return "Hex encode a given file";
         }

      void go() override
         {
         auto hex_enc_f = [&](const uint8_t b[], size_t l) { output() << Botan::hex_encode(b, l); };
         this->read_file(get_arg("file"), hex_enc_f, 2);
         }
   };

BOTAN_REGISTER_COMMAND("hex_enc", Hex_Encode);

class Hex_Decode final : public Command
   {
   public:
      Hex_Decode() : Command("hex_dec file") {}

      std::string group() const override
         {
         return "codec";
         }

      std::string description() const override
         {
         return "Hex decode a given file";
         }

      void go() override
         {
         auto hex_dec_f = [&](const uint8_t b[], size_t l)
            {
            std::vector<uint8_t> bin = Botan::hex_decode(reinterpret_cast<const char*>(b), l);
            output().write(reinterpret_cast<const char*>(bin.data()), bin.size());
            };

         this->read_file(get_arg("file"), hex_dec_f, 2);
         }
   };

BOTAN_REGISTER_COMMAND("hex_dec", Hex_Decode);

#endif

#if defined(BOTAN_HAS_BASE58_CODEC)

class Base58_Encode final : public Command
   {
   public:
      Base58_Encode() : Command("base58_enc --check file") {}

      std::string group() const override
         {
         return "codec";
         }

      std::string description() const override
         {
         return "Encode given file to Base58";
         }

      void go() override
         {
         auto data = slurp_file(get_arg("file"));

         if(flag_set("check"))
            output() << Botan::base58_check_encode(data);
         else
            output() << Botan::base58_encode(data);
         }
   };

BOTAN_REGISTER_COMMAND("base58_enc", Base58_Encode);

class Base58_Decode final : public Command
   {
   public:
      Base58_Decode() : Command("base58_dec --check file") {}

      std::string group() const override
         {
         return "codec";
         }

      std::string description() const override
         {
         return "Decode Base58 encoded file";
         }

      void go() override
         {
         auto data = slurp_file_as_str(get_arg("file"));

         std::vector<uint8_t> bin;

         if(flag_set("check"))
            bin = Botan::base58_check_decode(data);
         else
            bin = Botan::base58_decode(data);

         output().write(reinterpret_cast<const char*>(bin.data()), bin.size());
         }
   };

BOTAN_REGISTER_COMMAND("base58_dec", Base58_Decode);

#endif // base58

#if defined(BOTAN_HAS_BASE32_CODEC)

class Base32_Encode final : public Command
   {
   public:
      Base32_Encode() : Command("base32_enc file") {}

      std::string group() const override
         {
         return "codec";
         }

      std::string description() const override
         {
         return "Encode given file to Base32";
         }

      void go() override
         {
         auto onData = [&](const uint8_t b[], size_t l)
            {
            output() << Botan::base32_encode(b, l);
            };
         this->read_file(get_arg("file"), onData, 768);
         }
   };

BOTAN_REGISTER_COMMAND("base32_enc", Base32_Encode);

class Base32_Decode final : public Command
   {
   public:
      Base32_Decode() : Command("base32_dec file") {}

      std::string group() const override
         {
         return "codec";
         }

      std::string description() const override
         {
         return "Decode Base32 encoded file";
         }

      void go() override
         {
         auto write_bin = [&](const uint8_t b[], size_t l)
            {
            Botan::secure_vector<uint8_t> bin = Botan::base32_decode(reinterpret_cast<const char*>(b), l);
            output().write(reinterpret_cast<const char*>(bin.data()), bin.size());
            };

         this->read_file(get_arg("file"), write_bin, 1024);
         }
   };

BOTAN_REGISTER_COMMAND("base32_dec", Base32_Decode);

#endif // base32

#if defined(BOTAN_HAS_BASE64_CODEC)

class Base64_Encode final : public Command
   {
   public:
      Base64_Encode() : Command("base64_enc file") {}

      std::string group() const override
         {
         return "codec";
         }

      std::string description() const override
         {
         return "Encode given file to Base64";
         }

      void go() override
         {
         auto onData = [&](const uint8_t b[], size_t l)
            {
            output() << Botan::base64_encode(b, l);
            };
         this->read_file(get_arg("file"), onData, 768);
         }
   };

BOTAN_REGISTER_COMMAND("base64_enc", Base64_Encode);

class Base64_Decode final : public Command
   {
   public:
      Base64_Decode() : Command("base64_dec file") {}

      std::string group() const override
         {
         return "codec";
         }

      std::string description() const override
         {
         return "Decode Base64 encoded file";
         }

      void go() override
         {
         auto write_bin = [&](const uint8_t b[], size_t l)
            {
            Botan::secure_vector<uint8_t> bin = Botan::base64_decode(reinterpret_cast<const char*>(b), l);
            output().write(reinterpret_cast<const char*>(bin.data()), bin.size());
            };

         this->read_file(get_arg("file"), write_bin, 1024);
         }
   };

BOTAN_REGISTER_COMMAND("base64_dec", Base64_Decode);

#endif // base64

}
