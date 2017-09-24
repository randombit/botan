/*
* (C) 2009,2010,2014,2015 Jack Lloyd
* (C) 2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#include <botan/version.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/cpuid.h>
#include <botan/hex.h>
#include <botan/entropy_src.h>

#if defined(BOTAN_HAS_BASE64_CODEC)
   #include <botan/base64.h>
#endif

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   #include <botan/auto_rng.h>
#endif

#if defined(BOTAN_HAS_SYSTEM_RNG)
   #include <botan/system_rng.h>
#endif

#if defined(BOTAN_HAS_RDRAND_RNG)
   #include <botan/rdrand_rng.h>
#endif

#if defined(BOTAN_HAS_HMAC_DRBG)
   #include <botan/hmac_drbg.h>
#endif

#if defined(BOTAN_HAS_HTTP_UTIL)
   #include <botan/http_util.h>
#endif

#if defined(BOTAN_HAS_BCRYPT)
   #include <botan/bcrypt.h>
#endif

namespace Botan_CLI {

std::unique_ptr<Botan::RandomNumberGenerator>
cli_make_rng(const std::string& rng_type, const std::string& hex_drbg_seed)
   {
#if defined(BOTAN_HAS_SYSTEM_RNG)
   if(rng_type == "system" || rng_type.empty())
      {
      return std::unique_ptr<Botan::RandomNumberGenerator>(new Botan::System_RNG);
      }
#endif

#if defined(BOTAN_HAS_RDRAND_RNG)
   if(rng_type == "rdrand")
      {
      if(Botan::CPUID::has_rdrand())
         return std::unique_ptr<Botan::RandomNumberGenerator>(new Botan::RDRAND_RNG);
      else
         throw CLI_Error("RDRAND instruction not supported on this processor");
      }
#endif

   const std::vector<uint8_t> drbg_seed = Botan::hex_decode(hex_drbg_seed);

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   if(rng_type == "auto" || rng_type == "entropy" || rng_type.empty())
      {
      std::unique_ptr<Botan::RandomNumberGenerator> rng;

      if(rng_type == "entropy")
         rng.reset(new Botan::AutoSeeded_RNG(Botan::Entropy_Sources::global_sources()));
      else
         rng.reset(new Botan::AutoSeeded_RNG);

      if(drbg_seed.size() > 0)
         rng->add_entropy(drbg_seed.data(), drbg_seed.size());
      return rng;
      }
#endif

#if defined(BOTAN_HAS_HMAC_DRBG) && defined(BOTAN_AUTO_RNG_HMAC)
   if(rng_type == "drbg")
      {
      std::unique_ptr<Botan::MessageAuthenticationCode> mac =
         Botan::MessageAuthenticationCode::create(BOTAN_AUTO_RNG_HMAC);
      std::unique_ptr<Botan::Stateful_RNG> rng(new Botan::HMAC_DRBG(std::move(mac)));
      rng->add_entropy(drbg_seed.data(), drbg_seed.size());

      if(rng->is_seeded() == false)
         throw CLI_Error("For " + rng->name() + " a seed of at least " +
                         std::to_string(rng->security_level()/8) +
                         " bytes must be provided");

      return std::unique_ptr<Botan::RandomNumberGenerator>(rng.release());
      }
#endif

   throw CLI_Error_Unsupported("RNG", rng_type);
   }

class Config_Info final : public Command
   {
   public:
      Config_Info() : Command("config info_type") {}

      std::string help_text() const override
         {
         return "Usage: config info_type\n"
                "   prefix: Print install prefix\n"
                "   cflags: Print include params\n"
                "   ldflags: Print linker params\n"
                "   libs: Print libraries\n";
         }

      void go() override
         {
         const std::string arg = get_arg("info_type");

         if(arg == "prefix")
            {
            output() << BOTAN_INSTALL_PREFIX << "\n";
            }
         else if(arg == "cflags")
            {
            output() << "-I" << BOTAN_INSTALL_PREFIX << "/" << BOTAN_INSTALL_HEADER_DIR << "\n";
            }
         else if(arg == "ldflags")
            {
            if(*BOTAN_LINK_FLAGS)
               output() << BOTAN_LINK_FLAGS << ' ';
            output() << "-L" << BOTAN_INSTALL_PREFIX << "/" << BOTAN_INSTALL_LIB_DIR << "\n";
            }
         else if(arg == "libs")
            {
            output() << "-lbotan-" << Botan::version_major() << " " << BOTAN_LIB_LINK << "\n";
            }
         else
            {
            throw CLI_Usage_Error("Unknown option to botan config " + arg);
            }
         }
   };

BOTAN_REGISTER_COMMAND("config", Config_Info);

class Version_Info final : public Command
   {
   public:
      Version_Info() : Command("version --full") {}

      void go() override
         {
         if(flag_set("full"))
            {
            output() << Botan::version_string() << "\n";
            }
         else
            {
            output() << Botan::version_major() << "."
                     << Botan::version_minor() << "."
                     << Botan::version_patch() << "\n";
            }
         }
   };

BOTAN_REGISTER_COMMAND("version", Version_Info);

class Print_Cpuid final : public Command
   {
   public:
      Print_Cpuid() : Command("cpuid") {}

      void go() override
         {
         output() << "CPUID flags: " << Botan::CPUID::to_string() << "\n";
         }
   };

BOTAN_REGISTER_COMMAND("cpuid", Print_Cpuid);

class Hash final : public Command
   {
   public:
      Hash() : Command("hash --algo=SHA-256 --buf-size=4096 *files") {}

      void go() override
         {
         const std::string hash_algo = get_arg("algo");
         std::unique_ptr<Botan::HashFunction> hash_fn(Botan::HashFunction::create(hash_algo));

         if(!hash_fn)
            {
            throw CLI_Error_Unsupported("hashing", hash_algo);
            }

         const size_t buf_size = get_arg_sz("buf-size");

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
               output() << Botan::hex_encode(hash_fn->final()) << " " << fsname << "\n";
               }
            catch(CLI_IO_Error& e)
               {
               error_output() << e.what() << "\n";
               }
            }
         }
   };

BOTAN_REGISTER_COMMAND("hash", Hash);

class RNG final : public Command
   {
   public:
      RNG() : Command("rng --system --rdrand --auto --entropy --drbg --drbg-seed= *bytes") {}

      void go() override
         {
         std::string type = get_arg("rng-type");

         if(type.empty())
            {
            for(std::string flag : { "system", "rdrand", "auto", "entropy", "drbg" })
               {
               if(flag_set(flag))
                  {
                  type = flag;
                  break;
                  }
               }
            }

         const std::string drbg_seed = get_arg("drbg-seed");
         std::unique_ptr<Botan::RNG> rng = cli_make_rng(type, drbg_seed);

         for(const std::string& req : get_arg_list("bytes"))
            {
            output() << Botan::hex_encode(rng->random_vec(Botan::to_u32bit(req))) << "\n";
            }
         }
   };

BOTAN_REGISTER_COMMAND("rng", RNG);

#if defined(BOTAN_HAS_HTTP_UTIL)

class HTTP_Get final : public Command
   {
   public:
      HTTP_Get() : Command("http_get url") {}

      void go() override
         {
         output() << Botan::HTTP::GET_sync(get_arg("url")) << "\n";
         }
   };

BOTAN_REGISTER_COMMAND("http_get", HTTP_Get);

#endif // http_util

#if defined(BOTAN_HAS_HEX_CODEC)

class Hex_Encode final : public Command
   {
   public:
      Hex_Encode() : Command("hex_enc file") {}

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

#if defined(BOTAN_HAS_BASE64_CODEC)

class Base64_Encode final : public Command
   {
   public:
      Base64_Encode() : Command("base64_enc file") {}

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

#if defined(BOTAN_HAS_BCRYPT)

class Generate_Bcrypt final : public Command
   {
   public:
      Generate_Bcrypt() : Command("gen_bcrypt --work-factor=12 password") {}

      void go() override
         {
         const std::string password = get_arg("password");
         const size_t wf = get_arg_sz("work-factor");

         if(wf < 4 || wf > 18)
            {
            error_output() << "Invalid bcrypt work factor\n";
            }
         else
            {
            const uint16_t wf16 = static_cast<uint16_t>(wf);
            output() << Botan::generate_bcrypt(password, rng(), wf16) << "\n";
            }
         }
   };

BOTAN_REGISTER_COMMAND("gen_bcrypt", Generate_Bcrypt);

class Check_Bcrypt final : public Command
   {
   public:
      Check_Bcrypt() : Command("check_bcrypt password hash") {}

      void go() override
         {
         const std::string password = get_arg("password");
         const std::string hash = get_arg("hash");

         if(hash.length() != 60)
            {
            error_output() << "Note: bcrypt '" << hash << "' has wrong length and cannot be valid\n";
            }

         const bool ok = Botan::check_bcrypt(password, hash);

         output() << "Password is " << (ok ? "valid" : "NOT valid") << std::endl;
         }
   };

BOTAN_REGISTER_COMMAND("check_bcrypt", Check_Bcrypt);

#endif // bcrypt

#if defined(BOTAN_HAS_HMAC)

class HMAC final : public Command
   {
   public:
      HMAC() : Command("hmac --hash=SHA-256 --buf-size=4096 key *files") {}

      void go() override
         {
         const std::string hash_algo = get_arg("hash");
         std::unique_ptr<Botan::MessageAuthenticationCode> hmac =
            Botan::MessageAuthenticationCode::create("HMAC(" + hash_algo + ")");

         if(!hmac)
            { throw CLI_Error_Unsupported("HMAC", hash_algo); }

         hmac->set_key(slurp_file(get_arg("key")));

         const size_t buf_size = get_arg_sz("buf-size");

         std::vector<std::string> files = get_arg_list("files");
         if(files.empty())
            { files.push_back("-"); } // read stdin if no arguments on command line

         for(const std::string& fsname : files)
            {
            try
               {
               auto update_hmac = [&](const uint8_t b[], size_t l) { hmac->update(b, l); };
               read_file(fsname, update_hmac, buf_size);
               output() << Botan::hex_encode(hmac->final()) << " " << fsname << "\n";
               }
            catch(CLI_IO_Error& e)
               {
               error_output() << e.what() << "\n";
               }
            }
         }
   };

BOTAN_REGISTER_COMMAND("hmac", HMAC);

#endif // hmac

}
