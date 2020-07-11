/*
* (C) 2010,2014,2015,2019 Jack Lloyd
* (C) 2019 Matthias Gierlings
* (C) 2015 René Korthaus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)

#include <botan/base64.h>
#include <botan/hex.h>
#include <botan/rng.h>

#include <botan/pk_keys.h>
#include <botan/x509_key.h>
#include <botan/pk_algs.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/workfactor.h>
#include <botan/data_src.h>

#include <fstream>

#if defined(BOTAN_HAS_DL_GROUP)
   #include <botan/dl_group.h>
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_group.h>
#endif

namespace Botan_CLI {

class PK_Keygen final : public Command
   {
   public:
      PK_Keygen() : Command("keygen --algo=RSA --params= --passphrase= --pbe= --pbe-millis=300 --provider= --der-out") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string description() const override
         {
         return "Generate a PKCS #8 private key";
         }

      void go() override
         {
         const std::string algo = get_arg("algo");
         const std::string params = get_arg("params");
         const std::string provider = get_arg("provider");

         std::unique_ptr<Botan::Private_Key> key =
            Botan::create_private_key(algo, rng(), params, provider);

         if(!key)
            {
            throw CLI_Error_Unsupported("keygen", algo);
            }

         const std::string pass = get_passphrase_arg("Key passphrase", "passphrase");
         const bool der_out = flag_set("der-out");

         const std::chrono::milliseconds pbe_millis(get_arg_sz("pbe-millis"));
         const std::string pbe = get_arg("pbe");

         if(der_out)
            {
            if(pass.empty())
               {
               write_output(Botan::PKCS8::BER_encode(*key));
               }
            else
               {
               write_output(Botan::PKCS8::BER_encode(*key, rng(), pass, pbe_millis, pbe));
               }
            }
         else
            {
            if(pass.empty())
               {
               output() << Botan::PKCS8::PEM_encode(*key);
               }
            else
               {
               output() << Botan::PKCS8::PEM_encode(*key, rng(), pass, pbe_millis, pbe);
               }
            }
         }
   };

BOTAN_REGISTER_COMMAND("keygen", PK_Keygen);

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

namespace {

std::string choose_sig_padding(const std::string& key, const std::string& emsa, const std::string& hash)
   {
   std::string emsa_or_default = [&]() -> std::string
      {
      if(!emsa.empty())
         {
         return emsa;
         }

      if(key == "RSA")
         {
         return "EMSA4";
         } // PSS
      else if(key == "ECDSA" || key == "DSA")
         {
         return "EMSA1";
         }
      else if(key == "Ed25519")
         {
         return "";
         }
      else
         {
         return "EMSA1";
         }
      }();

   if(emsa_or_default.empty())
      {
      return hash;
      }

   return emsa_or_default + "(" + hash + ")";
   }

}

class PK_Fingerprint final : public Command
   {
   public:
      PK_Fingerprint() : Command("fingerprint --no-fsname --algo=SHA-256 *keys") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string description() const override
         {
         return "Calculate a public key fingerprint";
         }

      void go() override
         {
         const std::string hash_algo = get_arg("algo");
         const bool no_fsname = flag_set("no-fsname");

         for(std::string key_file : get_arg_list("keys"))
            {
            std::unique_ptr<Botan::Public_Key> key(
               key_file == "-"
               ? Botan::X509::load_key(this->slurp_file("-", 4096))
               : Botan::X509::load_key(key_file));

            const std::string fprint = key->fingerprint_public(hash_algo);

            if(no_fsname || key_file == "-")
               { output() << fprint << "\n"; }
            else
               { output() << key_file << ": " << fprint << "\n"; }
            }
         }
   };

BOTAN_REGISTER_COMMAND("fingerprint", PK_Fingerprint);

class PK_Sign final : public Command
   {
   public:
      PK_Sign() : Command("sign --der-format --passphrase= --hash=SHA-256 --emsa= --provider= key file") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string description() const override
         {
         return "Sign arbitrary data";
         }

      void go() override
         {
         const std::string key_file = get_arg("key");
         const std::string passphrase = get_passphrase_arg("Passphrase for " + key_file, "passphrase");

         Botan::DataSource_Stream input(key_file);
         std::unique_ptr<Botan::Private_Key> key = Botan::PKCS8::load_key(input, passphrase);

         if(!key)
            {
            throw CLI_Error("Unable to load private key");
            }

         const std::string sig_padding =
            choose_sig_padding(key->algo_name(), get_arg("emsa"), get_arg("hash"));

         const Botan::Signature_Format format =
            flag_set("der-format") ? Botan::DER_SEQUENCE : Botan::IEEE_1363;

         const std::string provider = get_arg("provider");

         Botan::PK_Signer signer(*key, rng(), sig_padding, format, provider);

         auto onData = [&signer](const uint8_t b[], size_t l)
            {
            signer.update(b, l);
            };
         this->read_file(get_arg("file"), onData);

         std::vector<uint8_t> sig { signer.signature(rng()) };

         if(key->stateful_operation())
            {
            std::ofstream updated_key(key_file);
            if(passphrase.empty())
               { updated_key << Botan::PKCS8::PEM_encode(*key); }
            else
               { updated_key << Botan::PKCS8::PEM_encode(*key, rng(), passphrase); }
            }

         output() << Botan::base64_encode(sig) << "\n";
         }
   };

BOTAN_REGISTER_COMMAND("sign", PK_Sign);

class PK_Verify final : public Command
   {
   public:
      PK_Verify() : Command("verify --der-format --hash=SHA-256 --emsa= pubkey file signature") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string description() const override
         {
         return "Verify the authenticity of the given file with the provided signature";
         }

      void go() override
         {
         std::unique_ptr<Botan::Public_Key> key(Botan::X509::load_key(get_arg("pubkey")));
         if(!key)
            {
            throw CLI_Error("Unable to load public key");
            }

         const std::string sig_padding =
            choose_sig_padding(key->algo_name(), get_arg("emsa"), get_arg("hash"));

         const Botan::Signature_Format format =
            flag_set("der-format") ? Botan::DER_SEQUENCE : Botan::IEEE_1363;

         Botan::PK_Verifier verifier(*key, sig_padding, format);
         auto onData = [&verifier](const uint8_t b[], size_t l)
            {
            verifier.update(b, l);
            };
         this->read_file(get_arg("file"), onData);

         const Botan::secure_vector<uint8_t> signature =
            Botan::base64_decode(this->slurp_file_as_str(get_arg("signature")));

         const bool valid = verifier.check_signature(signature);

         output() << "Signature is " << (valid ? "valid" : "invalid") << "\n";
         }
   };

BOTAN_REGISTER_COMMAND("verify", PK_Verify);

class PKCS8_Tool final : public Command
   {
   public:
      PKCS8_Tool() : Command("pkcs8 --pass-in= --pub-out --der-out --pass-out= --pbe= --pbe-millis=300 key") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string description() const override
         {
         return "Open a PKCS #8 formatted key";
         }

      void go() override
         {
         const std::string key_file = get_arg("key");
         const std::string pass_in = get_passphrase_arg("Password for " + key_file, "pass-in");

         Botan::DataSource_Memory key_src(slurp_file(key_file));
         std::unique_ptr<Botan::Private_Key> key;

         if(pass_in.empty())
            {
            key.reset(Botan::PKCS8::load_key(key_src, rng()));
            }
         else
            {
            key.reset(Botan::PKCS8::load_key(key_src, rng(), pass_in));
            }

         const std::chrono::milliseconds pbe_millis(get_arg_sz("pbe-millis"));
         const std::string pbe = get_arg("pbe");
         const bool der_out = flag_set("der-out");

         if(flag_set("pub-out"))
            {
            if(der_out)
               {
               write_output(Botan::X509::BER_encode(*key));
               }
            else
               {
               output() << Botan::X509::PEM_encode(*key);
               }
            }
         else
            {
            const std::string pass_out = get_passphrase_arg("Passphrase to encrypt key", "pass-out");

            if(der_out)
               {
               if(pass_out.empty())
                  {
                  write_output(Botan::PKCS8::BER_encode(*key));
                  }
               else
                  {
                  write_output(Botan::PKCS8::BER_encode(*key, rng(), pass_out, pbe_millis, pbe));
                  }
               }
            else
               {
               if(pass_out.empty())
                  {
                  output() << Botan::PKCS8::PEM_encode(*key);
                  }
               else
                  {
                  output() << Botan::PKCS8::PEM_encode(*key, rng(), pass_out, pbe_millis, pbe);
                  }
               }
            }
         }
   };

BOTAN_REGISTER_COMMAND("pkcs8", PKCS8_Tool);

#endif

#if defined(BOTAN_HAS_ECC_GROUP)

class EC_Group_Info final : public Command
   {
   public:
      EC_Group_Info() : Command("ec_group_info --pem name") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string description() const override
         {
         return "Print raw elliptic curve domain parameters of the standardized curve name";
         }

      void go() override
         {
         Botan::EC_Group ec_group(get_arg("name"));

         if(flag_set("pem"))
            {
            output() << ec_group.PEM_encode();
            }
         else
            {
            output() << "P = " << std::hex << ec_group.get_p() << "\n"
                     << "A = " << std::hex << ec_group.get_a() << "\n"
                     << "B = " << std::hex << ec_group.get_b() << "\n"
                     << "N = " << std::hex << ec_group.get_order() << "\n"
                     << "G = " << ec_group.get_g_x() << "," << ec_group.get_g_y() << "\n";
            }

         }
   };

BOTAN_REGISTER_COMMAND("ec_group_info", EC_Group_Info);

#endif

#if defined(BOTAN_HAS_DL_GROUP)

class DL_Group_Info final : public Command
   {
   public:
      DL_Group_Info() : Command("dl_group_info --pem name") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string description() const override
         {
         return "Print raw Diffie-Hellman parameters (p,g) of the standardized DH group name";
         }

      void go() override
         {
         Botan::DL_Group dl_group(get_arg("name"));

         if(flag_set("pem"))
            {
            output() << dl_group.PEM_encode(Botan::DL_Group::ANSI_X9_42_DH_PARAMETERS);
            }
         else
            {
            output() << "P = " << std::hex << dl_group.get_p() << "\n"
                     << "G = " << dl_group.get_g() << "\n";
            }

         }
   };

BOTAN_REGISTER_COMMAND("dl_group_info", DL_Group_Info);

class PK_Workfactor final : public Command
   {
   public:
      PK_Workfactor() : Command("pk_workfactor --type=rsa bits") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string description() const override
         {
         return "Provide estimate of strength of public key based on size";
         }

      void go() override
         {
         const size_t bits = get_arg_sz("bits");
         const std::string type = get_arg("type");

         if(type == "rsa")
            { output() << Botan::if_work_factor(bits) << "\n"; }
         else if(type == "dl")
            { output() << Botan::dl_work_factor(bits) << "\n"; }
         else if(type == "dl_exp")
            { output() << Botan::dl_exponent_size(bits) << "\n"; }
         else
            { throw CLI_Usage_Error("Unknown type for pk_workfactor"); }
         }
   };

BOTAN_REGISTER_COMMAND("pk_workfactor", PK_Workfactor);

class Gen_DL_Group final : public Command
   {
   public:
      Gen_DL_Group() : Command("gen_dl_group --pbits=1024 --qbits=0 --seed= --type=subgroup") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string description() const override
         {
         return "Generate ANSI X9.42 encoded Diffie-Hellman group parameters";
         }

      void go() override
         {
         const size_t pbits = get_arg_sz("pbits");
         const size_t qbits = get_arg_sz("qbits");

         const std::string type = get_arg("type");
         const std::string seed_str = get_arg("seed");

         if(type == "strong")
            {
            if(seed_str.size() > 0)
               { throw CLI_Usage_Error("Seed only supported for DSA param gen"); }
            Botan::DL_Group grp(rng(), Botan::DL_Group::Strong, pbits);
            output() << grp.PEM_encode(Botan::DL_Group::ANSI_X9_42);
            }
         else if(type == "subgroup")
            {
            if(seed_str.size() > 0)
               { throw CLI_Usage_Error("Seed only supported for DSA param gen"); }
            Botan::DL_Group grp(rng(), Botan::DL_Group::Prime_Subgroup, pbits, qbits);
            output() << grp.PEM_encode(Botan::DL_Group::ANSI_X9_42);
            }
         else if(type == "dsa")
            {
            size_t dsa_qbits = qbits;
            if(dsa_qbits == 0)
               {
               if(pbits == 1024)
                  { dsa_qbits = 160; }
               else if(pbits == 2048 || pbits == 3072)
                  { dsa_qbits = 256; }
               else
                  { throw CLI_Usage_Error("Invalid DSA p/q sizes"); }
               }

            if(seed_str.empty())
               {
               Botan::DL_Group grp(rng(), Botan::DL_Group::DSA_Kosherizer, pbits, dsa_qbits);
               output() << grp.PEM_encode(Botan::DL_Group::ANSI_X9_42);
               }
            else
               {
               const std::vector<uint8_t> seed = Botan::hex_decode(seed_str);
               Botan::DL_Group grp(rng(), seed, pbits, dsa_qbits);
               output() << grp.PEM_encode(Botan::DL_Group::ANSI_X9_42);
               }

            }
         else
            {
            throw CLI_Usage_Error("Invalid DL type '" + type + "'");
            }
         }
   };

BOTAN_REGISTER_COMMAND("gen_dl_group", Gen_DL_Group);

#endif

}

#endif
