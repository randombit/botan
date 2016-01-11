/*
* (C) 2010,2014,2015 Jack Lloyd
* (C) 2015 René Korthaus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)

#include <botan/base64.h>

#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>

#if defined(BOTAN_HAS_DL_GROUP)
  #include <botan/dl_group.h>
#endif

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_CURVE_25519)
  #include <botan/curve25519.h>
#endif

#if defined(BOTAN_HAS_MCELIECE)
  #include <botan/mceliece.h>
#endif

namespace Botan_CLI {

class PK_Keygen final : public Command
   {
   public:
      PK_Keygen() : Command("keygen --algo=RSA --params= --passphrase= --pbe= --pbe-millis=300 --der-out") {}

      static std::unique_ptr<Botan::Private_Key> do_keygen(const std::string& algo,
                                                           const std::string& params,
                                                           Botan::RandomNumberGenerator& rng)
         {
         typedef std::function<std::unique_ptr<Botan::Private_Key> (std::string)> gen_fn;
         std::map<std::string, gen_fn> generators;

#if defined(BOTAN_HAS_RSA)
         generators["RSA"] = [&rng](std::string param) -> std::unique_ptr<Botan::Private_Key> {
            if(param.empty())
               param = "2048";
            return std::unique_ptr<Botan::Private_Key>(
               new Botan::RSA_PrivateKey(rng, Botan::to_u32bit(param)));
         };
#endif

#if defined(BOTAN_HAS_DSA)
         generators["DSA"] = [&rng](std::string param) -> std::unique_ptr<Botan::Private_Key> {
            if(param.empty())
               param = "dsa/botan/2048";
            return std::unique_ptr<Botan::Private_Key>(
               new Botan::DSA_PrivateKey(rng, Botan::DL_Group(param)));
         };
#endif

#if defined(BOTAN_HAS_ECDSA)
         generators["ECDSA"] = [&rng](std::string param) {
            if(param.empty())
               param = "secp256r1";
            Botan::EC_Group grp(param);
            return std::unique_ptr<Botan::Private_Key>(
               new Botan::ECDSA_PrivateKey(rng, grp));
         };
#endif

#if defined(BOTAN_HAS_CURVE_25519)
         generators["Curve25519"] = [&rng](std::string /*ignored*/) {
            return std::unique_ptr<Botan::Private_Key>(
               new Botan::Curve25519_PrivateKey(rng));
         };
#endif

#if defined(BOTAN_HAS_MCELIECE)
         generators["McEliece"] = [&rng](std::string param) {
            if(param.empty())
               param = "2280,45";
            std::vector<std::string> param_parts = Botan::split_on(param, ',');
            if(param_parts.size() != 2)
               throw CLI_Usage_Error("Bad McEliece parameters " + param);
            return std::unique_ptr<Botan::Private_Key>(
               new Botan::McEliece_PrivateKey(rng,
                                              Botan::to_u32bit(param_parts[0]),
                                              Botan::to_u32bit(param_parts[1])));
         };
#endif

         auto gen = generators.find(algo);
         if(gen == generators.end())
            {
            throw CLI_Error_Unsupported("keygen", algo);
            }

         return gen->second(params);
         }

      void go() override
         {
         std::unique_ptr<Botan::Private_Key> key(do_keygen(get_arg("algo"), get_arg("params"), rng()));

         const std::string pass = get_arg("passphrase");
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

namespace {

std::string algo_default_emsa(const std::string& key)
   {
   if(key == "RSA")
      return "EMSA4"; // PSS
   else if(key == "ECDSA" || key == "DSA")
      return "EMSA1";
   else if(key == "RW")
      return "EMSA2";
   else
      return "EMSA1";
   }

}

class PK_Sign final : public Command
   {
   public:
      PK_Sign() : Command("sign --passphrase= --hash=SHA-256 --emsa= key file") {}

      void go() override
         {
         std::unique_ptr<Botan::Private_Key> key(Botan::PKCS8::load_key(get_arg("key"),
                                                                        rng(),
                                                                        get_arg("passphrase")));

         if(!key)
            throw CLI_Error("Unable to load private key");

         const std::string sig_padding =
            get_arg_or("emsa", algo_default_emsa(key->algo_name())) + "(" + get_arg("hash") + ")";

         Botan::PK_Signer signer(*key, sig_padding);

         this->read_file(get_arg("file"),
                         [&signer](const uint8_t b[], size_t l) { signer.update(b, l); });

         output() << Botan::base64_encode(signer.signature(rng())) << "\n";
         }
   };

BOTAN_REGISTER_COMMAND("sign", PK_Sign);

class PK_Verify final : public Command
   {
   public:
      PK_Verify() : Command("verify --hash=SHA-256 --emsa= pubkey file signature") {}

      void go() override
         {
         std::unique_ptr<Botan::Public_Key> key(Botan::X509::load_key(get_arg("pubkey")));
         if(!key)
            throw CLI_Error("Unable to load public key");

         const std::string sig_padding =
            get_arg_or("emsa", algo_default_emsa(key->algo_name())) + "(" + get_arg("hash") + ")";

         Botan::PK_Verifier verifier(*key, sig_padding);
         this->read_file(get_arg("file"),
                         [&verifier](const uint8_t b[], size_t l) { verifier.update(b, l); });

         const Botan::secure_vector<uint8_t> signature =
            Botan::base64_decode(this->slurp_file_as_str(get_arg("signature")));

         const bool valid = verifier.check_signature(signature);

         output() << "Signature is " << (valid ? "valid" : "invalid") << "\n";
         }
   };

BOTAN_REGISTER_COMMAND("verify", PK_Verify);

#if defined(BOTAN_HAS_DL_GROUP)

class Gen_DL_Group final : public Command
   {
   public:
      Gen_DL_Group() : Command("gen_dl_group --pbits=1024 --qbits=0 --type=subgroup") {}

      void go() override
         {
         const size_t pbits = get_arg_sz("pbits");

         const std::string type = get_arg("type");

         if(type == "strong")
            {
            Botan::DL_Group grp(rng(), Botan::DL_Group::Strong, pbits);
            output() << grp.PEM_encode(Botan::DL_Group::ANSI_X9_42);
            }
         else if(type == "subgroup")
            {
            Botan::DL_Group grp(rng(), Botan::DL_Group::Prime_Subgroup, pbits, get_arg_sz("qbits"));
            output() << grp.PEM_encode(Botan::DL_Group::ANSI_X9_42);
            }
         else
            throw CLI_Usage_Error("Invalid DL type '" + type + "'");
         }
   };

BOTAN_REGISTER_COMMAND("gen_dl_group", Gen_DL_Group);

#endif

class PKCS8_Tool final : public Command
   {
   public:
      PKCS8_Tool() : Command("pkcs8 --pass-in= --pub-out --der-out --pass-out= --pbe= --pbe-millis=300 key") {}

      void go() override
         {
         std::unique_ptr<Botan::Private_Key> key(
            Botan::PKCS8::load_key(get_arg("key"),
                                   rng(),
                                   get_arg("pass-in")));

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
            const std::string pass = get_arg("pass-out");

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
         }
   };

BOTAN_REGISTER_COMMAND("pkcs8", PKCS8_Tool);

}

#endif
