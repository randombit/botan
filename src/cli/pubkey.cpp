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
   #include <botan/data_src.h>
   #include <botan/hash.h>
   #include <botan/hex.h>
   #include <botan/pk_algs.h>
   #include <botan/pk_keys.h>
   #include <botan/pk_options.h>
   #include <botan/pkcs8.h>
   #include <botan/pubkey.h>
   #include <botan/x509_key.h>
   #include <botan/internal/workfactor.h>
   #include <fstream>

   #if defined(BOTAN_HAS_DL_GROUP)
      #include <botan/dl_group.h>
   #endif

   #if defined(BOTAN_HAS_ECC_GROUP)
      #include <botan/ec_group.h>
   #endif

namespace Botan_CLI {

namespace {

class PK_Keygen final : public Command {
   public:
      PK_Keygen() :
            Command(
               "keygen --algo=RSA --params= --passphrase= --cipher= --pbkdf= --pbkdf-ms=300 --pbkdf-iter= --provider= --rng-type= --drbg-seed= --der-out") {
      }

      std::string group() const override { return "pubkey"; }

      std::string description() const override { return "Generate a PKCS #8 private key"; }

      void go() override {
         const std::string algo = get_arg("algo");
         const std::string params = get_arg("params");
         const std::string provider = get_arg("provider");

         const std::unique_ptr<Botan::Private_Key> key = Botan::create_private_key(algo, rng(), params, provider);

         if(!key) {
            throw CLI_Error_Unsupported("keygen", algo);
         }

         const std::string pass = get_passphrase_arg("Key passphrase", "passphrase");
         const bool der_out = flag_set("der-out");

         const std::chrono::milliseconds pbkdf_ms(get_arg_sz("pbkdf-ms"));

         if(der_out) {
            if(pass.empty()) {
               write_output(Botan::PKCS8::BER_encode(*key));
            } else {
               if(get_arg("pbkdf-iter").empty()) {
                  write_output(Botan::PKCS8::BER_encode_encrypted_pbkdf_msec(
                     *key, rng(), pass, pbkdf_ms, nullptr, get_arg("cipher"), get_arg("pbkdf")));
               } else {
                  write_output(Botan::PKCS8::BER_encode_encrypted_pbkdf_iter(
                     *key, rng(), pass, get_arg_sz("pbkdf-iter"), get_arg("cipher"), get_arg("pbkdf")));
               }
            }
         } else {
            if(pass.empty()) {
               output() << Botan::PKCS8::PEM_encode(*key);
            } else {
               if(get_arg("pbkdf-iter").empty()) {
                  output() << Botan::PKCS8::PEM_encode_encrypted_pbkdf_msec(
                     *key, rng(), pass, pbkdf_ms, nullptr, get_arg("cipher"), get_arg("pbkdf"));
               } else {
                  output() << Botan::PKCS8::PEM_encode_encrypted_pbkdf_iter(
                     *key, rng(), pass, get_arg_sz("pbkdf-iter"), get_arg("cipher"), get_arg("pbkdf"));
               }
            }
         }
      }
};

BOTAN_REGISTER_COMMAND("keygen", PK_Keygen);

   #if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

namespace {

/*
* Signature schemes for which the caller must select a hash function; the
* other schemes either fix the hash by the key type or do not use one.
*/
bool signature_scheme_requires_hash(std::string_view algo_name) {
   return algo_name == "RSA" || algo_name == "DSA" || algo_name == "ECDSA" || algo_name == "ECGDSA" ||
          algo_name == "ECKCDSA" || algo_name.starts_with("GOST-34.10");
}

}  // namespace

/*
* Shared handling of the signature related options of the sign and verify commands
*/
class PK_Signature_Command : public Command {
   protected:
      using Command::Command;

      Botan::PK_Signature_Options signature_options(const Botan::Public_Key& key) const {
         const std::string algo_name = key.algo_name();

         auto options = Botan::PK_Signature_Options();

         const bool prehashed = flag_set("prehashed");

         std::string hash_fn = get_arg("hash");
         // With a prehashed input an unnamed hash means the digest is signed as is
         if(hash_fn.empty() && !prehashed && signature_scheme_requires_hash(algo_name)) {
            hash_fn = "SHA-256";
         }
         if(!hash_fn.empty() && !Botan::HashFunction::create(hash_fn)) {
            throw CLI_Error_Unsupported("hashing", hash_fn);
         }
         options = options.with_hash(hash_fn);

         if(prehashed) {
            options = options.with_externally_computed_prehash();
         }

         std::string padding = get_arg("padding");
         if(padding.empty() && algo_name == "RSA") {
            padding = "PSS";
         }
         options = options.with_padding(padding);

         if(const auto prehash = get_arg_maybe("prehash")) {
            if(*prehash == "default") {
               options = options.with_prehash();
            } else {
               options = options.with_prehash(prehash);
            }
         }

         if(const auto context = get_arg_maybe("context")) {
            options = options.with_context(*context);
         }

         if(get_arg_maybe("salt-size")) {
            options = options.with_salt_size(get_arg_sz("salt-size"));
         }

         if(flag_set("deterministic")) {
            options = options.with_deterministic_signature();
         }

         if(flag_set("der-format")) {
            if(!key._signature_element_size_for_DER_encoding()) {
               throw CLI_Usage_Error("Key type " + algo_name + " does not support DER formatting for signatures");
            }
            options = options.with_der_encoded_signature();
         }

         options = options.with_provider(get_arg_or("provider", ""));

         return options;
      }
};

class PK_Fingerprint final : public Command {
   public:
      PK_Fingerprint() : Command("fingerprint --no-fsname --algo=SHA-256 *keys") {}

      std::string group() const override { return "pubkey"; }

      std::string description() const override { return "Calculate a public key fingerprint"; }

      void go() override {
         const std::string hash_algo = get_arg("algo");
         const bool no_fsname = flag_set("no-fsname");

         for(const std::string& key_file : get_arg_list("keys")) {
            std::unique_ptr<Botan::Public_Key> key(key_file == "-" ? Botan::X509::load_key(this->slurp_file("-", 4096))
                                                                   : Botan::X509::load_key(key_file));

            const std::string fprint = key->fingerprint_public(hash_algo);

            if(no_fsname || key_file == "-") {
               output() << fprint << "\n";
            } else {
               output() << key_file << ": " << fprint << "\n";
            }
         }
      }
};

BOTAN_REGISTER_COMMAND("fingerprint", PK_Fingerprint);

namespace {

std::unique_ptr<Botan::Private_Key> load_private_key(const std::string& key_filename, const std::string& passphrase) {
   std::string err_string;

   try {
      Botan::DataSource_Stream input(key_filename);
      return Botan::PKCS8::load_key(input, passphrase);
   } catch(Botan::Exception& e) {
      err_string = e.what();
   }

   if(passphrase.empty()) {
      try {
         Botan::DataSource_Stream input(key_filename);
         return Botan::PKCS8::load_key(input);
      } catch(Botan::Exception& e) {
         err_string = e.what();
      }
   }

   throw CLI_Error("Loading private key failed (" + err_string + ")");
}

}  // namespace

class PK_Sign final : public PK_Signature_Command {
   public:
      PK_Sign() :
            PK_Signature_Command(
               "sign --der-format --passphrase= --hash= --padding= --prehash= --prehashed --context= --salt-size= "
               "--deterministic --provider= --rng-type= --drbg-seed= key file") {}

      std::string group() const override { return "pubkey"; }

      std::string description() const override { return "Sign arbitrary data"; }

      void go() override {
         const std::string key_file = get_arg("key");
         const std::string passphrase = get_passphrase_arg("Passphrase for " + key_file, "passphrase");

         auto key = load_private_key(key_file, passphrase);

         Botan::PK_Signer signer(*key, rng(), signature_options(*key));

         auto onData = [&signer](const uint8_t b[], size_t l) { signer.update(b, l); };
         Command::read_file(get_arg("file"), onData);

         std::vector<uint8_t> sig{signer.signature(rng())};

         if(key->stateful_operation()) {
            std::ofstream updated_key(key_file);
            if(passphrase.empty()) {
               updated_key << Botan::PKCS8::PEM_encode(*key);
            } else {
               updated_key << Botan::PKCS8::PEM_encode(*key, rng(), passphrase);
            }
         }

         output() << Botan::base64_encode(sig) << "\n";
      }
};

BOTAN_REGISTER_COMMAND("sign", PK_Sign);

class PK_Verify final : public PK_Signature_Command {
   public:
      PK_Verify() :
            PK_Signature_Command(
               "verify --der-format --hash= --padding= --prehash= --prehashed --context= --salt-size= pubkey file "
               "signature") {}

      std::string group() const override { return "pubkey"; }

      std::string description() const override {
         return "Verify the authenticity of the given file with the provided signature";
      }

      void go() override {
         auto key = Botan::X509::load_key(get_arg("pubkey"));
         if(!key) {
            throw CLI_Error("Unable to load public key");
         }

         Botan::PK_Verifier verifier(*key, signature_options(*key));
         auto onData = [&verifier](const uint8_t b[], size_t l) { verifier.update(b, l); };
         Command::read_file(get_arg("file"), onData);

         const Botan::secure_vector<uint8_t> signature =
            Botan::base64_decode(this->slurp_file_as_str(get_arg("signature")));

         const bool valid = verifier.check_signature(signature);

         output() << "Signature is " << (valid ? "valid" : "invalid") << "\n";
      }
};

BOTAN_REGISTER_COMMAND("verify", PK_Verify);

class PKCS8_Tool final : public Command {
   public:
      PKCS8_Tool() :
            Command(
               "pkcs8 --pass-in= --pub-out --der-out --pass-out= --cipher= --pbkdf= --pbkdf-ms=300 --pbkdf-iter= --rng-type= --drbg-seed= key") {
      }

      std::string group() const override { return "pubkey"; }

      std::string description() const override { return "Open a PKCS #8 formatted key"; }

      void go() override {
         const std::string key_file = get_arg("key");
         const std::string pass_in = get_passphrase_arg("Password for " + key_file, "pass-in");

         Botan::DataSource_Memory key_src(slurp_file(key_file));
         std::unique_ptr<Botan::Private_Key> key;

         if(pass_in.empty()) {
            key = Botan::PKCS8::load_key(key_src);
         } else {
            key = Botan::PKCS8::load_key(key_src, pass_in);
         }

         const std::chrono::milliseconds pbkdf_ms(get_arg_sz("pbkdf-ms"));
         const bool der_out = flag_set("der-out");

         if(flag_set("pub-out")) {
            auto pk = key->public_key();
            if(der_out) {
               write_output(Botan::X509::BER_encode(*pk));
            } else {
               output() << Botan::X509::PEM_encode(*pk);
            }
         } else {
            const std::string pass_out = get_passphrase_arg("Passphrase to encrypt key", "pass-out");

            if(der_out) {
               if(pass_out.empty()) {
                  write_output(Botan::PKCS8::BER_encode(*key));
               } else {
                  if(get_arg("pbkdf-iter").empty()) {
                     write_output(Botan::PKCS8::BER_encode_encrypted_pbkdf_msec(
                        *key, rng(), pass_out, pbkdf_ms, nullptr, get_arg("cipher"), get_arg("pbkdf")));
                  } else {
                     write_output(Botan::PKCS8::BER_encode_encrypted_pbkdf_iter(
                        *key, rng(), pass_out, get_arg_sz("pbkdf-iter"), get_arg("cipher"), get_arg("pbkdf")));
                  }
               }
            } else {
               if(pass_out.empty()) {
                  output() << Botan::PKCS8::PEM_encode(*key);
               } else {
                  if(get_arg("pbkdf-iter").empty()) {
                     output() << Botan::PKCS8::PEM_encode_encrypted_pbkdf_msec(
                        *key, rng(), pass_out, pbkdf_ms, nullptr, get_arg("cipher"), get_arg("pbkdf"));
                  } else {
                     output() << Botan::PKCS8::PEM_encode_encrypted_pbkdf_iter(
                        *key, rng(), pass_out, get_arg_sz("pbkdf-iter"), get_arg("cipher"), get_arg("pbkdf"));
                  }
               }
            }
         }
      }
};

BOTAN_REGISTER_COMMAND("pkcs8", PKCS8_Tool);

   #endif

   #if defined(BOTAN_HAS_ECC_GROUP)

class EC_Group_Info final : public Command {
   public:
      EC_Group_Info() : Command("ec_group_info --pem name") {}

      std::string group() const override { return "pubkey"; }

      std::string description() const override {
         return "Print raw elliptic curve domain parameters of the standardized curve name";
      }

      void go() override {
         const auto ec_group = Botan::EC_Group::from_name(get_arg("name"));

         if(flag_set("pem")) {
            output() << ec_group.PEM_encode(Botan::EC_Group_Encoding::NamedCurve);
         } else {
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

class DL_Group_Info final : public Command {
   public:
      DL_Group_Info() : Command("dl_group_info --pem name") {}

      std::string group() const override { return "pubkey"; }

      std::string description() const override {
         return "Print raw Diffie-Hellman parameters (p,g) of the standardized DH group name";
      }

      void go() override {
         auto dl_group = Botan::DL_Group::from_name(get_arg("name"));

         if(flag_set("pem")) {
            output() << dl_group.PEM_encode(Botan::DL_Group_Format::ANSI_X9_42_DH_PARAMETERS);
         } else {
            output() << "P = " << std::hex << dl_group.get_p() << "\n"
                     << "G = " << dl_group.get_g() << "\n";
         }
      }
};

BOTAN_REGISTER_COMMAND("dl_group_info", DL_Group_Info);

class PK_Workfactor final : public Command {
   public:
      PK_Workfactor() : Command("pk_workfactor --type=rsa bits") {}

      std::string group() const override { return "pubkey"; }

      std::string description() const override { return "Provide estimate of strength of public key based on size"; }

      void go() override {
         const size_t bits = get_arg_sz("bits");
         const std::string type = get_arg("type");

         if(type == "rsa") {
            output() << Botan::if_work_factor(bits) << "\n";
         } else if(type == "dl") {
            output() << Botan::dl_work_factor(bits) << "\n";
         } else if(type == "dl_exp") {
            output() << Botan::dl_exponent_size(bits) << "\n";
         } else {
            throw CLI_Usage_Error("Unknown type for pk_workfactor (rsa, dl, dl_exp)");
         }
      }
};

BOTAN_REGISTER_COMMAND("pk_workfactor", PK_Workfactor);

class Gen_DL_Group final : public Command {
   public:
      Gen_DL_Group() :
            Command("gen_dl_group --pbits=2048 --qbits=0 --seed= --type=subgroup --rng-type= --drbg-seed=") {}

      std::string group() const override { return "pubkey"; }

      std::string description() const override { return "Generate ANSI X9.42 encoded Diffie-Hellman group parameters"; }

      void go() override {
         const size_t pbits = get_arg_sz("pbits");
         const size_t qbits = get_arg_sz("qbits");

         const std::string type = get_arg("type");
         const std::string seed_str = get_arg("seed");

         if(type == "strong") {
            if(!seed_str.empty()) {
               throw CLI_Usage_Error("Seed only supported for DSA param gen");
            }
            const Botan::DL_Group grp(rng(), Botan::DL_Group::Strong, pbits);
            output() << grp.PEM_encode(Botan::DL_Group_Format::ANSI_X9_42);
         } else if(type == "subgroup") {
            if(!seed_str.empty()) {
               throw CLI_Usage_Error("Seed only supported for DSA param gen");
            }
            const Botan::DL_Group grp(rng(), Botan::DL_Group::Prime_Subgroup, pbits, qbits);
            output() << grp.PEM_encode(Botan::DL_Group_Format::ANSI_X9_42);
         } else if(type == "dsa") {
            size_t dsa_qbits = qbits;
            if(dsa_qbits == 0) {
               if(pbits == 1024) {
                  dsa_qbits = 160;
               } else if(pbits == 2048 || pbits == 3072) {
                  dsa_qbits = 256;
               } else {
                  throw CLI_Usage_Error("Invalid DSA p/q sizes");
               }
            }

            if(seed_str.empty()) {
               const Botan::DL_Group grp(rng(), Botan::DL_Group::DSA_Kosherizer, pbits, dsa_qbits);
               output() << grp.PEM_encode(Botan::DL_Group_Format::ANSI_X9_57);
            } else {
               const std::vector<uint8_t> seed = Botan::hex_decode(seed_str);
               const Botan::DL_Group grp(rng(), seed, pbits, dsa_qbits);
               output() << grp.PEM_encode(Botan::DL_Group_Format::ANSI_X9_57);
            }

         } else {
            throw CLI_Usage_Error("Invalid DL type '" + type + "'");
         }
      }
};

BOTAN_REGISTER_COMMAND("gen_dl_group", Gen_DL_Group);

   #endif

}  // namespace

}  // namespace Botan_CLI

#endif
