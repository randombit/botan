/*
* (C) 2010,2014,2015,2018 Jack Lloyd
* (C) 2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   #include <botan/certstor.h>
   #include <botan/data_src.h>
   #include <botan/pk_keys.h>
   #include <botan/pkcs8.h>
   #include <botan/x509_ca.h>
   #include <botan/x509cert.h>
   #include <botan/x509path.h>
   #include <botan/x509self.h>

   #if defined(BOTAN_HAS_OCSP)
      #include <botan/ocsp.h>
   #endif

   #if defined(BOTAN_HAS_CERTSTOR_SYSTEM)
      #include <botan/certstor_system.h>
   #endif

   #include <fstream>

namespace Botan_CLI {

namespace {

std::unique_ptr<Botan::Private_Key> load_private_key(const std::string& key_file, const std::string& passphrase) {
   Botan::DataSource_Stream key_stream(key_file);
   auto key = Botan::PKCS8::load_key(key_stream, passphrase);

   if(!key) {
      throw CLI_Error("Failed to load key from " + key_file);
   }

   return key;
}

void update_stateful_private_key(const Botan::Private_Key& key,
                                 Botan::RandomNumberGenerator& rng,
                                 const std::string& key_file,
                                 const std::string& pass) {
   if(!key.stateful_operation()) {
      return;
   }

   std::ofstream updated_key(key_file);
   if(pass.empty()) {
      updated_key << Botan::PKCS8::PEM_encode(key);
   } else {
      updated_key << Botan::PKCS8::PEM_encode(key, rng, pass);
   }
}

}  // namespace

   #if defined(BOTAN_HAS_CERTSTOR_SYSTEM)

class Trust_Root_Info final : public Command {
   public:
      Trust_Root_Info() : Command("trust_roots --dn --dn-only --display") {}

      std::string group() const override { return "x509"; }

      std::string description() const override { return "List certs in the system trust store"; }

      void go() override {
         Botan::System_Certificate_Store trust_roots;

         const auto dn_list = trust_roots.all_subjects();

         if(flag_set("dn-only")) {
            for(const auto& dn : dn_list) {
               output() << dn << "\n";
            }
         } else {
            for(const auto& dn : dn_list) {
               // Some certstores have more than one cert with a particular DN
               for(const auto& cert : trust_roots.find_all_certs(dn, std::vector<uint8_t>())) {
                  if(flag_set("dn")) {
                     output() << "# " << dn << "\n";
                  }

                  if(flag_set("display")) {
                     output() << cert.to_string() << "\n";
                  }

                  output() << cert.PEM_encode() << "\n";
               }
            }
         }
      }
};

BOTAN_REGISTER_COMMAND("trust_roots", Trust_Root_Info);

   #endif

class Sign_Cert final : public Command {
   public:
      Sign_Cert() :
            Command(
               "sign_cert --ca-key-pass= --hash= "
               "--duration=365 --emsa= ca_cert ca_key pkcs10_req") {}

      std::string group() const override { return "x509"; }

      std::string description() const override { return "Create a CA-signed X.509 certificate from a PKCS #10 CSR"; }

      void go() override {
         Botan::X509_Certificate ca_cert(get_arg("ca_cert"));

         const std::string key_file = get_arg("ca_key");
         const std::string pass = get_passphrase_arg("Password for " + key_file, "ca-key-pass");
         const std::string emsa = get_arg("emsa");
         const std::string hash = get_arg("hash");

         auto key = load_private_key(key_file, pass);

         Botan::X509_CA ca(ca_cert, *key, hash, emsa, rng());

         Botan::PKCS10_Request req(get_arg("pkcs10_req"));

         auto now = std::chrono::system_clock::now();

         Botan::X509_Time start_time(now);

         typedef std::chrono::duration<int, std::ratio<86400>> days;

         Botan::X509_Time end_time(now + days(get_arg_sz("duration")));

         Botan::X509_Certificate new_cert = ca.sign_request(req, rng(), start_time, end_time);
         update_stateful_private_key(*key, rng(), key_file, pass);

         output() << new_cert.PEM_encode();
      }
};

BOTAN_REGISTER_COMMAND("sign_cert", Sign_Cert);

class Cert_Info final : public Command {
   public:
      Cert_Info() : Command("cert_info --fingerprint file") {}

      std::string group() const override { return "x509"; }

      std::string description() const override { return "Parse X.509 certificate and display data fields"; }

      void go() override {
         std::vector<uint8_t> data = slurp_file(get_arg("file"));

         Botan::DataSource_Memory in(data);

         while(!in.end_of_data()) {
            try {
               Botan::X509_Certificate cert(in);

               try {
                  output() << cert.to_string() << std::endl;
               } catch(Botan::Exception& e) {
                  // to_string failed - report the exception and continue
                  output() << "X509_Certificate::to_string failed: " << e.what() << "\n";
               }

               if(flag_set("fingerprint")) {
                  output() << "Fingerprint: " << cert.fingerprint("SHA-256") << std::endl;
               }
            } catch(Botan::Exception& e) {
               if(!in.end_of_data()) {
                  output() << "X509_Certificate parsing failed " << e.what() << "\n";
               }
            }
         }
      }
};

BOTAN_REGISTER_COMMAND("cert_info", Cert_Info);

   #if defined(BOTAN_HAS_OCSP) && defined(BOTAN_HAS_HTTP_UTIL)

class OCSP_Check final : public Command {
   public:
      OCSP_Check() : Command("ocsp_check --timeout=3000 subject issuer") {}

      std::string group() const override { return "x509"; }

      std::string description() const override {
         return "Verify an X.509 certificate against the issuers OCSP responder";
      }

      void go() override {
         Botan::X509_Certificate subject(get_arg("subject"));
         Botan::X509_Certificate issuer(get_arg("issuer"));
         std::chrono::milliseconds timeout(get_arg_sz("timeout"));

         Botan::Certificate_Store_In_Memory cas;
         cas.add_certificate(issuer);
         Botan::OCSP::Response resp = Botan::OCSP::online_check(issuer, subject, timeout);

         auto status = resp.status_for(issuer, subject, std::chrono::system_clock::now());

         if(status == Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD) {
            output() << "OCSP check OK\n";
         } else {
            output() << "OCSP check failed " << Botan::Path_Validation_Result::status_string(status) << "\n";
         }
      }
};

BOTAN_REGISTER_COMMAND("ocsp_check", OCSP_Check);

   #endif  // OCSP && HTTP

class Cert_Verify final : public Command {
   public:
      Cert_Verify() : Command("cert_verify subject *ca_certs") {}

      std::string group() const override { return "x509"; }

      std::string description() const override {
         return "Verify if the passed X.509 certificate passes path validation";
      }

      void go() override {
         Botan::X509_Certificate subject_cert(get_arg("subject"));
         Botan::Certificate_Store_In_Memory trusted;

         for(const auto& certfile : get_arg_list("ca_certs")) {
            trusted.add_certificate(Botan::X509_Certificate(certfile));
         }

         Botan::Path_Validation_Restrictions restrictions;

         Botan::Path_Validation_Result result = Botan::x509_path_validate(subject_cert, restrictions, trusted);

         if(result.successful_validation()) {
            output() << "Certificate passes validation checks\n";
         } else {
            output() << "Certificate did not validate - " << result.result_string() << "\n";
         }
      }
};

BOTAN_REGISTER_COMMAND("cert_verify", Cert_Verify);

class Gen_Self_Signed final : public Command {
   public:
      Gen_Self_Signed() :
            Command(
               "gen_self_signed key CN --country= --dns= "
               "--organization= --email= --path-limit=1 --days=365 --key-pass= --ca --hash= --emsa= --der") {}

      std::string group() const override { return "x509"; }

      std::string description() const override { return "Generate a self signed X.509 certificate"; }

      void go() override {
         const std::string key_file = get_arg("key");
         const std::string passphrase = get_passphrase_arg("Passphrase for " + key_file, "key-pass");
         auto key = load_private_key(key_file, passphrase);

         const uint32_t lifetime = static_cast<uint32_t>(get_arg_sz("days") * 24 * 60 * 60);

         Botan::X509_Cert_Options opts("", lifetime);

         opts.common_name = get_arg("CN");
         opts.country = get_arg("country");
         opts.organization = get_arg("organization");
         opts.email = get_arg("email");
         opts.more_dns = Command::split_on(get_arg("dns"), ',');
         const bool der_format = flag_set("der");

         std::string emsa = get_arg("emsa");

         if(emsa.empty() == false) {
            opts.set_padding_scheme(emsa);
         }

         if(flag_set("ca")) {
            opts.CA_key(get_arg_sz("path-limit"));
         }

         Botan::X509_Certificate cert = Botan::X509::create_self_signed_cert(opts, *key, get_arg("hash"), rng());
         update_stateful_private_key(*key, rng(), key_file, passphrase);

         if(der_format) {
            auto der = cert.BER_encode();
            output().write(reinterpret_cast<const char*>(der.data()), der.size());
         } else {
            output() << cert.PEM_encode();
         }
      }
};

BOTAN_REGISTER_COMMAND("gen_self_signed", Gen_Self_Signed);

class Generate_PKCS10 final : public Command {
   public:
      Generate_PKCS10() :
            Command(
               "gen_pkcs10 key CN --country= --organization= "
               "--ca --path-limit=1 --email= --dns= --ext-ku= --key-pass= --hash= --emsa=") {}

      std::string group() const override { return "x509"; }

      std::string description() const override { return "Generate a PKCS #10 certificate signing request (CSR)"; }

      void go() override {
         const std::string key_file = get_arg("key");
         const std::string passphrase = get_passphrase_arg("Passphrase for " + key_file, "key-pass");

         auto key = load_private_key(key_file, passphrase);

         Botan::X509_Cert_Options opts;

         opts.common_name = get_arg("CN");
         opts.country = get_arg("country");
         opts.organization = get_arg("organization");
         opts.email = get_arg("email");
         opts.more_dns = Command::split_on(get_arg("dns"), ',');

         if(flag_set("ca")) {
            opts.CA_key(get_arg_sz("path-limit"));
         }

         for(const std::string& ext_ku : Command::split_on(get_arg("ext-ku"), ',')) {
            opts.add_ex_constraint(ext_ku);
         }

         std::string emsa = get_arg("emsa");

         if(emsa.empty() == false) {
            opts.set_padding_scheme(emsa);
         }

         Botan::PKCS10_Request req = Botan::X509::create_cert_req(opts, *key, get_arg("hash"), rng());
         update_stateful_private_key(*key, rng(), key_file, passphrase);

         output() << req.PEM_encode();
      }
};

BOTAN_REGISTER_COMMAND("gen_pkcs10", Generate_PKCS10);

}  // namespace Botan_CLI

#endif
