/*
* (C) 2026
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_PKCS12) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   #include <botan/asn1_time.h>
   #include <botan/data_src.h>
   #include <botan/hex.h>
   #include <botan/pk_keys.h>
   #include <botan/pkcs12.h>
   #include <botan/pkcs8.h>
   #include <botan/pkix_types.h>
   #include <botan/x509cert.h>
   #include <fstream>

namespace Botan_CLI {

class PKCS12_Export final : public Command {
   public:
      PKCS12_Export() :
            Command("pkcs12_export --pass= --key-pass= --friendly-name= --use-pbes2 --iterations=2048 --output= key cert *ca_certs") {
      }

      std::string group() const override { return "pkcs12"; }

      std::string description() const override { return "Export private key and certificate(s) to PKCS#12/PFX format"; }

      void go() override {
         const std::string key_file = get_arg("key");
         const std::string key_pass = get_passphrase_arg("Key file password (empty if unencrypted)", "key-pass");
         const std::string pfx_pass = get_passphrase_arg("PFX password", "pass");
         const std::string output_file = get_arg("output");

         // Load private key
         Botan::DataSource_Stream key_stream(key_file);
         auto private_key = Botan::PKCS8::load_key(key_stream, key_pass);
         if(!private_key) {
            throw CLI_Error("Failed to load private key from " + key_file);
         }

         // Load end-entity certificate
         const Botan::X509_Certificate cert(get_arg("cert"));

         // Load CA certificate chain
         std::vector<Botan::X509_Certificate> ca_chain;
         for(const auto& ca_file : get_arg_list("ca_certs")) {
            ca_chain.emplace_back(ca_file);
         }

         // Set options
         Botan::PKCS12_Options options;
         options.password = pfx_pass;
         options.iterations = get_arg_sz("iterations");

         const std::string friendly_name = get_arg("friendly-name");
         if(!friendly_name.empty()) {
            options.friendly_name = friendly_name;
         }

         if(flag_set("use-pbes2")) {
            options.key_encryption_algo = "PBES2-SHA256-AES256";
         }

         // Create PKCS#12
         const auto pfx_data = Botan::PKCS12::create(*private_key, cert, ca_chain, options, rng());

         if(!output_file.empty()) {
            std::ofstream out(output_file, std::ios::binary);
            if(!out) {
               throw CLI_Error("Failed to open output file: " + output_file);
            }
            out.write(reinterpret_cast<const char*>(pfx_data.data()), pfx_data.size());
         } else {
            write_output(pfx_data);
         }
      }
};

BOTAN_REGISTER_COMMAND("pkcs12_export", PKCS12_Export);

class PKCS12_Import final : public Command {
   public:
      PKCS12_Import() :
            Command(
               "pkcs12_import --pass= --key-out= --cert-out= --chain-out= --key-pass= --key-cipher= --key-pbkdf-iter=100000 pfx_file") {
      }

      std::string group() const override { return "pkcs12"; }

      std::string description() const override { return "Import private key and certificate(s) from PKCS#12/PFX file"; }

      void go() override {
         const std::string pfx_file = get_arg("pfx_file");
         const std::string pfx_pass = get_passphrase_arg("PFX password", "pass");

         std::vector<uint8_t> pfx_data = slurp_file(pfx_file);

         // Parse PKCS#12
         const auto pkcs12_data = Botan::PKCS12::parse(pfx_data, pfx_pass);

         // Output private key
         const std::string key_out = get_arg("key-out");
         if(!key_out.empty() && pkcs12_data.has_private_key()) {
            const std::string key_pass = get_passphrase_arg("Output key password (empty for unencrypted)", "key-pass");
            std::ofstream key_stream(key_out);
            if(!key_stream) {
               throw CLI_Error("Cannot open " + key_out + " for writing");
            }

            if(key_pass.empty()) {
               key_stream << Botan::PKCS8::PEM_encode(*(pkcs12_data.private_key()));
            } else {
               const std::string cipher = get_arg_or("key-cipher", "AES-256/CBC");
               const size_t iterations = get_arg_sz("key-pbkdf-iter");
               key_stream << Botan::PKCS8::PEM_encode_encrypted_pbkdf_iter(
                  *(pkcs12_data.private_key()), rng(), key_pass, iterations, cipher);
            }
            output() << "Private key written to " << key_out << "\n";
         }

         // Output end-entity certificate
         const std::string cert_out = get_arg("cert-out");
         if(!cert_out.empty() && pkcs12_data.has_certificate()) {
            std::ofstream cert_stream(cert_out);
            if(!cert_stream) {
               throw CLI_Error("Cannot open " + cert_out + " for writing");
            }
            cert_stream << pkcs12_data.certificate()->PEM_encode();
            output() << "Certificate written to " << cert_out << "\n";
         }

         // Output CA chain
         const std::string chain_out = get_arg("chain-out");
         if(!chain_out.empty() && !pkcs12_data.ca_certificates().empty()) {
            std::ofstream chain_stream(chain_out);
            if(!chain_stream) {
               throw CLI_Error("Cannot open " + chain_out + " for writing");
            }
            for(const auto& ca_cert : pkcs12_data.ca_certificates()) {
               chain_stream << ca_cert->PEM_encode();
            }
            output() << "CA chain (" << pkcs12_data.ca_certificates().size() << " certs) written to " << chain_out
                     << "\n";
         }

         // If no output files specified, show info
         if(key_out.empty() && cert_out.empty() && chain_out.empty()) {
            output() << "PKCS#12 contents:\n";
            if(pkcs12_data.has_private_key()) {
               output() << "  Private key: " << pkcs12_data.private_key()->algo_name() << " ("
                        << pkcs12_data.private_key()->key_length() << " bits)\n";
            }
            if(pkcs12_data.has_certificate()) {
               output() << "  Certificate: " << pkcs12_data.certificate()->subject_dn().to_string() << "\n";
            }
            if(!pkcs12_data.ca_certificates().empty()) {
               output() << "  CA certificates: " << pkcs12_data.ca_certificates().size() << "\n";
               for(const auto& ca_cert : pkcs12_data.ca_certificates()) {
                  output() << "    - " << ca_cert->subject_dn().to_string() << "\n";
               }
            }
            if(!pkcs12_data.friendly_name().empty()) {
               output() << "  Friendly name: " << pkcs12_data.friendly_name() << "\n";
            }
         }
      }
};

BOTAN_REGISTER_COMMAND("pkcs12_import", PKCS12_Import);

class PKCS12_Info final : public Command {
   public:
      PKCS12_Info() : Command("pkcs12_info --pass= pfx_file") {}

      std::string group() const override { return "pkcs12"; }

      std::string description() const override { return "Display information about a PKCS#12/PFX file"; }

      void go() override {
         const std::string pfx_file = get_arg("pfx_file");
         const std::string pfx_pass = get_passphrase_arg("PFX password", "pass");

         std::vector<uint8_t> pfx_data = slurp_file(pfx_file);

         const auto pkcs12_data = Botan::PKCS12::parse(pfx_data, pfx_pass);

         output() << "PKCS#12 File: " << pfx_file << "\n";
         output() << "=====================================\n\n";

         // Private key info
         if(pkcs12_data.has_private_key()) {
            output() << "Private Key:\n";
            output() << "  Algorithm: " << pkcs12_data.private_key()->algo_name() << "\n";
            output() << "  Key Size: " << pkcs12_data.private_key()->key_length() << " bits\n\n";
         }

         // End-entity certificate info
         if(pkcs12_data.has_certificate()) {
            output() << "End-Entity Certificate:\n";
            output() << "  Subject: " << pkcs12_data.certificate()->subject_dn().to_string() << "\n";
            output() << "  Issuer: " << pkcs12_data.certificate()->issuer_dn().to_string() << "\n";
            output() << "  Serial: " << Botan::hex_encode(pkcs12_data.certificate()->serial_number()) << "\n";
            output() << "  Not Before: " << pkcs12_data.certificate()->not_before().readable_string() << "\n";
            output() << "  Not After: " << pkcs12_data.certificate()->not_after().readable_string() << "\n";
            output() << "  SHA-256 Fingerprint: " << pkcs12_data.certificate()->fingerprint("SHA-256") << "\n\n";
         }

         // CA chain info
         if(!pkcs12_data.ca_certificates().empty()) {
            output() << "CA Certificate Chain (" << pkcs12_data.ca_certificates().size() << " certificates):\n";
            size_t idx = 1;
            for(const auto& ca_cert : pkcs12_data.ca_certificates()) {
               output() << "  [" << idx++ << "] Subject: " << ca_cert->subject_dn().to_string() << "\n";
               output() << "      Issuer: " << ca_cert->issuer_dn().to_string() << "\n";
               output() << "      Not After: " << ca_cert->not_after().readable_string() << "\n";
            }
            output() << "\n";
         }

         // Friendly name
         if(!pkcs12_data.friendly_name().empty()) {
            output() << "Friendly Name: " << pkcs12_data.friendly_name() << "\n";
         }
      }
};

BOTAN_REGISTER_COMMAND("pkcs12_info", PKCS12_Info);

}  // namespace Botan_CLI

#endif
