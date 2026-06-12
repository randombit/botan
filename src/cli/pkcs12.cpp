/*
* PKCS#12 CLI
* (C) 2026 Damiano Mazzella
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
            Command(
               "pkcs12_export --output= --pass= --in-key-pass= --friendly-name= --key-cipher=PBES2-SHA256-AES256 --no-mac --cert-cipher= --mac-digest=SHA-256 --iterations=100000 key cert *ca_certs") {
      }

      std::string group() const override { return "pkcs12"; }

      std::string description() const override { return "Export private key and certificate(s) to PKCS#12/PFX format"; }

      void go() override {
         const std::string key_file = get_arg("key");
         const std::string key_pass = get_passphrase_arg("Key file password (empty if unencrypted)", "in-key-pass");
         const std::string pfx_pass = get_passphrase_arg("PFX password", "pass");

         // Load private key
         Botan::DataSource_Stream key_stream(key_file);
         auto private_key = Botan::PKCS8::load_key(key_stream, key_pass);
         if(!private_key) {
            throw CLI_Error("Failed to load private key from " + key_file);
         }

         // Load end-entity certificate
         const Botan::X509_Certificate cert(get_arg("cert"));

         // Populate the bundle
         Botan::PKCS12 bundle;
         bundle.add_key(std::shared_ptr<Botan::Private_Key>(std::move(private_key)));
         bundle.add_certificate(cert);
         for(const auto& ca_file : get_arg_list("ca_certs")) {
            bundle.add_certificate(Botan::X509_Certificate(ca_file));
         }

         const std::string friendly_name = get_arg("friendly-name");
         if(!friendly_name.empty()) {
            bundle.set_friendly_name(friendly_name);
         }

         // Build export options
         Botan::PKCS12_Export_Options options(pfx_pass);
         options.with_iterations(get_arg_sz("iterations"));
         options.with_key_encryption_algo(get_arg("key-cipher"));

         const std::string cert_cipher = get_arg("cert-cipher");
         if(!cert_cipher.empty()) {
            options.with_cert_encryption_algo(cert_cipher);
         }

         if(flag_set("no-mac")) {
            options.without_mac();
         }

         const std::string mac_digest = get_arg("mac-digest");
         if(!mac_digest.empty()) {
            options.with_mac_digest(mac_digest);
         }

         const auto pfx_data = bundle.export_to(options, rng());

         write_output(pfx_data);
      }
};

BOTAN_REGISTER_COMMAND("pkcs12_export", PKCS12_Export);

class PKCS12_Import final : public Command {
   public:
      PKCS12_Import() :
            Command(
               "pkcs12_import --pass= --key-out= --cert-out= --chain-out= --out-key-pass= --out-key-cipher= --key-pbkdf-iter=100000 pfx_file") {
      }

      std::string group() const override { return "pkcs12"; }

      std::string description() const override { return "Import private key and certificate(s) from PKCS#12/PFX file"; }

      void go() override {
         const std::string pfx_file = get_arg("pfx_file");
         const std::string pfx_pass = get_passphrase_arg("PFX password", "pass");

         std::vector<uint8_t> pfx_data = slurp_file(pfx_file);

         const Botan::PKCS12 bundle(pfx_data, pfx_pass);

         const bool has_key = !bundle.private_keys().empty();
         const auto end_entity = bundle.end_entity_certificate();

         // Build CA chain list (everything except end-entity)
         const std::vector<Botan::X509_Certificate> ca_chain = bundle.ca_certificates();

         // Output private key
         const std::string key_out = get_arg("key-out");
         if(!key_out.empty() && !has_key) {
            output() << "Warning: --key-out specified but PFX contains no private key\n";
         }
         if(!key_out.empty() && has_key) {
            const std::string key_pass =
               get_passphrase_arg("Output key password (empty for unencrypted)", "out-key-pass");
            std::ofstream key_stream(key_out);
            if(!key_stream) {
               throw CLI_Error("Cannot open " + key_out + " for writing");
            }

            const auto& key = *bundle.private_keys().front();
            if(key_pass.empty()) {
               key_stream << Botan::PKCS8::PEM_encode(key);
            } else {
               const std::string cipher = get_arg_or("out-key-cipher", "AES-256/CBC");
               const size_t iterations = get_arg_sz("key-pbkdf-iter");
               key_stream << Botan::PKCS8::PEM_encode_encrypted_pbkdf_iter(key, rng(), key_pass, iterations, cipher);
            }
            output() << "Private key written to " << key_out << "\n";
         }

         // Output end-entity certificate
         const std::string cert_out = get_arg("cert-out");
         if(!cert_out.empty() && !end_entity.has_value()) {
            output() << "Warning: --cert-out specified but PFX contains no end-entity certificate\n";
         }
         if(!cert_out.empty() && end_entity.has_value()) {
            std::ofstream cert_stream(cert_out);
            if(!cert_stream) {
               throw CLI_Error("Cannot open " + cert_out + " for writing");
            }
            cert_stream << end_entity->PEM_encode();
            output() << "Certificate written to " << cert_out << "\n";
         }

         // Output CA chain
         const std::string chain_out = get_arg("chain-out");
         if(!chain_out.empty() && ca_chain.empty()) {
            output() << "Warning: --chain-out specified but PFX contains no CA certificates\n";
         }
         if(!chain_out.empty() && !ca_chain.empty()) {
            std::ofstream chain_stream(chain_out);
            if(!chain_stream) {
               throw CLI_Error("Cannot open " + chain_out + " for writing");
            }
            for(const auto& ca_cert : ca_chain) {
               chain_stream << ca_cert.PEM_encode();
            }
            output() << "CA chain (" << ca_chain.size() << " certs) written to " << chain_out << "\n";
         }

         // If no output files specified, show info
         if(key_out.empty() && cert_out.empty() && chain_out.empty()) {
            output() << "PKCS#12 contents:\n\n";
            if(has_key) {
               const auto& key = *bundle.private_keys().front();
               output() << "Private Key:\n";
               output() << "  Algorithm: " << key.algo_name() << "\n";
               output() << "  Key Size: " << key.key_length() << " bits\n\n";
            }
            if(end_entity.has_value()) {
               output() << "End-Entity Certificate:\n";
               output() << "  Subject: " << end_entity->subject_dn().to_string() << "\n";
               output() << "  Issuer: " << end_entity->issuer_dn().to_string() << "\n";
               output() << "  Serial: " << Botan::hex_encode(end_entity->serial_number()) << "\n";
               output() << "  Not Before: " << end_entity->not_before().readable_string() << "\n";
               output() << "  Not After: " << end_entity->not_after().readable_string() << "\n";
               output() << "  SHA-1 Fingerprint:   " << end_entity->fingerprint("SHA-1") << "\n";
               output() << "  SHA-256 Fingerprint: " << end_entity->fingerprint("SHA-256") << "\n\n";
            }
            if(!ca_chain.empty()) {
               output() << "CA Certificate Chain (" << ca_chain.size() << " certificates):\n";
               size_t idx = 1;
               for(const auto& ca_cert : ca_chain) {
                  output() << "  [" << idx++ << "] Subject: " << ca_cert.subject_dn().to_string() << "\n";
                  output() << "      Issuer: " << ca_cert.issuer_dn().to_string() << "\n";
                  output() << "      Not After: " << ca_cert.not_after().readable_string() << "\n";
               }
               output() << "\n";
            }
            if(bundle.friendly_name().has_value()) {
               output() << "Friendly name: " << *bundle.friendly_name() << "\n";
            }
         }
      }
};

BOTAN_REGISTER_COMMAND("pkcs12_import", PKCS12_Import);

}  // namespace Botan_CLI

#endif
