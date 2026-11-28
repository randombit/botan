/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_CMS) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

   #include <botan/certstor.h>
   #include <botan/cms.h>
   #include <botan/data_src.h>
   #include <botan/pkcs8.h>
   #include <botan/x509cert.h>
   #include <botan/x509path.h>

namespace Botan_CLI {

namespace {

class CMS_Encrypt final : public Command {
   public:
      CMS_Encrypt() : Command("cms_encrypt --cipher=AES-256/GCM recipient_cert file") {}

      std::string group() const override { return "cms"; }

      std::string description() const override { return "Encrypt a file as a CMS enveloped message"; }

      void go() override {
         const Botan::X509_Certificate cert(get_arg("recipient_cert"));
         const auto content = slurp_file(get_arg("file"));

         Botan::CMS::Enveloped_Data_Builder builder;
         builder.set_content_encryption(get_arg("cipher"));

         const std::string key_algo = cert.subject_public_key()->algo_name();
         if(key_algo == "RSA") {
            builder.add_ktri_recipient(cert);
         } else if(key_algo == "ML-KEM") {
            builder.add_kem_recipient(cert);
         } else {
            throw CLI_Usage_Error("Cannot encrypt to a certificate with a " + key_algo + " key");
         }

         write_output(builder.build(content, rng()));
      }
};

BOTAN_REGISTER_COMMAND("cms_encrypt", CMS_Encrypt);

class CMS_Decrypt final : public Command {
   public:
      CMS_Decrypt() : Command("cms_decrypt --key= --cert= file") {}

      std::string group() const override { return "cms"; }

      std::string description() const override { return "Decrypt a CMS enveloped message"; }

      void go() override {
         Botan::DataSource_Stream key_stream(get_arg("key"));
         const auto get_pass = [this]() { return get_passphrase("Passphrase"); };
         const auto key = Botan::PKCS8::load_key(key_stream, get_pass);

         const Botan::X509_Certificate cert(get_arg("cert"));
         const auto content_info = slurp_file(get_arg("file"));

         try {
            write_output(Botan::CMS::decrypt(content_info, *key, cert, rng()));
         } catch(Botan::Exception& e) {
            error_output() << e.what() << "\n";
            set_return_code(1);
         }
      }
};

BOTAN_REGISTER_COMMAND("cms_decrypt", CMS_Decrypt);

class CMS_Sign final : public Command {
   public:
      CMS_Sign() : Command("cms_sign --key= --cert= --hash=SHA-256 --detached file") {}

      std::string group() const override { return "cms"; }

      std::string description() const override { return "Create a CMS signed message"; }

      void go() override {
         Botan::DataSource_Stream key_stream(get_arg("key"));
         const auto get_pass = [this]() { return get_passphrase("Passphrase"); };
         const auto key = Botan::PKCS8::load_key(key_stream, get_pass);

         const Botan::X509_Certificate cert(get_arg("cert"));
         const auto content = slurp_file(get_arg("file"));

         Botan::CMS::Signed_Data_Builder builder;
         builder.add_signer(cert, *key, get_arg("hash")).detached(flag_set("detached"));

         write_output(builder.sign(content, rng()));
      }
};

BOTAN_REGISTER_COMMAND("cms_sign", CMS_Sign);

class CMS_Verify final : public Command {
   public:
      CMS_Verify() : Command("cms_verify --content= --trusted= file") {}

      std::string group() const override { return "cms"; }

      std::string description() const override { return "Verify a CMS signed message"; }

      void go() override {
         const auto content_info = slurp_file(get_arg("file"));

         std::optional<std::vector<uint8_t>> detached_content;
         if(!get_arg("content").empty()) {
            detached_content = slurp_file(get_arg("content"));
         }

         std::optional<Botan::Certificate_Store_In_Memory> trusted;
         if(!get_arg("trusted").empty()) {
            const std::string path = get_arg("trusted");
            try {
               trusted.emplace();
               trusted->add_certificate(Botan::X509_Certificate(path));
            } catch(Botan::Exception&) {
               // Not a single certificate; treat as a directory
               trusted.emplace(path);
            }
         }

         try {
            const auto detached_span =
               detached_content ? std::optional<std::span<const uint8_t>>(*detached_content) : std::nullopt;
            const auto result = Botan::CMS::verify(
               content_info, detached_span, trusted ? &*trusted : nullptr, std::chrono::system_clock::now());

            for(const auto& signer : result.signers()) {
               output() << "Signed by: " << signer.subject_dn() << "\n";
            }

            if(result.path_result().has_value()) {
               output() << "Path validation: " << result.path_result()->result_string() << "\n";
               if(!result.path_result()->successful_validation()) {
                  set_return_code(1);
               }
            }
         } catch(Botan::Exception& e) {
            error_output() << e.what() << "\n";
            set_return_code(1);
         }
      }
};

BOTAN_REGISTER_COMMAND("cms_verify", CMS_Verify);

}  // namespace

}  // namespace Botan_CLI

#endif
