/*
* (C) 2010,2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)

#include <botan/certstor.h>
#include <botan/pkcs8.h>
#include <botan/x509_ca.h>
#include <botan/x509cert.h>
#include <botan/x509path.h>
#include <botan/x509self.h>

#if defined(BOTAN_HAS_OCSP)
  #include <botan/ocsp.h>
#endif

namespace Botan_CLI {

class Sign_Cert final : public Command
   {
   public:
      Sign_Cert() : Command("sign_cert --ca-key-pass= --hash=SHA-256 "
                            "--duration=365 ca_cert ca_key pkcs10_req") {}

      void go() override
         {
         Botan::X509_Certificate ca_cert(get_arg("ca_cert"));
         std::unique_ptr<Botan::PKCS8_PrivateKey> key;

         if(flag_set("ca_key_pass"))
            {
            key.reset(Botan::PKCS8::load_key(get_arg("ca_key"),
                     rng(),
                     get_arg("ca_key_pass")));
            }
         else
            {
            key.reset(Botan::PKCS8::load_key(get_arg("ca_key"),
                     rng()));
            }

         if(!key)
            throw CLI_Error("Failed to load key from " + get_arg("ca_key"));

         Botan::X509_CA ca(ca_cert, *key, get_arg("hash"), rng());

         Botan::PKCS10_Request req(get_arg("pkcs10_req"));

         auto now = std::chrono::system_clock::now();

         Botan::X509_Time start_time(now);

         typedef std::chrono::duration<int, std::ratio<86400>> days;

         Botan::X509_Time end_time(now + days(get_arg_sz("duration")));

         Botan::X509_Certificate new_cert = ca.sign_request(req, rng(),
                                                            start_time, end_time);

         output() << new_cert.PEM_encode();
         }
   };

BOTAN_REGISTER_COMMAND("sign_cert", Sign_Cert);

class Cert_Info final : public Command
   {
   public:
      Cert_Info() : Command("cert_info --ber file") {}

      void go() override
         {
         Botan::DataSource_Stream in(get_arg("file"), flag_set("ber"));

         while(!in.end_of_data())
            {
            try
               {
               Botan::X509_Certificate cert(in);

               try
                  {
                  output() << cert.to_string() << std::endl;
                  }
               catch(Botan::Exception& e)
                  {
                  // to_string failed - report the exception and continue
                  output() << "X509_Certificate::to_string failed: " << e.what() << "\n";
                  }
               }
            catch(Botan::Exception& e)
               {
               if(!in.end_of_data())
                  output() << "X509_Certificate parsing failed " << e.what() << "\n";
               }
            }
         }
   };

BOTAN_REGISTER_COMMAND("cert_info", Cert_Info);

#if defined(BOTAN_HAS_OCSP) && defined(BOTAN_HAS_HTTP_UTIL)

class OCSP_Check final : public Command
   {
   public:
      OCSP_Check() : Command("ocsp_check subject issuer") {}

      void go() override
         {
         Botan::X509_Certificate subject(get_arg("subject"));
         Botan::X509_Certificate issuer(get_arg("issuer"));

         Botan::Certificate_Store_In_Memory cas;
         cas.add_certificate(issuer);
         Botan::OCSP::Response resp = Botan::OCSP::online_check(issuer, subject, &cas);

         auto status = resp.status_for(issuer, subject, std::chrono::system_clock::now());

         if(status == Botan::Certificate_Status_Code::VERIFIED)
            {
            output() << "OCSP check OK\n";
            }
         else
            {
            output() << "OCSP check failed " <<
               Botan::Path_Validation_Result::status_string(status) << "\n";
            }
         }
   };

BOTAN_REGISTER_COMMAND("ocsp_check", OCSP_Check);

#endif // OCSP && HTTP

class Cert_Verify final : public Command
   {
   public:
      Cert_Verify() : Command("cert_verify subject *ca_certs") {}

      void go() override
         {
         Botan::X509_Certificate subject_cert(get_arg("subject"));
         Botan::Certificate_Store_In_Memory trusted;

         for(auto&& certfile : get_arg_list("ca_certs"))
            {
            trusted.add_certificate(Botan::X509_Certificate(certfile));
            }

         Botan::Path_Validation_Restrictions restrictions;

         Botan::Path_Validation_Result result =
            Botan::x509_path_validate(subject_cert,
                                      restrictions,
                                      trusted);

         if(result.successful_validation())
            {
            output() << "Certificate passes validation checks\n";
            }
         else
            {
            output() << "Certificate did not validate - " << result.result_string() << "\n";
            }
         }
   };

BOTAN_REGISTER_COMMAND("cert_verify", Cert_Verify);

class Gen_Self_Signed final : public Command
   {
   public:
      Gen_Self_Signed() : Command("gen_self_signed key CN --country= --dns= "
                                  "--organization= --email= --key-pass= --ca --hash=SHA-256") {}

      void go() override
         {
         std::unique_ptr<Botan::Private_Key> key(
            Botan::PKCS8::load_key(get_arg("key"),
                                   rng(),
                                   get_arg("key-pass")));

         if(!key)
            throw CLI_Error("Failed to load key from " + get_arg("key"));

         Botan::X509_Cert_Options opts;

         opts.common_name  = get_arg("CN");
         opts.country      = get_arg("country");
         opts.organization = get_arg("organization");
         opts.email        = get_arg("email");
         opts.dns          = get_arg("dns");

         if(flag_set("ca"))
            opts.CA_key();

         Botan::X509_Certificate cert =
            Botan::X509::create_self_signed_cert(opts, *key, get_arg("hash"), rng());

         output() << cert.PEM_encode();
         }
   };

BOTAN_REGISTER_COMMAND("gen_self_signed", Gen_Self_Signed);

class Generate_PKCS10 final : public Command
   {
   public:
      Generate_PKCS10() : Command("gen_pkcs10 key CN --country= --organization= "
                                  "--email= --key-pass= --hash=SHA-256") {}

      void go() override
         {
         std::unique_ptr<Botan::Private_Key> key(
            Botan::PKCS8::load_key(get_arg("key"),
                                   rng(),
                                   get_arg("key-pass")));

         if(!key)
            throw CLI_Error("Failed to load key from " + get_arg("key"));

         Botan::X509_Cert_Options opts;

         opts.common_name  = get_arg("CN");
         opts.country      = get_arg("country");
         opts.organization = get_arg("organization");
         opts.email        = get_arg("email");

         Botan::PKCS10_Request req =
            Botan::X509::create_cert_req(opts, *key,
                                         get_arg("hash"),
                                         rng());

         output() << req.PEM_encode();
         }
   };

BOTAN_REGISTER_COMMAND("gen_pkcs10", Generate_PKCS10);

}

#endif
