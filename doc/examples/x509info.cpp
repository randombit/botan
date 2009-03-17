/*
  Read an X.509 certificate, and print various things about it

  Written by Jack Lloyd, March 23 2003
    - October 31, 2003: Prints the public key
    - November 1, 2003: Removed the -d flag; it can tell automatically now

  This file is in the public domain
*/
#include <botan/botan.h>
#include <botan/x509cert.h>
#include <botan/oids.h>
using namespace Botan;

#include <iostream>
#include <iterator>
#include <algorithm>

std::string to_hex(const SecureVector<byte>& bin)
   {
   Pipe pipe(new Hex_Encoder);
   pipe.process_msg(bin);
   if(pipe.remaining())
      return pipe.read_all_as_string();
   else
      return "(none)";
   }

void do_print(const std::string& what,
              const std::vector<std::string>& vals)
   {
   if(vals.size() == 0)
      return;

   std::cout << "   " << what << ": ";
   std::copy(vals.begin(), vals.end(),
             std::ostream_iterator<std::string>(std::cout, " "));
   std::cout << "\n";
   }

void do_subject(const X509_Certificate& cert, const std::string& what)
   {
   do_print(what, cert.subject_info(what));
   }

void do_issuer(const X509_Certificate& cert, const std::string& what)
   {
   do_print(what, cert.issuer_info(what));
   }

int main(int argc, char* argv[])
   {
   if(argc != 2)
      {
      std::cout << "Usage: " << argv[0] << " <x509cert>\n";
      return 1;
      }

   Botan::LibraryInitializer init;

   try {
      X509_Certificate cert(argv[1]);

      std::cout << "Version: " << cert.x509_version() << std::endl;

      std::cout << "Subject" << std::endl;
      do_subject(cert, "Name");
      do_subject(cert, "Email");
      do_subject(cert, "Organization");
      do_subject(cert, "Organizational Unit");
      do_subject(cert, "Locality");
      do_subject(cert, "State");
      do_subject(cert, "Country");
      do_subject(cert, "IP");
      do_subject(cert, "DNS");
      do_subject(cert, "URI");
      do_subject(cert, "PKIX.XMPPAddr");

      std::cout << "Issuer" << std::endl;
      do_issuer(cert, "Name");
      do_issuer(cert, "Email");
      do_issuer(cert, "Organization");
      do_issuer(cert, "Organizational Unit");
      do_issuer(cert, "Locality");
      do_issuer(cert, "State");
      do_issuer(cert, "Country");
      do_issuer(cert, "IP");
      do_issuer(cert, "DNS");
      do_issuer(cert, "URI");

      std::cout << "Validity" << std::endl;

      std::cout << "   Not before: " << cert.start_time() << std::endl;
      std::cout << "   Not after: " << cert.end_time() << std::endl;

      std::cout << "Constraints" << std::endl;
      Key_Constraints constraints = cert.constraints();
      if(constraints == NO_CONSTRAINTS)
         std::cout << "No constraints" << std::endl;
      else
         {
         if(constraints & DIGITAL_SIGNATURE)
            std::cout << "   Digital Signature\n";
         if(constraints & NON_REPUDIATION)
            std::cout << "   Non-Repuidation\n";
         if(constraints & KEY_ENCIPHERMENT)
            std::cout << "   Key Encipherment\n";
         if(constraints & DATA_ENCIPHERMENT)
            std::cout << "   Data Encipherment\n";
         if(constraints & KEY_AGREEMENT)
            std::cout << "   Key Agreement\n";
         if(constraints & KEY_CERT_SIGN)
            std::cout << "   Cert Sign\n";
         if(constraints & CRL_SIGN)
            std::cout << "   CRL Sign\n";
         }

      std::vector<std::string> policies = cert.policies();
      if(policies.size())
         {
         std::cout << "Policies: " << std::endl;
         for(u32bit j = 0; j != policies.size(); j++)
            std::cout << "   " << policies[j] << std::endl;
         }

      std::vector<std::string> ex_constraints = cert.ex_constraints();
      if(ex_constraints.size())
         {
         std::cout << "Extended Constraints: " << std::endl;
         for(u32bit j = 0; j != ex_constraints.size(); j++)
            std::cout << "   " << ex_constraints[j] << std::endl;
         }

      std::cout << "Signature algorithm: " <<
         OIDS::lookup(cert.signature_algorithm().oid) << std::endl;

      std::cout << "Serial: "
                << to_hex(cert.serial_number()) << std::endl;
      std::cout << "Authority keyid: "
                << to_hex(cert.authority_key_id()) << std::endl;
      std::cout << "Subject keyid: "
                << to_hex(cert.subject_key_id()) << std::endl;

      X509_PublicKey* pubkey = cert.subject_public_key();
      std::cout << "Public Key:\n" << X509::PEM_encode(*pubkey);
      delete pubkey;
   }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }
   return 0;
   }
