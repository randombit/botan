/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

/*
* Generate a root CA plus httpd, dovecot, and postfix certs/keys
*
*/

#include <botan/botan.h>
#include <botan/rsa.h>
#include <botan/time.h>
#include <botan/x509self.h>
#include <botan/x509_ca.h>

using namespace Botan;

#include <iostream>
#include <fstream>

namespace {

void fill_commoninfo(X509_Cert_Options& opts)
   {
   opts.country = "US";
   opts.organization = "randombit.net";
   opts.email = "admin@randombit.net";
   opts.locality = "Vermont";
   }

X509_Certificate make_ca_cert(RandomNumberGenerator& rng,
                              const Private_Key& priv_key,
                              const X509_Time& now,
                              const X509_Time& later)
   {
   X509_Cert_Options opts;
   fill_commoninfo(opts);
   opts.common_name = "randombit.net CA";
   opts.start = now;
   opts.end = later;
   opts.CA_key();

   return X509::create_self_signed_cert(opts, priv_key, "SHA-256", rng);
   }

PKCS10_Request make_server_cert_req(const Private_Key& key,
                                    const std::string& hostname,
                                    RandomNumberGenerator& rng)
   {
   X509_Cert_Options opts;
   opts.common_name = hostname;
   fill_commoninfo(opts);

   opts.add_ex_constraint("PKIX.ServerAuth");

   return X509::create_cert_req(opts, key, "SHA-1", rng);
   }

void save_pair(const std::string& name,
               const std::string& password,
               const X509_Certificate& cert,
               const Private_Key& key,
               RandomNumberGenerator& rng)
   {
   std::string cert_fsname = name + "_cert.pem";
   std::string key_fsname = name + "_key.pem";

   std::ofstream cert_out(cert_fsname.c_str());
   cert_out << cert.PEM_encode() << "\n";
   cert_out.close();

   std::ofstream key_out(key_fsname.c_str());
   if(password != "")
      key_out << PKCS8::PEM_encode(key, rng, password);
   else
      key_out << PKCS8::PEM_encode(key);
   key_out.close();
   }

}

int main()
   {
   const u32bit seconds_in_a_year = 31556926;

   const u32bit current_time = system_time();

   X509_Time now = X509_Time(current_time);
   X509_Time later = X509_Time(current_time + 4*seconds_in_a_year);

   LibraryInitializer init;

   AutoSeeded_RNG rng;

   RSA_PrivateKey ca_key(rng, 2048);

   X509_Certificate ca_cert = make_ca_cert(rng, ca_key, now, later);

   const std::string ca_password = "sekrit";

   save_pair("ca", ca_password, ca_cert, ca_key, rng);

   X509_CA ca(ca_cert, ca_key, "SHA-256");

   RSA_PrivateKey httpd_key(rng, 1536);
   X509_Certificate httpd_cert = ca.sign_request(
      make_server_cert_req(httpd_key, "www.randombit.net", rng),
      rng, now, later);

   save_pair("httpd", "", httpd_cert, httpd_key, rng);

   RSA_PrivateKey bugzilla_key(rng, 1536);
   X509_Certificate bugzilla_cert = ca.sign_request(
      make_server_cert_req(bugzilla_key, "bugs.randombit.net", rng),
      rng, now, later);

   save_pair("bugzilla", "", bugzilla_cert, bugzilla_key, rng);

   RSA_PrivateKey postfix_key(rng, 1536);
   X509_Certificate postfix_cert = ca.sign_request(
      make_server_cert_req(postfix_key, "mail.randombit.net", rng),
      rng, now, later);

   save_pair("postfix", "", postfix_cert, postfix_key, rng);

   RSA_PrivateKey dovecot_key(rng, 1536);
   X509_Certificate dovecot_cert = ca.sign_request(
      make_server_cert_req(dovecot_key, "imap.randombit.net", rng),
      rng, now, later);

   save_pair("dovecot", "", dovecot_cert, dovecot_key, rng);
   }
