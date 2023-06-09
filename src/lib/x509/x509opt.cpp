/*
* X.509 Certificate Options
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509self.h>

#include <botan/internal/parsing.h>
#include <chrono>

namespace Botan {

/*
* Set when the certificate should become valid
*/
void X509_Cert_Options::not_before(std::string_view time_string) {
   start = X509_Time(time_string);
}

/*
* Set when the certificate should expire
*/
void X509_Cert_Options::not_after(std::string_view time_string) {
   end = X509_Time(time_string);
}

/*
* Set key constraint information
*/
void X509_Cert_Options::add_constraints(Key_Constraints usage) {
   constraints = usage;
}

/*
* Set key constraint information
*/
void X509_Cert_Options::add_ex_constraint(const OID& oid) {
   ex_constraints.push_back(oid);
}

/*
* Set key constraint information
*/
void X509_Cert_Options::add_ex_constraint(std::string_view oid_str) {
   ex_constraints.push_back(OID::from_string(oid_str));
}

/*
* Mark this certificate for CA usage
*/
void X509_Cert_Options::CA_key(size_t limit) {
   is_CA = true;
   path_limit = limit;
}

void X509_Cert_Options::set_padding_scheme(std::string_view scheme) {
   padding_scheme = scheme;
}

/*
* Initialize the certificate options
*/
X509_Cert_Options::X509_Cert_Options(std::string_view initial_opts, uint32_t expiration_time) {
   is_CA = false;
   path_limit = 0;
   // use default for chosen algorithm
   padding_scheme = "";

   auto now = std::chrono::system_clock::now();

   start = X509_Time(now);
   end = X509_Time(now + std::chrono::seconds(expiration_time));

   if(initial_opts.empty()) {
      return;
   }

   std::vector<std::string> parsed = split_on(initial_opts, '/');

   if(parsed.size() > 4) {
      throw Invalid_Argument("X.509 cert options: Too many names");
   }

   if(!parsed.empty()) {
      common_name = parsed[0];
   }
   if(parsed.size() >= 2) {
      country = parsed[1];
   }
   if(parsed.size() >= 3) {
      organization = parsed[2];
   }
   if(parsed.size() == 4) {
      org_unit = parsed[3];
   }
}

}  // namespace Botan
