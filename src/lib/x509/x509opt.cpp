/*
* X.509 Certificate Options
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509self.h>

#include <botan/internal/fmt.h>
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

CertificateParametersBuilder X509_Cert_Options::into_builder() const {
   auto builder = CertificateParametersBuilder();
   if(!this->common_name.empty()) {
      builder.add_common_name(this->common_name);
   }
   if(!this->country.empty()) {
      builder.add_country(this->country);
   }
   if(!this->organization.empty()) {
      builder.add_organization(this->organization);
   }
   if(!this->org_unit.empty()) {
      builder.add_organizational_unit(this->org_unit);
   }
   for(const auto& ou : this->more_org_units) {
      if(!ou.empty()) {
         builder.add_organizational_unit(ou);
      }
   }
   if(!this->locality.empty()) {
      builder.add_locality(this->locality);
   }
   if(!this->state.empty()) {
      builder.add_state(this->state);
   }
   if(!this->serial_number.empty()) {
      builder.add_serial_number(this->serial_number);
   }
   if(!this->email.empty()) {
      builder.add_email(this->email);
   }
   if(!this->uri.empty()) {
      builder.add_uri(this->uri);
   }
   if(!this->ip.empty()) {
      if(auto ipv4 = string_to_ipv4(this->ip)) {
         builder.add_ipv4(*ipv4);
      } else {
         throw Invalid_Argument(fmt("Invalid IPv4 address '{}'", this->ip));
      }
   }

   if(!this->dns.empty()) {
      builder.add_dns(this->dns);
   }
   for(const auto& nm : this->more_dns) {
      if(!nm.empty()) {
         builder.add_dns(nm);
      }
   }
   if(!this->xmpp.empty()) {
      builder.add_xmpp(this->xmpp);
   }
   if(this->is_CA) {
      builder.set_as_ca_certificate(this->path_limit);
   }
   if(!this->constraints.empty()) {
      builder.add_allowed_usage(this->constraints);
   }
   for(const OID& usage : this->ex_constraints) {
      builder.add_allowed_extended_usage(usage);
   }

   for(auto& [extn, is_critical] : this->extensions.extensions()) {
      builder.add_extension(std::move(extn), is_critical);
   }

   return builder;
}

}  // namespace Botan
