/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_builder.h>

#include <botan/assert.h>
#include <botan/pubkey.h>
#include <botan/x509_ca.h>
#include <botan/x509_ext.h>
#include <botan/internal/fmt.h>

namespace Botan {

class CertificateParametersBuilder::State final {
   public:
      const X509_DN& subject_dn() const { return m_subject_dn; }

      Extensions finalize_extensions(const Public_Key& key) const {
         auto extensions = m_extensions;

         extensions.replace(setup_alt_name(extensions));

         extensions.add_new(
            std::make_unique<Cert_Extension::Basic_Constraints>(m_is_ca_request, m_path_limit.value_or(0)), true);

         const Key_Constraints usage = this->usage();

         if(!usage.empty()) {
            if(!usage.compatible_with(key)) {
               throw Invalid_Argument("The requested key usage is incompatible with the algorithm");
            }

            extensions.add_new(std::make_unique<Cert_Extension::Key_Usage>(usage), true);
         }

         if(!m_ext_usage.empty()) {
            extensions.add_new(std::make_unique<Cert_Extension::Extended_Key_Usage>(m_ext_usage));
         }

         return extensions;
      }

      Key_Constraints usage() const {
         if(m_is_ca_request) {
            return Key_Constraints::ca_constraints();
         } else {
            return m_usage;
         }
      }

      void add_common_name(std::string_view cn) { add_subject_dn("common_name", "X520.CommonName", cn); }

      void add_country(std::string_view country) { add_subject_dn("country", "X520.Country", country); }

      void add_state(std::string_view state) { add_subject_dn("state", "X520.State", state); }

      void add_locality(std::string_view locality) { add_subject_dn("locality", "X520.Locality", locality); }

      void add_serial_number(std::string_view sn) { add_subject_dn("serial_number", "X520.SerialNumber", sn); }

      void add_organization(std::string_view org) { add_subject_dn("organization", "X520.Organization", org); }

      void add_organizational_unit(std::string_view org_unit) {
         add_subject_dn("organizational_unit", "X520.OrganizationalUnit", org_unit);
      }

      void add_extension(std::unique_ptr<Certificate_Extension> extn, bool is_critical) {
         if(!m_extensions.add_new(std::move(extn), is_critical)) {
            throw Invalid_Argument("CertificateParametersBuilder::add_extension: cannot add same extension twice");
         }
      }

      void add_email(std::string_view email) { m_email.emplace_back(email); }

      void add_dns(std::string_view dns) { m_dns.emplace_back(dns); }

      void add_uri(std::string_view uri) { m_uri.emplace_back(uri); }

      void add_xmpp(std::string_view xmpp) { m_xmpp.emplace_back(xmpp); }

      void add_ipv4(uint32_t ipv4) { m_ipv4.push_back(ipv4); }

      void add_allowed_usage(Key_Constraints usage) { m_usage |= usage; }

      void add_allowed_extended_usage(const OID& usage) { m_ext_usage.push_back(usage); }

      void set_as_ca_certificate(std::optional<size_t> path_limit) {
         if(m_is_ca_request) {
            throw Invalid_State("CertificateParametersBuilder::set_as_ca_certificate cannot be called twice");
         } else {
            m_is_ca_request = true;
            m_path_limit = path_limit;
         }
      }

   private:
      void add_subject_dn(std::string_view fn_suffix, std::string_view attr, std::string_view value) {
         const auto oid = OID::from_string(attr);
         const size_t ub = X509_DN::lookup_ub(oid);

         if(value.empty()) {
            throw Invalid_Argument(fmt("CertificateParametersBuilder::add_{}: empty name is prohibited", fn_suffix));
         }

         if(value.size() > ub) {
            throw Invalid_Argument(
               fmt("CertificateParametersBuilder::add_{}: name exceeds maximum allowed length ({}) for this type",
                   fn_suffix,
                   ub));
         }
         m_subject_dn.add_attribute(oid, value);
      }

      std::unique_ptr<Certificate_Extension> setup_alt_name(const Extensions& extensions) const {
         AlternativeName subject_alt;

         /*
         If the extension was already created in extensions we need to merge the
         values provided with the extension value
         */
         if(const auto* ext = extensions.get_extension_object_as<Cert_Extension::Subject_Alternative_Name>()) {
            subject_alt = ext->get_alt_name();
         }

         for(const auto& dns : m_dns) {
            subject_alt.add_dns(dns);
         }
         for(const auto& uri : m_uri) {
            subject_alt.add_uri(uri);
         }
         for(const auto& email : m_email) {
            subject_alt.add_email(email);
         }
         for(const auto& xmpp : m_xmpp) {
            subject_alt.add_other_name(OID::from_string("PKIX.XMPPAddr"), ASN1_String(xmpp, ASN1_Type::Utf8String));
         }
         for(const uint32_t ipv4 : m_ipv4) {
            subject_alt.add_ipv4_address(ipv4);
         }

         return std::make_unique<Cert_Extension::Subject_Alternative_Name>(subject_alt);
      }

      X509_DN m_subject_dn;
      Extensions m_extensions;
      Key_Constraints m_usage;
      std::vector<std::string> m_email;
      std::vector<std::string> m_dns;
      std::vector<std::string> m_uri;
      std::vector<std::string> m_xmpp;
      std::vector<uint32_t> m_ipv4;
      std::vector<OID> m_ext_usage;
      bool m_is_ca_request = false;
      std::optional<size_t> m_path_limit;
};

CertificateParametersBuilder::CertificateParametersBuilder() :
      m_state(std::make_unique<CertificateParametersBuilder::State>()) {}

CertificateParametersBuilder::CertificateParametersBuilder(CertificateParametersBuilder&& other) noexcept = default;

CertificateParametersBuilder::~CertificateParametersBuilder() = default;

X509_Certificate CertificateParametersBuilder::into_self_signed_cert(std::chrono::system_clock::time_point not_before,
                                                                     std::chrono::system_clock::time_point not_after,
                                                                     const Private_Key& key,
                                                                     RandomNumberGenerator& rng,
                                                                     std::optional<std::string_view> hash_fn,
                                                                     std::optional<std::string_view> padding) const {
   auto signer_p = X509_Object::choose_sig_format(key, rng, hash_fn.value_or(""), padding.value_or(""));
   auto& signer = *signer_p;

   const AlgorithmIdentifier sig_algo = signer.algorithm_identifier();
   BOTAN_ASSERT_NOMSG(sig_algo.oid().has_value());

   Extensions extensions = m_state->finalize_extensions(key);

   const std::vector<uint8_t> pub_key = key.subject_public_key();
   auto skid = std::make_unique<Cert_Extension::Subject_Key_ID>(pub_key, signer.hash_function());

   extensions.add_new(std::make_unique<Cert_Extension::Authority_Key_ID>(skid->get_key_id()));
   extensions.add_new(std::move(skid));

   const auto& subject_dn = m_state->subject_dn();

   return X509_CA::make_cert(
      signer, rng, sig_algo, pub_key, X509_Time(not_before), X509_Time(not_after), subject_dn, subject_dn, extensions);
}

PKCS10_Request CertificateParametersBuilder::into_pkcs10_request(
   const Private_Key& key,
   RandomNumberGenerator& rng,
   std::optional<std::string_view> hash_fn,
   std::optional<std::string_view> padding,
   std::optional<std::string_view> challenge_password) const {
   const auto& subject_dn = m_state->subject_dn();

   const auto extensions = m_state->finalize_extensions(key);

   return PKCS10_Request::create(
      key, subject_dn, extensions, hash_fn.value_or(""), rng, padding.value_or(""), challenge_password.value_or(""));
}

CertificateParametersBuilder& CertificateParametersBuilder::add_common_name(std::string_view cn) {
   m_state->add_common_name(cn);
   return (*this);
}

CertificateParametersBuilder& CertificateParametersBuilder::add_country(std::string_view country) {
   m_state->add_country(country);
   return (*this);
}

CertificateParametersBuilder& CertificateParametersBuilder::add_organization(std::string_view org) {
   m_state->add_organization(org);
   return (*this);
}

CertificateParametersBuilder& CertificateParametersBuilder::add_organizational_unit(std::string_view org_unit) {
   m_state->add_organizational_unit(org_unit);
   return (*this);
}

CertificateParametersBuilder& CertificateParametersBuilder::add_locality(std::string_view locality) {
   m_state->add_locality(locality);
   return (*this);
}

CertificateParametersBuilder& CertificateParametersBuilder::add_state(std::string_view state) {
   m_state->add_state(state);
   return (*this);
}

CertificateParametersBuilder& CertificateParametersBuilder::add_serial_number(std::string_view serial) {
   m_state->add_serial_number(serial);
   return (*this);
}

CertificateParametersBuilder& CertificateParametersBuilder::add_email(std::string_view email) {
   m_state->add_email(email);
   return (*this);
}

CertificateParametersBuilder& CertificateParametersBuilder::add_uri(std::string_view uri) {
   m_state->add_uri(uri);
   return (*this);
}

CertificateParametersBuilder& CertificateParametersBuilder::add_dns(std::string_view dns) {
   m_state->add_dns(dns);
   return (*this);
}

CertificateParametersBuilder& CertificateParametersBuilder::add_ipv4(uint32_t ipv4) {
   m_state->add_ipv4(ipv4);
   return (*this);
}

CertificateParametersBuilder& CertificateParametersBuilder::add_xmpp(std::string_view xmpp) {
   m_state->add_xmpp(xmpp);
   return (*this);
}

CertificateParametersBuilder& CertificateParametersBuilder::add_allowed_usage(Key_Constraints kc) {
   m_state->add_allowed_usage(kc);
   return (*this);
}

CertificateParametersBuilder& CertificateParametersBuilder::add_allowed_extended_usage(const OID& usage) {
   m_state->add_allowed_extended_usage(usage);
   return (*this);
}

CertificateParametersBuilder& CertificateParametersBuilder::add_extension(std::unique_ptr<Certificate_Extension> extn,
                                                                          bool is_critical) {
   m_state->add_extension(std::move(extn), is_critical);
   return (*this);
}

CertificateParametersBuilder& CertificateParametersBuilder::set_as_ca_certificate(std::optional<size_t> path_limit) {
   m_state->set_as_ca_certificate(path_limit);
   return (*this);
}

}  // namespace Botan
