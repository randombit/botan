/*
* X.509 CRL
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_crl.h>

#include <botan/asn1_obj.h>
#include <botan/asn1_time.h>
#include <botan/ber_dec.h>
#include <botan/data_src.h>
#include <botan/x509_ext.h>
#include <botan/x509cert.h>
#include <algorithm>
#include <set>

namespace Botan {

class CRL_Data final {
   public:
      CRL_Data(const X509_DN& issuer,
               const X509_Time& this_update,
               const X509_Time& next_update,
               const std::vector<CRL_Entry>& revoked) :
            m_issuer(issuer), m_this_update(this_update), m_next_update(next_update), m_entries(revoked) {
         this->update_index();
      }

      CRL_Data() = default;

      void update_index() {
         m_revoked_serials.clear();
         for(const auto& entry : m_entries) {
            if(entry.reason_code() == CRL_Code::RemoveFromCrl) {
               m_revoked_serials.erase(entry.serial_number());
            } else {
               m_revoked_serials.insert(entry.serial_number());
            }
         }
      }

      // NOLINTBEGIN(*non-private-member-variables-in-classes)
      X509_DN m_issuer;
      size_t m_version{};
      X509_Time m_this_update;
      X509_Time m_next_update;
      std::vector<CRL_Entry> m_entries;
      Extensions m_extensions;

      // cached values from entries
      std::set<std::vector<uint8_t>> m_revoked_serials;

      // cached values from extensions
      size_t m_crl_number = 0;
      std::vector<uint8_t> m_auth_key_id;
      std::vector<URI> m_idp_urls;
      // NOLINTEND(*non-private-member-variables-in-classes)
};

std::string X509_CRL::PEM_label() const {
   return "X509 CRL";
}

std::vector<std::string> X509_CRL::alternate_PEM_labels() const {
   return {"CRL"};
}

X509_CRL::X509_CRL(DataSource& src) {
   load_data(src);
}

X509_CRL::X509_CRL(const std::vector<uint8_t>& vec) {
   DataSource_Memory src(vec.data(), vec.size());
   load_data(src);
}

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
X509_CRL::X509_CRL(std::string_view fsname) {
   DataSource_Stream src(fsname, true);
   load_data(src);
}
#endif

X509_CRL::X509_CRL(const X509_DN& issuer,
                   const X509_Time& this_update,
                   const X509_Time& next_update,
                   const std::vector<CRL_Entry>& revoked) {
   m_data = std::make_shared<CRL_Data>(issuer, this_update, next_update, revoked);
}

/**
* Check if this particular certificate is listed in the CRL
*/
bool X509_CRL::is_revoked(const X509_Certificate& cert) const {
   /*
   If the cert wasn't issued by the CRL issuer, it's possible the cert
   is revoked, but not by this CRL. Maybe throw an exception instead?
   */
   if(cert.issuer_dn() != issuer_dn()) {
      return false;
   }

   const std::vector<uint8_t> crl_akid = authority_key_id();
   const std::vector<uint8_t>& cert_akid = cert.authority_key_id();

   if(!crl_akid.empty() && !cert_akid.empty()) {
      if(crl_akid != cert_akid) {
         return false;
      }
   }

   return data().m_revoked_serials.contains(cert.serial_number());
}

/*
* Decode the TBSCertList data
*/
namespace {

std::unique_ptr<CRL_Data> decode_crl_body(const std::vector<uint8_t>& body, const AlgorithmIdentifier& sig_algo) {
   auto data = std::make_unique<CRL_Data>();

   BER_Decoder tbs_crl(body, BER_Decoder::Limits::DER());

   tbs_crl.decode_optional(data->m_version, ASN1_Type::Integer, ASN1_Class::Universal);
   data->m_version += 1;  // wire-format is 0-based

   if(data->m_version != 1 && data->m_version != 2) {
      throw Decoding_Error("Unknown X.509 CRL version " + std::to_string(data->m_version));
   }

   AlgorithmIdentifier sig_algo_inner;
   tbs_crl.decode(sig_algo_inner);

   if(sig_algo != sig_algo_inner) {
      throw Decoding_Error("Algorithm identifier mismatch in CRL");
   }

   tbs_crl.decode(data->m_issuer).decode(data->m_this_update);

   // According to RFC 5280 Section 5.1, nextUpdate is OPTIONAL and may be
   // encoded as either a UTCTime or a GeneralizedTime. Section 5.1.2.5
   // further states that "[c]onforming CRL issuers MUST include the nextUpdate
   // field in all CRLs". Obviously, not everyone complies...
   //
   // See https://github.com/randombit/botan/issues/4722 for more details.
   {
      const auto& next_update = tbs_crl.peek_next_object();
      if(next_update.is_a(ASN1_Type::UtcTime, ASN1_Class::Universal) ||
         next_update.is_a(ASN1_Type::GeneralizedTime, ASN1_Class::Universal)) {
         tbs_crl.decode(data->m_next_update);
      }
   }

   BER_Object next = tbs_crl.get_next_object();

   if(next.is_a(ASN1_Type::Sequence, ASN1_Class::Constructed)) {
      BER_Decoder cert_list(next, tbs_crl.limits());

      while(cert_list.more_items()) {
         CRL_Entry entry;
         cert_list.decode(entry);
         data->m_entries.push_back(entry);
      }
      next = tbs_crl.get_next_object();
   }

   if(next.is_a(0, ASN1_Class::Constructed | ASN1_Class::ContextSpecific)) {
      BER_Decoder crl_options(next, tbs_crl.limits());
      crl_options.decode(data->m_extensions).verify_end();
      next = tbs_crl.get_next_object();
   }

   if(next.is_set()) {
      throw Decoding_Error("Unknown tag following extensions in CRL");
   }

   tbs_crl.verify_end();

   // Now cache some fields from the extensions
   if(const auto* ext = data->m_extensions.get_extension_object_as<Cert_Extension::CRL_Number>()) {
      data->m_crl_number = ext->get_crl_number();
   }
   if(const auto* ext = data->m_extensions.get_extension_object_as<Cert_Extension::Authority_Key_ID>()) {
      data->m_auth_key_id = ext->get_key_id();
   }
   if(const auto* ext = data->m_extensions.get_extension_object_as<Cert_Extension::CRL_Issuing_Distribution_Point>()) {
      for(const auto& uri : ext->get_point().uri_names()) {
         data->m_idp_urls.push_back(uri);
      }
   }

   data->update_index();

   return data;
}

}  // namespace

void X509_CRL::force_decode() {
   m_data.reset(decode_crl_body(signed_body(), signature_algorithm()).release());
}

const CRL_Data& X509_CRL::data() const {
   if(!m_data) {
      throw Invalid_State("X509_CRL uninitialized");
   }
   return *m_data;
}

const Extensions& X509_CRL::extensions() const {
   return data().m_extensions;
}

/*
* Return the list of revoked certificates
*/
const std::vector<CRL_Entry>& X509_CRL::get_revoked() const {
   return data().m_entries;
}

uint32_t X509_CRL::x509_version() const {
   return static_cast<uint32_t>(data().m_version);
}

/*
* Return the distinguished name of the issuer
*/
const X509_DN& X509_CRL::issuer_dn() const {
   return data().m_issuer;
}

/*
* Return the key identifier of the issuer
*/
const std::vector<uint8_t>& X509_CRL::authority_key_id() const {
   return data().m_auth_key_id;
}

/*
* Return the CRL number of this CRL
*/
uint32_t X509_CRL::crl_number() const {
   return static_cast<uint32_t>(data().m_crl_number);
}

/*
* Return the issue data of the CRL
*/
const X509_Time& X509_CRL::this_update() const {
   return data().m_this_update;
}

/*
* Return the date when a new CRL will be issued
*/
const X509_Time& X509_CRL::next_update() const {
   return data().m_next_update;
}

/*
* Return the CRL's distribution point
*/
std::string X509_CRL::crl_issuing_distribution_point() const {
   if(!data().m_idp_urls.empty()) {
      return data().m_idp_urls[0].original_input();
   }
   return "";
}

/*
* Return the CRL's issuing distribution point
*/
std::vector<std::string> X509_CRL::issuing_distribution_points() const {
   std::vector<std::string> out;
   out.reserve(data().m_idp_urls.size());
   for(const auto& uri : data().m_idp_urls) {
      out.push_back(uri.original_input());
   }
   return out;
}

const std::vector<URI>& X509_CRL::issuing_distribution_point_uris() const {
   return data().m_idp_urls;
}

namespace {

/*
* Compare two distribution point names for overlap, per RFC 5280 section 6.3.3
* step (b)(2). In practice CRLDP/IDP general names are either uniformResourceIdentifier
* or directoryName; the other GeneralName variants have no defined semantics for a
* distribution point (RFC 5280 4.2.1.13 and 5.2.5) so they are ignored here.
*/
bool dp_names_overlap(const AlternativeName& a, const AlternativeName& b) {
   auto has_common = [](const auto& s1, const auto& s2) {
      return std::ranges::any_of(s1, [&](const auto& e) { return s2.contains(e); });
   };

   return has_common(a.uri_names(), b.uri_names()) || has_common(a.directory_names(), b.directory_names());
}

}  // namespace

bool X509_CRL::has_matching_distribution_point(const X509_Certificate& cert) const {
   const auto* cdp_ext = cert.v3_extensions().get_extension_object_as<Cert_Extension::CRL_Distribution_Points>();
   if(cdp_ext == nullptr || cdp_ext->distribution_points().empty()) {
      return true;
   }

   const auto* idp_ext = this->extensions().get_extension_object_as<Cert_Extension::CRL_Issuing_Distribution_Point>();
   if(idp_ext == nullptr) {
      return false;
   }

   return std::ranges::any_of(cdp_ext->distribution_points(),
                              [&](const auto& dp) { return dp_names_overlap(dp.point(), idp_ext->get_point()); });
}

}  // namespace Botan
