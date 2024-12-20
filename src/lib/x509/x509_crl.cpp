/*
* X.509 CRL
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_crl.h>

#include <botan/ber_dec.h>
#include <botan/x509_ext.h>
#include <botan/x509cert.h>

#include <sstream>

namespace Botan {

struct CRL_Data {
      X509_DN m_issuer;
      size_t m_version;
      X509_Time m_this_update;
      X509_Time m_next_update;
      std::vector<CRL_Entry> m_entries;
      Extensions m_extensions;

      // cached values from extensions
      size_t m_crl_number = 0;
      std::vector<uint8_t> m_auth_key_id;
      std::vector<std::string> m_idp_urls;
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
                   const std::vector<CRL_Entry>& revoked) :
      X509_Object() {
   m_data = std::make_shared<CRL_Data>();
   m_data->m_issuer = issuer;
   m_data->m_this_update = this_update;
   m_data->m_next_update = next_update;
   m_data->m_entries = revoked;
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

   std::vector<uint8_t> crl_akid = authority_key_id();
   const std::vector<uint8_t>& cert_akid = cert.authority_key_id();

   if(!crl_akid.empty() && !cert_akid.empty()) {
      if(crl_akid != cert_akid) {
         return false;
      }
   }

   const std::vector<uint8_t>& cert_serial = cert.serial_number();

   bool is_revoked = false;

   // FIXME would be nice to avoid a linear scan here - maybe sort the entries?
   for(const CRL_Entry& entry : get_revoked()) {
      if(cert_serial == entry.serial_number()) {
         if(entry.reason_code() == CRL_Code::RemoveFromCrl) {
            is_revoked = false;
         } else {
            is_revoked = true;
         }
      }
   }

   return is_revoked;
}

/*
* Decode the TBSCertList data
*/
namespace {

std::unique_ptr<CRL_Data> decode_crl_body(const std::vector<uint8_t>& body, const AlgorithmIdentifier& sig_algo) {
   auto data = std::make_unique<CRL_Data>();

   BER_Decoder tbs_crl(body);

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

   tbs_crl.decode(data->m_issuer).decode(data->m_this_update).decode(data->m_next_update);

   BER_Object next = tbs_crl.get_next_object();

   if(next.is_a(ASN1_Type::Sequence, ASN1_Class::Constructed)) {
      BER_Decoder cert_list(std::move(next));

      while(cert_list.more_items()) {
         CRL_Entry entry;
         cert_list.decode(entry);
         data->m_entries.push_back(entry);
      }
      next = tbs_crl.get_next_object();
   }

   if(next.is_a(0, ASN1_Class::Constructed | ASN1_Class::ContextSpecific)) {
      BER_Decoder crl_options(std::move(next));
      crl_options.decode(data->m_extensions).verify_end();
      next = tbs_crl.get_next_object();
   }

   if(next.is_set()) {
      throw Decoding_Error("Unknown tag following extensions in CRL");
   }

   tbs_crl.verify_end();

   // Now cache some fields from the extensions
   if(auto ext = data->m_extensions.get_extension_object_as<Cert_Extension::CRL_Number>()) {
      data->m_crl_number = ext->get_crl_number();
   }
   if(auto ext = data->m_extensions.get_extension_object_as<Cert_Extension::Authority_Key_ID>()) {
      data->m_auth_key_id = ext->get_key_id();
   }
   if(auto ext = data->m_extensions.get_extension_object_as<Cert_Extension::CRL_Issuing_Distribution_Point>()) {
      data->m_idp_urls = ext->get_point().get_attribute("URL");
   }

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
      return data().m_idp_urls[0];
   }
   return "";
}

/*
* Return the CRL's issuing distribution point
*/
std::vector<std::string> X509_CRL::issuing_distribution_points() const {
   return data().m_idp_urls;
}

}  // namespace Botan
