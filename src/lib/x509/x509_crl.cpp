/*
* X.509 CRL
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_crl.h>
#include <botan/x509_ext.h>
#include <botan/x509cert.h>
#include <botan/ber_dec.h>

namespace Botan {

struct CRL_Data
   {
   X509_DN m_issuer;
   X509_Time m_this_update;
   X509_Time m_next_update;
   std::vector<CRL_Entry> m_entries;
   Extensions m_extensions;

   // cached values from extensions
   size_t m_crl_number = 0;
   std::vector<uint8_t> m_auth_key_id;
   };

/*
* Load a X.509 CRL
*/
X509_CRL::X509_CRL(DataSource& in) :
   X509_Object(in, "X509 CRL/CRL")
   {
   do_decode();
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
/*
* Load a X.509 CRL
*/
X509_CRL::X509_CRL(const std::string& fsname) :
   X509_Object(fsname, "CRL/X509 CRL")
   {
   do_decode();
   }
#endif

X509_CRL::X509_CRL(const std::vector<uint8_t>& in) :
   X509_Object(in, "CRL/X509 CRL")
   {
   do_decode();
   }

X509_CRL::X509_CRL(const X509_DN& issuer,
                   const X509_Time& this_update,
                   const X509_Time& next_update,
                   const std::vector<CRL_Entry>& revoked) :
   X509_Object()
   {
   m_data.reset(new CRL_Data);
   m_data->m_issuer = issuer;
   m_data->m_this_update = this_update;
   m_data->m_next_update = next_update;
   m_data->m_entries = revoked;
   }

/**
* Check if this particular certificate is listed in the CRL
*/
bool X509_CRL::is_revoked(const X509_Certificate& cert) const
   {
   /*
   If the cert wasn't issued by the CRL issuer, it's possible the cert
   is revoked, but not by this CRL. Maybe throw an exception instead?
   */
   if(cert.issuer_dn() != issuer_dn())
      return false;

   std::vector<uint8_t> crl_akid = authority_key_id();
   std::vector<uint8_t> cert_akid = cert.authority_key_id();

   if(!crl_akid.empty() && !cert_akid.empty())
      {
      if(crl_akid != cert_akid)
         return false;
      }

   std::vector<uint8_t> cert_serial = cert.serial_number();

   bool is_revoked = false;

   // FIXME would be nice to avoid a linear scan here - maybe sort the entries?
   for(const CRL_Entry& entry : get_revoked())
      {
      if(cert_serial == entry.serial_number())
         {
         if(entry.reason_code() == REMOVE_FROM_CRL)
            is_revoked = false;
         else
            is_revoked = true;
         }
      }

   return is_revoked;
   }

/*
* Decode the TBSCertList data
*/
namespace {

std::unique_ptr<CRL_Data> decode_crl_body(const std::vector<uint8_t>& body,
                                          const AlgorithmIdentifier& sig_algo)
   {
   std::unique_ptr<CRL_Data> data(new CRL_Data);

   BER_Decoder tbs_crl(body);

   size_t version;
   tbs_crl.decode_optional(version, INTEGER, UNIVERSAL);

   if(version != 0 && version != 1)
      throw X509_CRL::X509_CRL_Error("Unknown X.509 CRL version " +
                           std::to_string(version+1));

   AlgorithmIdentifier sig_algo_inner;
   tbs_crl.decode(sig_algo_inner);

   if(sig_algo != sig_algo_inner)
      throw X509_CRL::X509_CRL_Error("Algorithm identifier mismatch");

   tbs_crl.decode(data->m_issuer)
      .decode(data->m_this_update)
      .decode(data->m_next_update);

   BER_Object next = tbs_crl.get_next_object();

   if(next.type_tag == SEQUENCE && next.class_tag == CONSTRUCTED)
      {
      BER_Decoder cert_list(next.value);

      while(cert_list.more_items())
         {
         CRL_Entry entry;
         cert_list.decode(entry);
         data->m_entries.push_back(entry);
         }
      next = tbs_crl.get_next_object();
      }

   if(next.type_tag == 0 &&
      next.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      {
      BER_Decoder crl_options(next.value);
      crl_options.decode(data->m_extensions).verify_end();
      next = tbs_crl.get_next_object();
      }

   if(next.type_tag != NO_OBJECT)
      throw X509_CRL::X509_CRL_Error("Unknown tag in CRL");

   tbs_crl.verify_end();

   return data;
   }

}

void X509_CRL::force_decode()
   {
   m_data.reset(decode_crl_body(signed_body(), signature_algorithm()).release());
   }

const CRL_Data& X509_CRL::data() const
   {
   if(!m_data)
      throw Decoding_Error("Error decoding X509 CRL");
   return *m_data.get();
   }

const Extensions& X509_CRL::extensions() const
   {
   return data().m_extensions;
   }

/*
* Return the list of revoked certificates
*/
const std::vector<CRL_Entry>& X509_CRL::get_revoked() const
   {
   return data().m_entries;
   }

/*
* Return the distinguished name of the issuer
*/
const X509_DN& X509_CRL::issuer_dn() const
   {
   return data().m_issuer;
   }

/*
* Return the key identifier of the issuer
*/
const std::vector<uint8_t>& X509_CRL::authority_key_id() const
   {
   return data().m_auth_key_id;
   }

/*
* Return the CRL number of this CRL
*/
uint32_t X509_CRL::crl_number() const
   {
   return data().m_crl_number;
   }

/*
* Return the issue data of the CRL
*/
const X509_Time& X509_CRL::this_update() const
   {
   return data().m_this_update;
   }

/*
* Return the date when a new CRL will be issued
*/
const X509_Time& X509_CRL::next_update() const
   {
   return data().m_next_update;
   }

}
