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
#include <botan/parsing.h>
#include <botan/bigint.h>
#include <botan/oids.h>

namespace Botan {

/*
* Load a X.509 CRL
*/
X509_CRL::X509_CRL(DataSource& in, bool touc) :
   X509_Object(in, "X509 CRL/CRL"), m_throw_on_unknown_critical(touc)
   {
   do_decode();
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
/*
* Load a X.509 CRL
*/
X509_CRL::X509_CRL(const std::string& fsname, bool touc) :
   X509_Object(fsname, "CRL/X509 CRL"), m_throw_on_unknown_critical(touc)
   {
   do_decode();
   }
#endif

X509_CRL::X509_CRL(const std::vector<byte>& in, bool touc) :
   X509_Object(in, "CRL/X509 CRL"), m_throw_on_unknown_critical(touc)
   {
   do_decode();
   }

X509_CRL::X509_CRL(const X509_DN& issuer, const X509_Time& thisUpdate,
                   const X509_Time& nextUpdate, const std::vector<CRL_Entry>& revoked) :
   X509_Object(), m_throw_on_unknown_critical(false), m_revoked(revoked)
   {
   m_info.add(issuer.contents());
   m_info.add("X509.CRL.start", thisUpdate.to_string());
   m_info.add("X509.CRL.end", nextUpdate.to_string());
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

   std::vector<byte> crl_akid = authority_key_id();
   std::vector<byte> cert_akid = cert.authority_key_id();

   if(!crl_akid.empty() && !cert_akid.empty())
      if(crl_akid != cert_akid)
         return false;

   std::vector<byte> cert_serial = cert.serial_number();

   bool is_revoked = false;

   for(size_t i = 0; i != m_revoked.size(); ++i)
      {
      if(cert_serial == m_revoked[i].serial_number())
         {
         if(m_revoked[i].reason_code() == REMOVE_FROM_CRL)
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
void X509_CRL::force_decode()
   {
   BER_Decoder tbs_crl(m_tbs_bits);

   size_t version;
   tbs_crl.decode_optional(version, INTEGER, UNIVERSAL);

   if(version != 0 && version != 1)
      throw X509_CRL_Error("Unknown X.509 CRL version " +
                           std::to_string(version+1));

   AlgorithmIdentifier sig_algo_inner;
   tbs_crl.decode(sig_algo_inner);

   if(m_sig_algo != sig_algo_inner)
      throw X509_CRL_Error("Algorithm identifier mismatch");

   X509_DN dn_issuer;
   tbs_crl.decode(dn_issuer);
   m_info.add(dn_issuer.contents());

   X509_Time start, end;
   tbs_crl.decode(start).decode(end);
   m_info.add("X509.CRL.start", start.to_string());
   m_info.add("X509.CRL.end", end.to_string());

   BER_Object next = tbs_crl.get_next_object();

   if(next.type_tag == SEQUENCE && next.class_tag == CONSTRUCTED)
      {
      BER_Decoder cert_list(next.value);

      while(cert_list.more_items())
         {
         CRL_Entry entry(m_throw_on_unknown_critical);
         cert_list.decode(entry);
         m_revoked.push_back(entry);
         }
      next = tbs_crl.get_next_object();
      }

   if(next.type_tag == 0 &&
      next.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      {
      BER_Decoder crl_options(next.value);

      Extensions extensions(m_throw_on_unknown_critical);

      crl_options.decode(extensions).verify_end();

      extensions.contents_to(m_info, m_info);

      next = tbs_crl.get_next_object();
      }

   if(next.type_tag != NO_OBJECT)
      throw X509_CRL_Error("Unknown tag in CRL");

   tbs_crl.verify_end();
   }

/*
* Return the list of revoked certificates
*/
std::vector<CRL_Entry> X509_CRL::get_revoked() const
   {
   return m_revoked;
   }

/*
* Return the distinguished name of the issuer
*/
X509_DN X509_CRL::issuer_dn() const
   {
   return create_dn(m_info);
   }

/*
* Return the key identifier of the issuer
*/
std::vector<byte> X509_CRL::authority_key_id() const
   {
   return m_info.get1_memvec("X509v3.AuthorityKeyIdentifier");
   }

/*
* Return the CRL number of this CRL
*/
u32bit X509_CRL::crl_number() const
   {
   return m_info.get1_u32bit("X509v3.CRLNumber");
   }

/*
* Return the issue data of the CRL
*/
X509_Time X509_CRL::this_update() const
   {
   return X509_Time(m_info.get1("X509.CRL.start"), ASN1_Tag::UTC_OR_GENERALIZED_TIME);
   }

/*
* Return the date when a new CRL will be issued
*/
X509_Time X509_CRL::next_update() const
   {
   return X509_Time(m_info.get1("X509.CRL.end"), ASN1_Tag::UTC_OR_GENERALIZED_TIME);
   }

}
