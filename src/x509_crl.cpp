/*************************************************
* X.509 CRL Source File                          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/x509_crl.h>
#include <botan/parsing.h>
#include <botan/bigint.h>
#include <botan/conf.h>
#include <botan/oids.h>

namespace Botan {

/*************************************************
* Load a X.509 CRL                               *
*************************************************/
X509_CRL::X509_CRL(DataSource& in) : X509_Object(in, "X509 CRL/CRL")
   {
   version = crl_count = 0;

   do_decode();
   }

/*************************************************
* Load a X.509 CRL                               *
*************************************************/
X509_CRL::X509_CRL(const std::string& in) : X509_Object(in, "CRL/X509 CRL")
   {
   version = crl_count = 0;

   do_decode();
   }

/*************************************************
* Decode the TBSCertList data                    *
*************************************************/
void X509_CRL::force_decode()
   {
   BER_Decoder tbs_crl(tbs_bits);

   BER::decode_optional(tbs_crl, version, INTEGER, UNIVERSAL);

   if(version != 0 && version != 1)
      throw X509_CRL_Error("Unknown X.509 CRL version " +
                           to_string(version+1));

   AlgorithmIdentifier sig_algo_inner;
   BER::decode(tbs_crl, sig_algo_inner);

   if(sig_algo != sig_algo_inner)
      throw X509_CRL_Error("Algorithm identifier mismatch");

   BER::decode(tbs_crl, issuer);
   BER::decode(tbs_crl, start);
   BER::decode(tbs_crl, end);

   BER_Object next = tbs_crl.get_next_object();

   if(next.type_tag == SEQUENCE && next.class_tag == CONSTRUCTED)
      {
      BER_Decoder cert_list(next.value);

      while(cert_list.more_items())
         {
         CRL_Entry entry;
         BER::decode(cert_list, entry);
         revoked.push_back(entry);
         }
      next = tbs_crl.get_next_object();
      }

   if(next.type_tag == 0 &&
      next.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      {
      BER_Decoder crl_options(next.value);
      BER_Decoder sequence = BER::get_subsequence(crl_options);

      while(sequence.more_items())
         {
         Extension extn;
         BER::decode(sequence, extn);
         handle_crl_extension(extn);
         }
      next = tbs_crl.get_next_object();
      }

   if(next.type_tag != NO_OBJECT)
      throw X509_CRL_Error("Unknown tag in CRL");

   tbs_crl.verify_end();
   }

/*************************************************
* Decode a CRL extension                         *
*************************************************/
void X509_CRL::handle_crl_extension(const Extension& extn)
   {
   BER_Decoder value(extn.value);

   if(extn.oid == OIDS::lookup("X509v3.AuthorityKeyIdentifier"))
      {
      BER_Decoder key_id = BER::get_subsequence(value);
      BER::decode_optional_string(key_id, issuer_key_id, OCTET_STRING,
                                  ASN1_Tag(0), CONTEXT_SPECIFIC);
      }
   else if(extn.oid == OIDS::lookup("X509v3.CRLNumber"))
      value.decode(crl_count);
   else
      {
      if(extn.critical)
         {
         std::string action = Config::get_string("x509/crl/unknown_critical");
         if(action == "throw")
            throw X509_CRL_Error("Unknown critical CRL extension " +
                                 extn.oid.as_string());
         else if(action != "ignore")
            throw Invalid_Argument("Bad value of x509/crl/unknown_critical: "
                                   + action);
         }
      return;
      }

   value.verify_end();
   }

/*************************************************
* Return the list of revoked certificates        *
*************************************************/
std::vector<CRL_Entry> X509_CRL::get_revoked() const
   {
   return revoked;
   }

/*************************************************
* Return the distinguished name of the issuer    *
*************************************************/
X509_DN X509_CRL::issuer_dn() const
   {
   return issuer;
   }

/*************************************************
* Return the key identifier of the issuer        *
*************************************************/
MemoryVector<byte> X509_CRL::authority_key_id() const
   {
   return issuer_key_id;
   }

/*************************************************
* Return the CRL number of this CRL              *
*************************************************/
u32bit X509_CRL::crl_number() const
   {
   return crl_count;
   }

/*************************************************
* Return the issue data of the CRL               *
*************************************************/
X509_Time X509_CRL::this_update() const
   {
   return start;
   }

/*************************************************
* Return the date when a new CRL will be issued  *
*************************************************/
X509_Time X509_CRL::next_update() const
   {
   return end;
   }

}
