/*************************************************
* X.509 CRL Source File                          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/x509_crl.h>
#include <botan/ber_dec.h>
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
   do_decode();
   }

/*************************************************
* Load a X.509 CRL                               *
*************************************************/
X509_CRL::X509_CRL(const std::string& in) : X509_Object(in, "CRL/X509 CRL")
   {
   do_decode();
   }

/*************************************************
* Decode the TBSCertList data                    *
*************************************************/
void X509_CRL::force_decode()
   {
   BER_Decoder tbs_crl(tbs_bits);

   u32bit version;
   tbs_crl.decode_optional(version, INTEGER, UNIVERSAL);

   if(version != 0 && version != 1)
      throw X509_CRL_Error("Unknown X.509 CRL version " +
                           to_string(version+1));

   AlgorithmIdentifier sig_algo_inner;
   tbs_crl.decode(sig_algo_inner);

   if(sig_algo != sig_algo_inner)
      throw X509_CRL_Error("Algorithm identifier mismatch");

   X509_DN dn_issuer;
   X509_Time start, end;

   tbs_crl.decode(dn_issuer);
   tbs_crl.decode(start);
   tbs_crl.decode(end);

   info.add(dn_issuer.contents());
   info.add("X509.CRL.start", start.readable_string());
   info.add("X509.CRL.end", end.readable_string());

   BER_Object next = tbs_crl.get_next_object();

   if(next.type_tag == SEQUENCE && next.class_tag == CONSTRUCTED)
      {
      BER_Decoder cert_list(next.value);

      while(cert_list.more_items())
         {
         CRL_Entry entry;
         cert_list.decode(entry);
         revoked.push_back(entry);
         }
      next = tbs_crl.get_next_object();
      }

   if(next.type_tag == 0 &&
      next.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      {
      BER_Decoder crl_options(next.value);
      BER_Decoder sequence = crl_options.start_cons(SEQUENCE);

      while(sequence.more_items())
         {
         Extension extn;
         sequence.decode(extn);
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
      MemoryVector<byte> v3_issuer_key_id;
      BER_Decoder key_id = value.start_cons(SEQUENCE);
      key_id.decode_optional_string(v3_issuer_key_id, OCTET_STRING, 0);
      info.add("X509v3.AuthorityKeyIdentifier", v3_issuer_key_id);
      }
   else if(extn.oid == OIDS::lookup("X509v3.CRLNumber"))
      {
      u32bit crl_count = 0;
      value.decode(crl_count);
      info.add("X509v3.CRLNumber", crl_count);
      }
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
   return create_dn(info);
   }

/*************************************************
* Return the key identifier of the issuer        *
*************************************************/
MemoryVector<byte> X509_CRL::authority_key_id() const
   {
   return info.get1_memvec("X509v3.AuthorityKeyIdentifier");
   }

/*************************************************
* Return the CRL number of this CRL              *
*************************************************/
u32bit X509_CRL::crl_number() const
   {
   return info.get1_memvec("X509v3.CRLNumber");
   }

/*************************************************
* Return the issue data of the CRL               *
*************************************************/
X509_Time X509_CRL::this_update() const
   {
   return info.get1("X509.CRL.start");
   }

/*************************************************
* Return the date when a new CRL will be issued  *
*************************************************/
X509_Time X509_CRL::next_update() const
   {
   return info.get1("X509.CRL.end");
   }

}
