/*************************************************
* Globally Saved X.509 State Source              *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/x509stat.h>
#include <botan/x509_ext.h>
#include <botan/oids.h>

namespace Botan {

/*************************************************
* Add a new prototype                            *
*************************************************/
void X509_GlobalState::add(Extension_Prototype* proto)
   {
   if(proto)
      prototypes.push_back(proto);
   }

/*************************************************
* Get an extension object                        *
*************************************************/
Certificate_Extension* X509_GlobalState::get_extension(const OID& oid) const
   {
   Certificate_Extension* extension = 0;
   for(u32bit j = 0; j != prototypes.size() && !extension; ++j)
      extension = prototypes[j]->make(oid);
   return extension;
   }

/*************************************************
* Set up a new global state for X.509            *
*************************************************/
X509_GlobalState::X509_GlobalState()
   {

#define CREATE_PROTOTYPE(NAME, TYPE)                         \
   do {                                                      \
      struct TYPE ## _Prototype : public Extension_Prototype \
         {                                                   \
         Certificate_Extension* make(const OID& oid)         \
            {                                                \
            if(Botan::OIDS::name_of(oid, NAME))              \
               return new Botan::Cert_Extension::TYPE();     \
            return 0;                                        \
            }                                                \
         };                                                  \
                                                             \
      add(new TYPE ## _Prototype);                           \
   } while(0);

   CREATE_PROTOTYPE("X509v3.KeyUsage", Key_Usage);
   CREATE_PROTOTYPE("X509v3.BasicConstraints", Basic_Constraints);
   CREATE_PROTOTYPE("X509v3.SubjectKeyIdentifier", Subject_Key_ID);
   CREATE_PROTOTYPE("X509v3.AuthorityKeyIdentifier", Authority_Key_ID);
   CREATE_PROTOTYPE("X509v3.ExtendedKeyUsage", Extended_Key_Usage);
   CREATE_PROTOTYPE("X509v3.IssuerAlternativeName", Issuer_Alternative_Name);
   CREATE_PROTOTYPE("X509v3.SubjectAlternativeName", Subject_Alternative_Name);
   CREATE_PROTOTYPE("X509v3.CRLNumber", CRL_Number);
   CREATE_PROTOTYPE("X509v3.CertificatePolicies", Certificate_Policies);

#undef CREATE_PROTOTYPE
   }

/*************************************************
* Destroy this global state object               *
*************************************************/
X509_GlobalState::~X509_GlobalState()
   {
   for(u32bit j = 0; j != prototypes.size(); ++j)
      delete prototypes[j];
   prototypes.clear();
   }

}
