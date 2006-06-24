/*************************************************
* Globally Saved X.509 State                     *
* (C) 1999-2006 The Botan Project                *
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
#define CREATE_PROTOTYPE(TYPE, NAME)                      \
   struct TYPE ## _Prototype : public Extension_Prototype \
      {                                                   \
      Certificate_Extension* make(const OID& oid)         \
         {                                                \
         if(oid == OIDS::lookup(NAME))                    \
            return new Cert_Extension::TYPE();            \
         return 0;                                        \
         }                                                \
      };                                                  \
   add(new TYPE ## _Prototype);

#if 0
   class Basic_Constraints_Prototype : public Extension_Prototype
      {
      public:
         Certificate_Extension* make(const OID& oid)
            {
            if(oid == OIDS::lookup("X509v3.BasicConstraints"))
               return new Cert_Extension::Basic_Constraints();
            return 0;
            }
      };

   add(new Basic_Constraints_Prototype);
#else

   CREATE_PROTOTYPE(Basic_Constraints, "X509v3.BasicConstraints");

#endif
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
