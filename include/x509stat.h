/*************************************************
* Globally Saved X.509 State Header              *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/asn1_oid.h>

namespace Botan {

/*************************************************
* Prototype for a Certificate Extension          *
*************************************************/
class Extension_Prototype
   {
   public:
      virtual class Certificate_Extension* make(const OID&) = 0;
      virtual ~Extension_Prototype() {}
   };

/*************************************************
* X.509 Global State                             *
*************************************************/
class X509_GlobalState
   {
   public:
      void add(Extension_Prototype*);
      class Certificate_Extension* get_extension(const OID&) const;

      X509_GlobalState();
      ~X509_GlobalState();
   private:
      std::vector<Extension_Prototype*> prototypes;
   };

}
