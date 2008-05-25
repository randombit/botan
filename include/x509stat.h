/*************************************************
* Globally Saved X.509 State Header              *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/asn1_oid.h>
#include <botan/freestore.h>

namespace Botan {

/*************************************************
* Prototype for a Certificate Extension          *
*************************************************/
class Extension_Prototype
   {
   public:
      virtual std::tr1::shared_ptr<class Certificate_Extension> make(const OID&) = 0;
      virtual ~Extension_Prototype() {}
   };

/*************************************************
* X.509 Global State                             *
*************************************************/
class X509_GlobalState
   {
   public:
      void add(SharedPtrConverter<Extension_Prototype>);
      std::tr1::shared_ptr<class Certificate_Extension> get_extension(const OID&) const;

      X509_GlobalState();
      ~X509_GlobalState();
   private:
      std::vector<std::tr1::shared_ptr<Extension_Prototype> > prototypes;
   };

}
