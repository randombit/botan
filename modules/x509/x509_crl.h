/*************************************************
* X.509 CRL Header File                          *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_X509_CRL_H__
#define BOTAN_X509_CRL_H__

#include <botan/x509_obj.h>
#include <botan/crl_ent.h>
#include <vector>

namespace Botan {

/*************************************************
* X.509 CRL                                      *
*************************************************/
class BOTAN_DLL X509_CRL : public X509_Object
   {
   public:
      struct X509_CRL_Error : public Exception
         {
         X509_CRL_Error(const std::string& error) :
            Exception("X509_CRL: " + error) {}
         };

      std::vector<CRL_Entry> get_revoked() const;

      X509_DN issuer_dn() const;
      MemoryVector<byte> authority_key_id() const;

      u32bit crl_number() const;
      X509_Time this_update() const;
      X509_Time next_update() const;

      X509_CRL(DataSource&);
      X509_CRL(const std::string&);
   private:
      void force_decode();
      std::vector<CRL_Entry> revoked;
      Data_Store info;
   };

}

#endif
