/*************************************************
* PKCS #10 Header File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_PKCS10_H__
#define BOTAN_PKCS10_H__

#include <botan/x509_obj.h>
#include <botan/pkcs8.h>
#include <botan/datastor.h>
#include <vector>

namespace Botan {

/*************************************************
* PKCS #10 Certificate Request                   *
*************************************************/
class BOTAN_DLL PKCS10_Request : public X509_Object
   {
   public:
      Public_Key* subject_public_key() const;

      MemoryVector<byte> raw_public_key() const;
      X509_DN subject_dn() const;
      AlternativeName subject_alt_name() const;
      Key_Constraints constraints() const;
      std::vector<OID> ex_constraints() const;

      bool is_CA() const;
      u32bit path_limit() const;

      std::string challenge_password() const;

      PKCS10_Request(DataSource&);
      PKCS10_Request(const std::string&);
   private:
      void force_decode();
      void handle_attribute(const Attribute&);

      Data_Store info;
   };

}

#endif
