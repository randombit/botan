/*************************************************
* PKCS #10 Header File                           *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_PKCS10_H__
#define BOTAN_PKCS10_H__

#include <botan/x509_obj.h>
#include <botan/pkcs8.h>
#include <vector>

namespace Botan {

/*************************************************
* PKCS #10 Certificate Request                   *
*************************************************/
class PKCS10_Request : public X509_Object
   {
   public:
      X509_PublicKey* subject_public_key() const;

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
      void handle_v3_extension(const Extension&);

      MemoryVector<byte> pub_key;
      X509_DN dn;
      AlternativeName subject_alt;
      std::string challenge;
      Key_Constraints constraints_value;
      std::vector<OID> ex_constraints_list;
      bool is_ca;
      u32bit max_path_len;
   };

}

#endif
