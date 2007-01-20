/*************************************************
* X.509 Certificates Header File                 *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_X509_CERTS_H__
#define BOTAN_X509_CERTS_H__

#include <botan/x509_obj.h>
#include <botan/x509_key.h>
#include <botan/datastor.h>
#include <botan/enums.h>
#include <map>

namespace Botan {

/*************************************************
* X.509 Certificate                              *
*************************************************/
class X509_Certificate : public X509_Object
   {
   public:
      Public_Key* subject_public_key() const;

      X509_DN issuer_dn() const;
      X509_DN subject_dn() const;
      std::vector<std::string> subject_info(const std::string&) const;
      std::vector<std::string> issuer_info(const std::string&) const;

      std::string start_time() const;
      std::string end_time() const;

      u32bit x509_version() const;
      MemoryVector<byte> serial_number() const;

      MemoryVector<byte> authority_key_id() const;
      MemoryVector<byte> subject_key_id() const;
      bool is_self_signed() const { return self_signed; }
      bool is_CA_cert() const;

      u32bit path_limit() const;
      Key_Constraints constraints() const;
      std::vector<std::string> ex_constraints() const;
      std::vector<std::string> policies() const;

      bool operator==(const X509_Certificate&) const;

      X509_Certificate(DataSource&);
      X509_Certificate(const std::string&);
   private:
      void force_decode();
      friend class X509_CA;
      X509_Certificate() {}

      Data_Store subject, issuer;
      bool self_signed;
   };

/*************************************************
* X.509 Certificate Comparison                   *
*************************************************/
bool operator!=(const X509_Certificate&, const X509_Certificate&);

/*************************************************
* Data Store Extraction Operations               *
*************************************************/
X509_DN create_dn(const Data_Store&);
AlternativeName create_alt_name(const Data_Store&);

}

#endif
