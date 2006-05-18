/*************************************************
* X.509 Certificates Header File                 *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_X509_CERTS_H__
#define BOTAN_X509_CERTS_H__

#include <botan/x509_obj.h>
#include <botan/x509_key.h>
#include <botan/datastor.h>
#include <map>

namespace Botan {

static const u32bit NO_CERT_PATH_LIMIT = 0xFFFFFFFF;

/*************************************************
* X.509 Certificate                              *
*************************************************/
class X509_Certificate : public X509_Object
   {
   public:
      X509_PublicKey* subject_public_key() const;

      u32bit x509_version() const;
      MemoryVector<byte> serial_number() const;
      MemoryVector<byte> authority_key_id() const;
      MemoryVector<byte> subject_key_id() const;
      Key_Constraints constraints() const;

      std::string start_time() const;
      std::string end_time() const;

      std::string subject_info(const std::string&) const;
      std::string issuer_info(const std::string&) const;
      X509_DN issuer_dn() const;
      X509_DN subject_dn() const;

      bool self_signed() const;
      bool is_CA_cert() const;

      u32bit path_limit() const;
      std::vector<std::string> ex_constraints() const;
      std::vector<std::string> policies() const;

      bool operator==(const X509_Certificate&) const;

      void force_decode();

      X509_Certificate(DataSource&);
      X509_Certificate(const std::string&);
   private:
      friend class X509_CA;
      X509_Certificate() {}
      void handle_v3_extension(const Extension&);

      Data_Store info;
      std::multimap<std::string, std::string> subject, issuer;
      bool is_ca;
   };

/*************************************************
* X.509 Certificate Comparison                   *
*************************************************/
bool operator!=(const X509_Certificate&, const X509_Certificate&);

}

#endif
