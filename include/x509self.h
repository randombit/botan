/*************************************************
* X.509 Self-Signed Certificate Header File      *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_X509_SELF_H__
#define BOTAN_X509_SELF_H__

#include <botan/x509cert.h>
#include <botan/pkcs8.h>
#include <botan/pkcs10.h>

namespace Botan {

/*************************************************
* Options for X.509 Certificates                 *
*************************************************/
class X509_Cert_Options
   {
   public:
      std::string common_name;
      std::string country;
      std::string organization;
      std::string org_unit;
      std::string locality;
      std::string state;
      std::string serial_number;

      std::string email, uri, dns, ip, xmpp;

      std::string challenge;

      X509_Time start, end;

      bool is_CA;
      u32bit path_limit;
      Key_Constraints constraints;
      std::vector<OID> ex_constraints;

      void sanity_check() const;

      void CA_key(u32bit = 8);
      void not_before(const std::string&);
      void not_after(const std::string&);

      void add_constraints(Key_Constraints);
      void add_ex_constraint(const OID&);
      void add_ex_constraint(const std::string&);

      X509_Cert_Options(const std::string& = "");
   };

namespace X509 {

/*************************************************
* Create a self-signed X.509 certificate         *
*************************************************/
X509_Certificate create_self_signed_cert(const X509_Cert_Options&,
                                         const Private_Key&);

/*************************************************
* Create a PKCS #10 certificate request          *
*************************************************/
PKCS10_Request create_cert_req(const X509_Cert_Options&,
                               const Private_Key&);

}

}

#endif
