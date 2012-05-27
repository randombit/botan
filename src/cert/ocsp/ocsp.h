/*
* OCSP
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_OCSP_H__
#define BOTAN_OCSP_H__

#include <botan/ocsp_types.h>

namespace Botan {

namespace OCSP {

class BOTAN_DLL Request
   {
   public:
      Request(const X509_Certificate& issuer_cert,
              const X509_Certificate& subject_cert) :
         m_issuer(issuer_cert),
         m_subject(subject_cert)
         {}

      std::vector<byte> BER_encode() const;

      std::string base64_encode() const;
   private:
      X509_Certificate m_issuer, m_subject;
   };

class BOTAN_DLL Response
   {
   public:
      Response(const std::vector<byte>& response);
   };

}

}

#endif
