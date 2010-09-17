/*
* Certificate Store
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CERT_STORE_H__
#define BOTAN_CERT_STORE_H__

#include <botan/x509cert.h>
#include <botan/x509_crl.h>

namespace Botan {

/**
* Certificate Store Interface
*/
class BOTAN_DLL Certificate_Store
   {
   public:
      virtual ~Certificate_Store() {}

      virtual Certificate_Store* clone() const = 0;

      /**
      * Add a certificate
      */
      virtual void add_certificate(const X509_Certificate& cert) = 0;

      /**
      * Subject DN and (optionally) key identifier
      */
      virtual std::vector<X509_Certificate>
         find_by_subject_and_key_id(
            const X509_DN& subject_dn,
            const MemoryRegion<byte>& key_id) = 0;
   };

class BOTAN_DLL Certificate_Store_Memory : public Certificate_Store
   {
   public:
      Certificate_Store* clone() const;

      void add_certificate(const X509_Certificate& cert);

      std::vector<X509_Certificate> find_by_subject_and_key_id(
         const X509_DN& subject_dn,
         const MemoryRegion<byte>& key_id);

      Certificate_Store_Memory() {}
   private:
      // TODO: Add indexing on the DN and key id to avoid linear search?
      std::vector<X509_Certificate> certs;
   };

// TODO: file-backed store

}

#endif
