/*
* Certificate Store
* (C) 1999-2010 Jack Lloyd
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

      /**
      * Add a certificate; this may fail if the store is write-only
      */
      virtual void add_certificate(const X509_Certificate& cert) = 0;

      /**
      * Add a CRL; this may fail if the store is write-only
      */
      virtual void add_crl(const X509_CRL& crl) = 0;

      bool certificate_known(const X509_Certificate& cert) const;

      virtual std::vector<X509_DN> all_subjects() const = 0;

      /**
      * Subject DN and (optionally) key identifier
      */
      virtual std::vector<X509_Certificate>
         find_cert_by_subject_and_key_id(
            const X509_DN& subject_dn,
            const std::vector<byte>& key_id) const = 0;

      /**
      * Find CRLs by the DN and key id of the issuer
      */
      virtual std::vector<X509_CRL>
         find_crl_by_issuer_and_key_id(
            const X509_DN& issuer_dn,
            const std::vector<byte>& key_id) const = 0;
   };

/**
* In Memory Certificate Store
*/
class BOTAN_DLL Certificate_Store_In_Memory : public Certificate_Store
   {
   public:
      Certificate_Store_In_Memory() {}

      void add_certificate(const X509_Certificate& cert) override;

      void add_crl(const X509_CRL& crl) override;

      std::vector<X509_DN> all_subjects() const override;

      std::vector<X509_Certificate> find_cert_by_subject_and_key_id(
         const X509_DN& subject_dn,
         const std::vector<byte>& key_id) const override;

      std::vector<X509_CRL> find_crl_by_issuer_and_key_id(
         const X509_DN& issuer_dn,
         const std::vector<byte>& key_id) const override;
   private:
      // TODO: Add indexing on the DN and key id to avoid linear search
      std::vector<X509_Certificate> m_certs;
      std::vector<X509_CRL> m_crls;
   };

// TODO: file backed store
// TODO: directory backed store (eg /usr/share/ca-certificates)
// TODO: sqlite3 backed store

}

#endif
