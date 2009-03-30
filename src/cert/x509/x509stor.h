/*
* X.509 Certificate Store
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_X509_CERT_STORE_H__
#define BOTAN_X509_CERT_STORE_H__

#include <botan/x509cert.h>
#include <botan/x509_crl.h>
#include <botan/certstor.h>

namespace Botan {

/*
* X.509 Certificate Validation Result
*/
enum X509_Code {
   VERIFIED,
   UNKNOWN_X509_ERROR,
   CANNOT_ESTABLISH_TRUST,
   CERT_CHAIN_TOO_LONG,
   SIGNATURE_ERROR,
   POLICY_ERROR,
   INVALID_USAGE,

   CERT_FORMAT_ERROR,
   CERT_ISSUER_NOT_FOUND,
   CERT_NOT_YET_VALID,
   CERT_HAS_EXPIRED,
   CERT_IS_REVOKED,

   CRL_FORMAT_ERROR,
   CRL_ISSUER_NOT_FOUND,
   CRL_NOT_YET_VALID,
   CRL_HAS_EXPIRED,

   CA_CERT_CANNOT_SIGN,
   CA_CERT_NOT_FOR_CERT_ISSUER,
   CA_CERT_NOT_FOR_CRL_ISSUER
};

/*
* X.509 Certificate Store
*/
class BOTAN_DLL X509_Store
   {
   public:
      class BOTAN_DLL Search_Func
         {
         public:
            virtual bool match(const X509_Certificate&) const = 0;
            virtual ~Search_Func() {}
         };

      enum Cert_Usage {
         ANY              = 0x00,
         TLS_SERVER       = 0x01,
         TLS_CLIENT       = 0x02,
         CODE_SIGNING     = 0x04,
         EMAIL_PROTECTION = 0x08,
         TIME_STAMPING    = 0x10,
         CRL_SIGNING      = 0x20
      };

      X509_Code validate_cert(const X509_Certificate&, Cert_Usage = ANY);

      std::vector<X509_Certificate> get_certs(const Search_Func&) const;
      std::vector<X509_Certificate> get_cert_chain(const X509_Certificate&);
      std::string PEM_encode() const;

      /*
      * Made CRL_Data public for XLC for Cell 0.9, otherwise cannot
      * instantiate member variable std::vector<CRL_Data> revoked
      */
      class BOTAN_DLL CRL_Data
         {
         public:
            X509_DN issuer;
            MemoryVector<byte> serial, auth_key_id;
            bool operator==(const CRL_Data&) const;
            bool operator!=(const CRL_Data&) const;
            bool operator<(const CRL_Data&) const;
         };

      X509_Code add_crl(const X509_CRL&);
      void add_cert(const X509_Certificate&, bool = false);
      void add_certs(DataSource&);
      void add_trusted_certs(DataSource&);

      void add_new_certstore(Certificate_Store*);

      static X509_Code check_sig(const X509_Object&, Public_Key*);

      X509_Store(u32bit time_slack = 24*60*60,
                 u32bit cache_results = 30*60);

      X509_Store(const X509_Store&);
      ~X509_Store();
   private:
      X509_Store& operator=(const X509_Store&) { return (*this); }

      class BOTAN_DLL Cert_Info
         {
         public:
            bool is_verified(u32bit timeout) const;
            bool is_trusted() const;
            X509_Code verify_result() const;
            void set_result(X509_Code) const;
            Cert_Info(const X509_Certificate&, bool = false);

            X509_Certificate cert;
            bool trusted;
         private:
            mutable bool checked;
            mutable X509_Code result;
            mutable u64bit last_checked;
         };

      u32bit find_cert(const X509_DN&, const MemoryRegion<byte>&) const;
      X509_Code check_sig(const Cert_Info&, const Cert_Info&) const;
      void recompute_revoked_info() const;

      void do_add_certs(DataSource&, bool);
      X509_Code construct_cert_chain(const X509_Certificate&,
                                     std::vector<u32bit>&, bool = false);

      u32bit find_parent_of(const X509_Certificate&);
      bool is_revoked(const X509_Certificate&) const;

      static const u32bit NO_CERT_FOUND = 0xFFFFFFFF;
      std::vector<Cert_Info> certs;
      std::vector<CRL_Data> revoked;
      std::vector<Certificate_Store*> stores;
      u32bit time_slack, validation_cache_timeout;
      mutable bool revoked_info_valid;
   };

}

#endif
