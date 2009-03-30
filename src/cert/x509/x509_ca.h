/*
* X.509 Certificate Authority
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_X509_CA_H__
#define BOTAN_X509_CA_H__

#include <botan/x509cert.h>
#include <botan/x509_crl.h>
#include <botan/x509_ext.h>
#include <botan/pkcs8.h>
#include <botan/pkcs10.h>
#include <botan/pubkey.h>

namespace Botan {

/**
* This class represents X.509 Certificate Authorities (CAs).
*/
class BOTAN_DLL X509_CA
   {
   public:

      /**
      * Sign a PKCS#10 Request.
      * @param req the request to sign
      * @param rng the rng to use
      * @param not_before the starting time for the certificate
      * @param not_after the expiration time for the certificate
      * @return the resulting certificate
      */
      X509_Certificate sign_request(const PKCS10_Request& req,
                                    RandomNumberGenerator& rng,
                                    const X509_Time& not_before,
                                    const X509_Time& not_after);

      /**
      * Get the certificate of this CA.
      * @return the CA certificate
      */
      X509_Certificate ca_certificate() const;

      /**
      * Create a new and empty CRL for this CA.
      * @param rng the random number generator to use
      * @param next_update the time to set in next update in seconds
      * as the offset from the current time
      * @return the new CRL
      */
      X509_CRL new_crl(RandomNumberGenerator& rng, u32bit = 0) const;

      /**
      * Create a new CRL by with additional entries.
      * @param last_crl the last CRL of this CA to add the new entries to
      * @param new_entries contains the new CRL entries to be added to the CRL
      * @param rng the random number generator to use
      * @param next_update the time to set in next update in seconds
      * as the offset from the current time
      */
      X509_CRL update_crl(const X509_CRL& last_crl,
                          const std::vector<CRL_Entry>& new_entries,
                          RandomNumberGenerator& rng,
                          u32bit next_update = 0) const;

      static X509_Certificate make_cert(PK_Signer*,
                                        RandomNumberGenerator&,
                                        const AlgorithmIdentifier&,
                                        const MemoryRegion<byte>&,
                                        const X509_Time&, const X509_Time&,
                                        const X509_DN&, const X509_DN&,
                                        const Extensions&);

      /**
      * Create a new CA object.
      * @param ca_certificate the certificate of the CA
      * @param key the private key of the CA
      */
      X509_CA(const X509_Certificate& ca_certificate, const Private_Key& key);
      ~X509_CA();
   private:
      X509_CA(const X509_CA&) {}
      X509_CA& operator=(const X509_CA&) { return (*this); }

      X509_CRL make_crl(const std::vector<CRL_Entry>&,
                        u32bit, u32bit, RandomNumberGenerator&) const;

      AlgorithmIdentifier ca_sig_algo;
      X509_Certificate cert;
      PK_Signer* signer;
   };

/**
* Choose the default signature format for a certain public key signature
* scheme.
* @param key will be the key to choose a padding scheme for
* @param alg_id will be set to the chosen scheme
* @return A PK_Signer object for generating signatures
*/
BOTAN_DLL PK_Signer* choose_sig_format(const Private_Key& key,
                                       AlgorithmIdentifier& alg_id);


}

#endif
