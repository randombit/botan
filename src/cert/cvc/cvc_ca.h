/*
* EAC1.1 CVC Certificate Authority
* (C) 2007 FlexSecure GmbH
*     2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CVC_CA_H__
#define BOTAN_CVC_CA_H__

#include <botan/pkcs8.h>
#include <botan/pkcs10.h>
#include <botan/pubkey.h>
#include <botan/cvc_cert.h>

namespace Botan {

/**
* This class represents a CVC CA.
*/
class BOTAN_DLL EAC1_1_CVC_CA
   {
   public:

      /**
      * Create an arbitrary EAC 1.1 CVC.
      * The desired key encoding must be set within the key (if applicable).
      * @param signer the signer used to sign the certificate
      * @param public_key the DER encoded public key to appear in
      * the certificate
      * @param car the CAR of the certificate
      * @param chr the CHR of the certificate
      * @param holder_auth_templ the holder authorization value byte to
      * appear in the CHAT of the certificate
      * @param ced the CED to appear in the certificate
      * @param ced the CEX to appear in the certificate
      */
      static EAC1_1_CVC make_cert(std::auto_ptr<PK_Signer> signer,
                                  MemoryRegion<byte> const& public_key,
                                  ASN1_Car const& car,
                                  ASN1_Chr const& chr,
                                  byte holder_auth_templ,
                                  ASN1_Ced ced,
                                  ASN1_Cex cex,
                                  RandomNumberGenerator& rng);
   };

}

#endif
