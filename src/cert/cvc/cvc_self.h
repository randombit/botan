/*
* CVC Self-Signed Certificate
* (C) 2007 FlexSecure GmbH
*     2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CVC_EAC_SELF_H__
#define BOTAN_CVC_EAC_SELF_H__

#include <botan/pkcs8.h>
#include <botan/pkcs10.h>
#include <botan/cvc_cert.h>
#include <botan/ecdsa.h>
#include <botan/asn1_obj.h>
#include <botan/cvc_req.h>
#include <botan/cvc_ado.h>

namespace Botan {

/**
* This class represents a set of options used for the creation of CVC certificates
*/
class BOTAN_DLL EAC1_1_CVC_Options
   {
   public:

      ASN1_Car car;
      ASN1_Chr chr;
      byte holder_auth_templ;
      ASN1_Ced ced;
      ASN1_Cex cex;
      std::string hash_alg;
   };

/**
* This namespace represents general EAC 1.1 convenience functions.
*/
namespace CVC_EAC {

/**
* Create a selfsigned CVCA
* @param rng the rng to use
* @param key the ECDSA private key to be used to sign the certificate
* @param opts used to set several parameters. Necessary are:
* car, holder_auth_templ, hash_alg, ced, cex and hash_alg
* @result the self signed certificate
*/

EAC1_1_CVC create_self_signed_cert(Private_Key const& key,
                                   EAC1_1_CVC_Options const& opts,
                                   RandomNumberGenerator& rng);
/**
* Create a CVC request. The key encoding will be according to the provided private key.
* @param priv_key the private key associated with the requesting entity
* @param chr the chr to appear in the certificate (to be provided without
* sequence number)
* @param hash_alg the string defining the hash algorithm to be used for the creation
* of the signature
* @param rng the rng to use
* @result the new request
*/
EAC1_1_Req create_cvc_req(Private_Key const& priv_key,
                          ASN1_Chr const& chr,
                          std::string const& hash_alg,
                          RandomNumberGenerator& rng);

/**
* Create an ADO from a request object.
* @param priv_key the private key used to sign the ADO
* @param req the request forming the body of the ADO
* @param car the CAR forming the body of the ADO, i.e. the
* CHR of the entity associated with the provided private key
* @param rng the rng to use
*/
EAC1_1_ADO create_ado_req(Private_Key const& priv_key,
                          EAC1_1_Req const& req,
                          ASN1_Car const& car,
                          RandomNumberGenerator& rng);
}
/**
* This namespace represents EAC 1.1 CVC convenience functions following the specific german
* requirements.
*/
namespace DE_EAC {

/**
* Create a CVCA certificate.
* @param priv_key the private key associated with the CVCA certificate
* to be created
* @param hash the string identifying the hash algorithm to be used
* for signing the certificate to be created
* @param car the CAR of the certificate to be created
* @param iris indicates whether the entity associated with the certificate
* shall be entitled to read the biometrical iris image
* @param fingerpr indicates whether the entity associated with the certificate
* shall be entitled to read the biometrical fingerprint image
* @param rng the rng to use
* @result the CVCA certificate created
*/
EAC1_1_CVC create_cvca(Private_Key const& priv_key,
                       std::string const& hash,
                       ASN1_Car const& car,
                       bool iris,
                       bool fingerpr,
                       u32bit cvca_validity_months,
                       RandomNumberGenerator& rng);

/**
* Create a link certificate between two CVCA certificates. The key
* encoding will be implicitCA.
* @param signer the cvca certificate associated with the signing
* entity
* @param priv_key the private key associated with the signer
* @param to_be_signed the certificate which whose CAR/CHR will be
* the holder of the link certificate
* @param rng a random number generator
*/
EAC1_1_CVC link_cvca(EAC1_1_CVC const& signer,
                     Private_Key const& priv_key,
                     EAC1_1_CVC const& to_be_signed,
                     RandomNumberGenerator& rng);

/**
* Create a CVC request. The key encoding will be implicitCA.
* @param priv_key the private key associated with the requesting entity
* @param chr the chr to appear in the certificate (to be provided without
* sequence number)
* @param hash_alg the string defining the hash algorithm to be used for the creation
* of the signature
* @param rng a random number generator
* @result the new request
*/
EAC1_1_Req create_cvc_req(Private_Key const& priv_key,
                          ASN1_Chr const& chr,
                          std::string const& hash_alg,
                          RandomNumberGenerator& rng);

/**
* Sign a CVC request.
* @param signer_cert the certificate of the signing entity
* @param priv_key the private key of the signing entity
* @param req the request to be signed
* @param seqnr the sequence number of the certificate to be created
* @param seqnr_len the number of digits the sequence number will be
* encoded in
* @param domestic indicates whether to sign a domestic or a foreign certificate:
* set to true for domestic
* @param rng a random number generator
* @result the new certificate
*
**/
EAC1_1_CVC sign_request(EAC1_1_CVC const& signer_cert,
                        Private_Key const& priv_key,
                        EAC1_1_Req const& req,
                        u32bit seqnr,
                        u32bit seqnr_len,
                        bool domestic,
                        u32bit dvca_validity_months,
                        u32bit ca_is_validity_months,
                        RandomNumberGenerator& rng);
}

}

#endif
