/*
* EAC1_1 CVC
* (C) 2008 Falko Strenzke
*     2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CVC_EAC_H__
#define BOTAN_CVC_EAC_H__

#include <botan/cvc_gen_cert.h>
#include <botan/ecdsa.h>
#include <string>

namespace Botan {

/**
* This class represents TR03110 (EAC) v1.1 CV Certificates
*/
class BOTAN_DLL EAC1_1_CVC : public EAC1_1_gen_CVC<EAC1_1_CVC>//Signed_Object
    {
    public:
       friend class EAC1_1_obj<EAC1_1_CVC>;

       /**
       * Get the CAR of the certificate.
       * @result the CAR of the certificate
       */
       ASN1_Car get_car() const;

       /**
       * Get the CED of this certificate.
       * @result the CED this certificate
       */
       ASN1_Ced get_ced() const;

       /**
       * Get the CEX of this certificate.
       * @result the CEX this certificate
       */
       ASN1_Cex get_cex() const;

       /**
       * Get the CHAT value.
       * @result the CHAT value
       */
       u32bit get_chat_value() const;

       bool operator==(const EAC1_1_CVC&) const;

       /**
       * Construct a CVC from a data source
       * @param source the data source
       */
       EAC1_1_CVC(DataSource& source);

       /**
       * Construct a CVC from a file
       * @param str the path to the certificate file
       */
       EAC1_1_CVC(const std::string& str);

       virtual ~EAC1_1_CVC() {}
    private:
       void force_decode();
       EAC1_1_CVC() {}

       ASN1_Car m_car;
       ASN1_Ced m_ced;
       ASN1_Cex m_cex;
       byte m_chat_val;
       OID m_chat_oid;
    };

/*
* Comparison
*/
inline bool operator!=(EAC1_1_CVC const& lhs, EAC1_1_CVC const& rhs)
   {
   return !(lhs == rhs);
   }

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
* @param cex the CEX to appear in the certificate
* @param rng a random number generator
*/
EAC1_1_CVC BOTAN_DLL make_cvc_cert(PK_Signer& signer,
                                   const std::vector<byte>& public_key,
                                   ASN1_Car const& car,
                                   ASN1_Chr const& chr,
                                   byte holder_auth_templ,
                                   ASN1_Ced ced,
                                   ASN1_Cex cex,
                                   RandomNumberGenerator& rng);

/**
* Decode an EAC encoding ECDSA key
*/
BOTAN_DLL ECDSA_PublicKey* decode_eac1_1_key(const std::vector<byte>& enc_key,
                                             AlgorithmIdentifier& sig_algo);

}

#endif

