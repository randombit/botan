/*
* EAC1_1 general CVC
* (C) 2008 Falko Strenzke
*     2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EAC_CVC_GEN_CERT_H__
#define BOTAN_EAC_CVC_GEN_CERT_H__

#include <botan/x509_key.h>
#include <botan/eac_asn_obj.h>
#include <botan/pubkey_enums.h>
#include <botan/pubkey.h>
#include <botan/ecdsa_sig.h>
#include <string>
#include <assert.h>

namespace Botan {

/**
*  This class represents TR03110 (EAC) v1.1 generalized CV Certificates
*/
template<typename Derived>
class BOTAN_DLL EAC1_1_gen_CVC : public EAC1_1_obj<Derived> // CRTP continuation from EAC1_1_obj
   {
      friend class EAC1_1_obj<EAC1_1_gen_CVC>;

   public:

      /**
      * Get this certificates public key.
      * @result this certificates public key
      */
      std::auto_ptr<Public_Key> subject_public_key() const;

      /**
      * Find out whether this object is self signed.
      * @result true if this object is self signed
      */
      bool is_self_signed() const;

      /**
      * Get the CHR of the certificate.
      * @result the CHR of the certificate
      */
      ASN1_Chr get_chr() const;

      /**
      * Put the DER encoded version of this object into a pipe. PEM
      * is not supported.
      * @param out the pipe to push the DER encoded version into
      * @param encoding the encoding to use. Must be DER.
      */
      void encode(Pipe& out, X509_Encoding encoding) const;

      /**
      * Get the to-be-signed (TBS) data of this object.
      * @result the TBS data of this object
      */
      SecureVector<byte> tbs_data() const;

      /**
      * Build the DER encoded certifcate body of an object
      * @param tbs the data to be signed
      * @result the correctly encoded body of the object
      */
      static SecureVector<byte> build_cert_body(MemoryRegion<byte> const& tbs);

      /**
      * Create a signed generalized CVC object.
      * @param signer the signer used to sign this object
      * @param tbs_bits the body the generalized CVC object to be signed
      * @result the DER encoded signed generalized CVC object
      */
      static MemoryVector<byte> make_signed(
         std::auto_ptr<PK_Signer> signer,
         const MemoryRegion<byte>& tbs_bits,
         RandomNumberGenerator& rng);
      virtual ~EAC1_1_gen_CVC<Derived>()
         {}

   protected:
      ECDSA_PublicKey m_pk; // public key
      ASN1_Chr m_chr;
      bool self_signed;

      static void decode_info(SharedPtrConverter<DataSource> source,
                              SecureVector<byte> & res_tbs_bits,
                              ECDSA_Signature & res_sig);

   };

template<typename Derived> ASN1_Chr EAC1_1_gen_CVC<Derived>::get_chr() const
   {
   return m_chr;
   }

template<typename Derived> bool EAC1_1_gen_CVC<Derived>::is_self_signed() const
   {
   return self_signed;
   }

template<typename Derived> MemoryVector<byte> EAC1_1_gen_CVC<Derived>::make_signed(
   std::auto_ptr<PK_Signer> signer,
   const MemoryRegion<byte>& tbs_bits,
   RandomNumberGenerator& rng) // static
   {
   SecureVector<byte> concat_sig = EAC1_1_obj<Derived>::make_signature(signer.get(), tbs_bits, rng);
   assert(concat_sig.size() % 2 == 0);
   return DER_Encoder()
      .start_cons(ASN1_Tag(33), APPLICATION)
      .raw_bytes(tbs_bits)
      .encode(concat_sig, OCTET_STRING, ASN1_Tag(55), APPLICATION)
      .end_cons()
      .get_contents();
   }

template<typename Derived> std::auto_ptr<Public_Key> EAC1_1_gen_CVC<Derived>::subject_public_key() const
   {
   return std::auto_ptr<Public_Key>(new ECDSA_PublicKey(m_pk));
   }

template<typename Derived> SecureVector<byte> EAC1_1_gen_CVC<Derived>::build_cert_body(MemoryRegion<byte> const& tbs)
   {
   return DER_Encoder()
      .start_cons(ASN1_Tag(78), APPLICATION)
      .raw_bytes(tbs)
      .end_cons().get_contents();
   }

template<typename Derived> SecureVector<byte> EAC1_1_gen_CVC<Derived>::tbs_data() const
   {
   return build_cert_body(EAC1_1_obj<Derived>::tbs_bits);
   }

template<typename Derived> void EAC1_1_gen_CVC<Derived>::encode(Pipe& out, X509_Encoding encoding) const
   {
   SecureVector<byte> concat_sig(EAC1_1_obj<Derived>::m_sig.get_concatenation());
   SecureVector<byte> der = DER_Encoder()
      .start_cons(ASN1_Tag(33), APPLICATION)
      .start_cons(ASN1_Tag(78), APPLICATION)
      .raw_bytes(EAC1_1_obj<Derived>::tbs_bits)
      .end_cons()
      .encode(concat_sig, OCTET_STRING, ASN1_Tag(55), APPLICATION)
      .end_cons()
      .get_contents();

   if (encoding == PEM)
      throw Invalid_Argument("EAC1_1_gen_CVC::encode() cannot PEM encode an EAC object");
   else
      out.write(der);
   }

template<typename Derived>
void EAC1_1_gen_CVC<Derived>::decode_info(
   SharedPtrConverter<DataSource> source,
   SecureVector<byte> & res_tbs_bits,
   ECDSA_Signature & res_sig)
   {
   SecureVector<byte> concat_sig;
   BER_Decoder(*source.get_shared().get())
      .start_cons(ASN1_Tag(33))
      .start_cons(ASN1_Tag(78))
      .raw_bytes(res_tbs_bits)
      .end_cons()
      .decode(concat_sig, OCTET_STRING, ASN1_Tag(55), APPLICATION)
      .end_cons();
   res_sig = decode_concatenation(concat_sig);
   }

}

#endif


