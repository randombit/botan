/*
 (C) 2007 FlexSecure GmbH
     2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cvc_cert.h>
#include <botan/cvc_key.h>
#include <botan/ecdsa.h>

namespace Botan {

ASN1_Car EAC1_1_CVC::get_car() const
   {
   return m_car;
   }

ASN1_Ced EAC1_1_CVC::get_ced() const
   {
   return m_ced;
   }
ASN1_Cex EAC1_1_CVC::get_cex() const
   {
   return m_cex;
   }
u32bit EAC1_1_CVC::get_chat_value() const
   {
   return m_chat_val;
   }

/*
* Decode the TBSCertificate data
*/
void EAC1_1_CVC::force_decode()
   {
   SecureVector<byte> enc_pk;
   SecureVector<byte> enc_chat_val;
   u32bit cpi;
   BER_Decoder tbs_cert(tbs_bits);
   tbs_cert.decode(cpi, ASN1_Tag(41), APPLICATION)
      .decode(m_car)
      .start_cons(ASN1_Tag(73))
      .raw_bytes(enc_pk)
      .end_cons()
      .decode(m_chr)
      .start_cons(ASN1_Tag(76))
      .decode(m_chat_oid)
      .decode(enc_chat_val, OCTET_STRING, ASN1_Tag(19), APPLICATION)
      .end_cons()
      .decode(m_ced)
      .decode(m_cex)
      .verify_end();

   if(enc_chat_val.size() != 1)
      throw Decoding_Error("CertificateHolderAuthorizationValue was not of length 1");

   if(cpi != 0)
      throw Decoding_Error("EAC1_1 certificate´s cpi was not 0");

   // FIXME: PK algos have no notion of EAC encoder/decoder currently
#if 0
   ECDSA_PublicKey tmp_pk;
   std::auto_ptr<EAC1_1_CVC_Decoder> dec = tmp_pk.cvc_eac1_1_decoder();
   sig_algo = dec->public_key(enc_pk);


   m_pk = tmp_pk;
   m_chat_val = enc_chat_val[0];
   self_signed = false;
   if(m_car.iso_8859() == m_chr.iso_8859())
      {
      self_signed= true;
      }
#endif
   }

/*
* CVC Certificate Constructor
*/
EAC1_1_CVC::EAC1_1_CVC(std::tr1::shared_ptr<DataSource>& in)
   {
   init(in);
   self_signed = false;
   do_decode();
   }

EAC1_1_CVC::EAC1_1_CVC(const std::string& in)
   {
   std::tr1::shared_ptr<DataSource> stream(new DataSource_Stream(in, true));
   init(stream);
   self_signed = false;
   do_decode();
   }

bool EAC1_1_CVC::operator==(EAC1_1_CVC const& rhs) const
   {
   return (tbs_data() == rhs.tbs_data()
           && get_concat_sig() == rhs.get_concat_sig());
   }

}
