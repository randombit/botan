/*
* CVC Certificate Constructor
* (C) 2007 FlexSecure GmbH
*      2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cvc_ado.h>
#include <fstream>

namespace Botan {

EAC1_1_ADO::EAC1_1_ADO(DataSource& in)
   {
   init(in);
   do_decode();
   }

EAC1_1_ADO::EAC1_1_ADO(const std::string& in)
   {
   DataSource_Stream stream(in, true);
   init(stream);
   do_decode();
   }

void EAC1_1_ADO::force_decode()
   {
   secure_vector<byte> inner_cert;
   BER_Decoder(tbs_bits)
      .start_cons(ASN1_Tag(33))
      .raw_bytes(inner_cert)
      .end_cons()
      .decode(m_car)
      .verify_end();

   secure_vector<byte> req_bits = DER_Encoder()
      .start_cons(ASN1_Tag(33), APPLICATION)
      .raw_bytes(inner_cert)
      .end_cons()
      .get_contents();

   DataSource_Memory req_source(req_bits);
   m_req = EAC1_1_Req(req_source);
   sig_algo = m_req.sig_algo;
   }

std::vector<byte> EAC1_1_ADO::make_signed(PK_Signer& signer,
                                           const secure_vector<byte>& tbs_bits,
                                           RandomNumberGenerator& rng)
   {
   secure_vector<byte> concat_sig = signer.sign_message(tbs_bits, rng);

   return DER_Encoder()
      .start_cons(ASN1_Tag(7), APPLICATION)
      .raw_bytes(tbs_bits)
      .encode(concat_sig, OCTET_STRING, ASN1_Tag(55), APPLICATION)
      .end_cons()
      .get_contents();
   }

ASN1_Car EAC1_1_ADO::get_car() const
   {
   return m_car;
   }

void EAC1_1_ADO::decode_info(DataSource& source,
                             secure_vector<byte> & res_tbs_bits,
                             ECDSA_Signature & res_sig)
   {
   secure_vector<byte> concat_sig;
   secure_vector<byte> cert_inner_bits;
   ASN1_Car car;

   BER_Decoder(source)
      .start_cons(ASN1_Tag(7))
      .start_cons(ASN1_Tag(33))
      .raw_bytes(cert_inner_bits)
      .end_cons()
      .decode(car)
      .decode(concat_sig, OCTET_STRING, ASN1_Tag(55), APPLICATION)
      .end_cons();

   secure_vector<byte> enc_cert = DER_Encoder()
      .start_cons(ASN1_Tag(33), APPLICATION)
      .raw_bytes(cert_inner_bits)
      .end_cons()
      .get_contents();

   res_tbs_bits = enc_cert;
   res_tbs_bits += DER_Encoder().encode(car).get_contents();
   res_sig = decode_concatenation(concat_sig);
   }

void EAC1_1_ADO::encode(Pipe& out, X509_Encoding encoding) const
   {
   if(encoding == PEM)
      throw Invalid_Argument("EAC1_1_ADO::encode() cannot PEM encode an EAC object");

   secure_vector<byte> concat_sig(
      EAC1_1_obj<EAC1_1_ADO>::m_sig.get_concatenation());

   out.write(DER_Encoder()
             .start_cons(ASN1_Tag(7), APPLICATION)
                 .raw_bytes(tbs_bits)
                 .encode(concat_sig, OCTET_STRING, ASN1_Tag(55), APPLICATION)
             .end_cons()
             .get_contents());
   }

secure_vector<byte> EAC1_1_ADO::tbs_data() const
   {
   return tbs_bits;
   }

bool EAC1_1_ADO::operator==(EAC1_1_ADO const& rhs) const
   {
   return (this->get_concat_sig() == rhs.get_concat_sig()
           && this->tbs_data() == rhs.tbs_data()
           && this->get_car() ==  rhs.get_car());
   }

EAC1_1_Req EAC1_1_ADO::get_request() const
   {
   return m_req;
   }

}
