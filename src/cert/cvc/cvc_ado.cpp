/*
* CVC Certificate Constructor
* (C) 2007 FlexSecure GmbH
*      2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cvc_ado.h>
#include <fstream>
#include <assert.h>

namespace Botan {

EAC1_1_ADO::EAC1_1_ADO(std::tr1::shared_ptr<DataSource> in)
   {
   init(in);
   do_decode();
   }

EAC1_1_ADO::EAC1_1_ADO(const std::string& in)
   {
   std::tr1::shared_ptr<DataSource> stream(new DataSource_Stream(in, true));
   init(stream);
   do_decode();
   }

void EAC1_1_ADO::force_decode()
   {
   SecureVector<byte> inner_cert;
   BER_Decoder(tbs_bits)
      .start_cons(ASN1_Tag(33))
      .raw_bytes(inner_cert)
      .end_cons()
      .decode(m_car)
      .verify_end();

   SecureVector<byte> req_bits = DER_Encoder()
      .start_cons(ASN1_Tag(33), APPLICATION)
      .raw_bytes(inner_cert)
      .end_cons()
      .get_contents();

   std::tr1::shared_ptr<DataSource> req_source(new DataSource_Memory(req_bits));
   m_req = EAC1_1_Req(req_source);
   sig_algo = m_req.sig_algo;
   }

MemoryVector<byte> EAC1_1_ADO::make_signed(
   std::auto_ptr<PK_Signer> signer,
   const MemoryRegion<byte>& tbs_bits,
   RandomNumberGenerator& rng)
   {
   SecureVector<byte> concat_sig =
      EAC1_1_obj<EAC1_1_ADO>::make_signature(signer.get(), tbs_bits, rng);
   assert(concat_sig.size() % 2 == 0);
   MemoryVector<byte> result = DER_Encoder()
      .start_cons(ASN1_Tag(7), APPLICATION)
      .raw_bytes(tbs_bits)
      .encode(concat_sig, OCTET_STRING, ASN1_Tag(55), APPLICATION)
      .end_cons()
      .get_contents();
   return result;
   }

ASN1_Car EAC1_1_ADO::get_car() const
   {
   return m_car;
   }

void EAC1_1_ADO::decode_info(SharedPtrConverter<DataSource> source,
                             SecureVector<byte> & res_tbs_bits,
                             ECDSA_Signature & res_sig)
   {
   SecureVector<byte> concat_sig;
   SecureVector<byte> cert_inner_bits;
   ASN1_Car car;
   BER_Decoder(*source.get_ptr().get())
      .start_cons(ASN1_Tag(7))
      .start_cons(ASN1_Tag(33))
      .raw_bytes(cert_inner_bits)
      .end_cons()
      .decode(car)
      .decode(concat_sig, OCTET_STRING, ASN1_Tag(55), APPLICATION)
      .end_cons();

   SecureVector<byte> enc_cert = DER_Encoder()
      .start_cons(ASN1_Tag(33), APPLICATION)
      .raw_bytes(cert_inner_bits)
      .end_cons()
      .get_contents();
   SecureVector<byte> enc_car = DER_Encoder()
      .encode(car)
      .get_contents();
   res_tbs_bits = enc_cert;
   res_tbs_bits.append(enc_car);
   res_sig = decode_concatenation(concat_sig);


   }
void EAC1_1_ADO::encode(Pipe& out, X509_Encoding encoding) const
   {
   SecureVector<byte> concat_sig(EAC1_1_obj<EAC1_1_ADO>::m_sig.get_concatenation());
   SecureVector<byte> der = DER_Encoder()
      .start_cons(ASN1_Tag(7), APPLICATION)
      .raw_bytes(tbs_bits)
      .encode(concat_sig, OCTET_STRING, ASN1_Tag(55), APPLICATION)
      .end_cons()
      .get_contents();
   if(encoding == PEM)
      throw Invalid_Argument("EAC1_1_ADO::encode() cannot PEM encode an EAC object");
   else
      out.write(der);
   }

SecureVector<byte> EAC1_1_ADO::tbs_data() const
   {
   return tbs_bits;
   }

bool EAC1_1_ADO::operator==(EAC1_1_ADO const& rhs) const
   {
   assert(((this->m_req == rhs.m_req) && (this->tbs_data() == rhs.tbs_data())) ||
          ((this->m_req != rhs.m_req) && (this->tbs_data() != rhs.tbs_data())));
   return (this->get_concat_sig() == rhs.get_concat_sig()
           && this->tbs_data() == rhs.tbs_data()
           && this->get_car() ==  rhs.get_car());
   }

EAC1_1_Req EAC1_1_ADO::get_request() const
   {
   return m_req;
   }

}
