/*
  (C) 2007 FlexSecure GmbH
      2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cvc_cert.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/pem.h>
#include <botan/parsing.h>
#include <assert.h>
#include <botan/cvc_key.h>
#include <botan/oids.h>
#include <botan/look_pk.h>
#include <botan/cvc_req.h>
#include <botan/freestore.h>

namespace Botan {

bool EAC1_1_Req::operator==(EAC1_1_Req const& rhs) const
   {
   return (this->tbs_data() == rhs.tbs_data()
           && this->get_concat_sig() == rhs.get_concat_sig());
   }

void EAC1_1_Req::force_decode()
   {
   SecureVector<byte> enc_pk;
   BER_Decoder tbs_cert(tbs_bits);
   u32bit cpi;
   tbs_cert.decode(cpi, ASN1_Tag(41), APPLICATION)
      .start_cons(ASN1_Tag(73))
      .raw_bytes(enc_pk)
      .end_cons()
      .decode(m_chr)
      .verify_end();
   if(cpi != 0)
      {
      throw Decoding_Error("EAC1_1 request´s cpi was not 0");
      }

   // FIXME: No EAC support in ECDSA
#if 0
   ECDSA_PublicKey tmp_pk;
   std::auto_ptr<EAC1_1_CVC_Decoder> dec = tmp_pk.cvc_eac1_1_decoder();
   sig_algo = dec->public_key(enc_pk);
   m_pk = tmp_pk;
#endif
   }

EAC1_1_Req::EAC1_1_Req(std::tr1::shared_ptr<DataSource> in)
   {
   init(in);
   self_signed = true;
   do_decode();
   }

EAC1_1_Req::EAC1_1_Req(const std::string& in)
   {
   std::tr1::shared_ptr<DataSource> stream(new DataSource_Stream(in, true));
   init(stream);
   self_signed = true;
   do_decode();
   }

}
