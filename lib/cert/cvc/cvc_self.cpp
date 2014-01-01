/*
  (C) 2007 FlexSecure GmbH
      2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cvc_self.h>
#include <botan/ecc_key.h>
#include <botan/point_gfp.h>
#include <botan/oids.h>
#include <sstream>
#include <memory>

namespace Botan {

namespace {

/*
* cvc CHAT values
*/
enum CHAT_values{
      CVCA = 0xC0,
      DVCA_domestic = 0x80,
      DVCA_foreign =  0x40,
      IS   = 0x00,

      IRIS = 0x02,
      FINGERPRINT = 0x01
};

void encode_eac_bigint(DER_Encoder& der, const BigInt& x, ASN1_Tag tag)
   {
   der.encode(BigInt::encode_1363(x, x.bytes()), OCTET_STRING, tag);
   }

std::vector<byte> eac_1_1_encoding(const EC_PublicKey* key,
                                    const OID& sig_algo)
   {
   if(key->domain_format() == EC_DOMPAR_ENC_OID)
      throw Encoding_Error("CVC encoder: cannot encode parameters by OID");

   const EC_Group& domain = key->domain();

   // This is why we can't have nice things

   DER_Encoder enc;
   enc.start_cons(ASN1_Tag(73), APPLICATION)
      .encode(sig_algo);

   if(key->domain_format() == EC_DOMPAR_ENC_EXPLICIT)
      {
      encode_eac_bigint(enc, domain.get_curve().get_p(), ASN1_Tag(1));
      encode_eac_bigint(enc, domain.get_curve().get_a(), ASN1_Tag(2));
      encode_eac_bigint(enc, domain.get_curve().get_b(), ASN1_Tag(3));

      enc.encode(EC2OSP(domain.get_base_point(), PointGFp::UNCOMPRESSED),
                 OCTET_STRING, ASN1_Tag(4));

      encode_eac_bigint(enc, domain.get_order(), ASN1_Tag(4));
      }

   enc.encode(EC2OSP(key->public_point(), PointGFp::UNCOMPRESSED),
              OCTET_STRING, ASN1_Tag(6));

   if(key->domain_format() == EC_DOMPAR_ENC_EXPLICIT)
      encode_eac_bigint(enc, domain.get_cofactor(), ASN1_Tag(7));

   enc.end_cons();

   return enc.get_contents_unlocked();
   }

std::string padding_and_hash_from_oid(OID const& oid)
   {
   std::string padding_and_hash = OIDS::lookup(oid); // use the hash

   if(padding_and_hash.substr(0,6) != "ECDSA/")
      throw Invalid_State("CVC: Can only use ECDSA, not " + padding_and_hash);

   padding_and_hash.erase(0, padding_and_hash.find("/") + 1);
   return padding_and_hash;
   }

}

namespace CVC_EAC {

EAC1_1_CVC create_self_signed_cert(Private_Key const& key,
                                   EAC1_1_CVC_Options const& opt,
                                   RandomNumberGenerator& rng)
   {
   // NOTE: we ignore the value of opt.chr

   const ECDSA_PrivateKey* priv_key = dynamic_cast<const ECDSA_PrivateKey*>(&key);

   if(priv_key == 0)
      throw Invalid_Argument("CVC_EAC::create_self_signed_cert(): unsupported key type");

   ASN1_Chr chr(opt.car.value());

   AlgorithmIdentifier sig_algo;
   std::string padding_and_hash("EMSA1_BSI(" + opt.hash_alg + ")");
   sig_algo.oid = OIDS::lookup(priv_key->algo_name() + "/" + padding_and_hash);
   sig_algo = AlgorithmIdentifier(sig_algo.oid, AlgorithmIdentifier::USE_NULL_PARAM);

   PK_Signer signer(*priv_key, padding_and_hash);

   std::vector<byte> enc_public_key = eac_1_1_encoding(priv_key, sig_algo.oid);

   return make_cvc_cert(signer,
                        enc_public_key,
                        opt.car, chr,
                        opt.holder_auth_templ,
                        opt.ced, opt.cex, rng);
   }

EAC1_1_Req create_cvc_req(Private_Key const& key,
                          ASN1_Chr const& chr,
                          std::string const& hash_alg,
                          RandomNumberGenerator& rng)
   {

   ECDSA_PrivateKey const* priv_key = dynamic_cast<ECDSA_PrivateKey const*>(&key);
   if (priv_key == 0)
      {
      throw Invalid_Argument("CVC_EAC::create_self_signed_cert(): unsupported key type");
      }
   AlgorithmIdentifier sig_algo;
   std::string padding_and_hash("EMSA1_BSI(" + hash_alg + ")");
   sig_algo.oid = OIDS::lookup(priv_key->algo_name() + "/" + padding_and_hash);
   sig_algo = AlgorithmIdentifier(sig_algo.oid, AlgorithmIdentifier::USE_NULL_PARAM);

   PK_Signer signer(*priv_key, padding_and_hash);

   std::vector<byte> enc_public_key = eac_1_1_encoding(priv_key, sig_algo.oid);

   std::vector<byte> enc_cpi;
   enc_cpi.push_back(0x00);
   std::vector<byte> tbs = DER_Encoder()
      .encode(enc_cpi, OCTET_STRING, ASN1_Tag(41), APPLICATION)
      .raw_bytes(enc_public_key)
      .encode(chr)
      .get_contents_unlocked();

   std::vector<byte> signed_cert =
      EAC1_1_gen_CVC<EAC1_1_Req>::make_signed(signer,
                                              EAC1_1_gen_CVC<EAC1_1_Req>::build_cert_body(tbs),
                                              rng);

   DataSource_Memory source(signed_cert);
   return EAC1_1_Req(source);
   }

EAC1_1_ADO create_ado_req(Private_Key const& key,
                          EAC1_1_Req const& req,
                          ASN1_Car const& car,
                          RandomNumberGenerator& rng)
   {

   ECDSA_PrivateKey const* priv_key = dynamic_cast<ECDSA_PrivateKey const*>(&key);
   if (priv_key == 0)
      {
      throw Invalid_Argument("CVC_EAC::create_self_signed_cert(): unsupported key type");
      }

   std::string padding_and_hash = padding_and_hash_from_oid(req.signature_algorithm().oid);
   PK_Signer signer(*priv_key, padding_and_hash);
   std::vector<byte> tbs_bits = req.BER_encode();
   tbs_bits += DER_Encoder().encode(car).get_contents();

   std::vector<byte> signed_cert =
      EAC1_1_ADO::make_signed(signer, tbs_bits, rng);

   DataSource_Memory source(signed_cert);
   return EAC1_1_ADO(source);
   }

} // namespace CVC_EAC
namespace DE_EAC
{

EAC1_1_CVC create_cvca(Private_Key const& key,
                       std::string const& hash,
                       ASN1_Car const& car, bool iris, bool fingerpr,
                       u32bit cvca_validity_months,
                       RandomNumberGenerator& rng)
   {
   ECDSA_PrivateKey const* priv_key = dynamic_cast<ECDSA_PrivateKey const*>(&key);
   if (priv_key == 0)
      {
      throw Invalid_Argument("CVC_EAC::create_self_signed_cert(): unsupported key type");
      }
   EAC1_1_CVC_Options opts;
   opts.car = car;

   opts.ced = ASN1_Ced(std::chrono::system_clock::now());
   opts.cex = ASN1_Cex(opts.ced);
   opts.cex.add_months(cvca_validity_months);
   opts.holder_auth_templ = (CVCA | (iris * IRIS) | (fingerpr * FINGERPRINT));
   opts.hash_alg = hash;
   return CVC_EAC::create_self_signed_cert(*priv_key, opts, rng);
   }



EAC1_1_CVC link_cvca(EAC1_1_CVC const& signer,
                     Private_Key const& key,
                     EAC1_1_CVC const& signee,
                     RandomNumberGenerator& rng)
   {
   const ECDSA_PrivateKey* priv_key = dynamic_cast<ECDSA_PrivateKey const*>(&key);

   if (priv_key == 0)
      throw Invalid_Argument("link_cvca(): unsupported key type");

   ASN1_Ced ced(std::chrono::system_clock::now());
   ASN1_Cex cex(signee.get_cex());
   if (*static_cast<EAC_Time*>(&ced) > *static_cast<EAC_Time*>(&cex))
      {
      std::string detail("link_cvca(): validity periods of provided certificates don't overlap: currend time = ced = ");
      detail += ced.as_string();
      detail += ", signee.cex = ";
      detail += cex.as_string();
      throw Invalid_Argument(detail);
      }
   if (signer.signature_algorithm() != signee.signature_algorithm())
      {
      throw Invalid_Argument("link_cvca(): signature algorithms of signer and signee don't match");
      }
   AlgorithmIdentifier sig_algo = signer.signature_algorithm();
   std::string padding_and_hash = padding_and_hash_from_oid(sig_algo.oid);
   PK_Signer pk_signer(*priv_key, padding_and_hash);
   std::unique_ptr<Public_Key> pk(signee.subject_public_key());
   ECDSA_PublicKey* subj_pk = dynamic_cast<ECDSA_PublicKey*>(pk.get());
   subj_pk->set_parameter_encoding(EC_DOMPAR_ENC_EXPLICIT);

   std::vector<byte> enc_public_key = eac_1_1_encoding(priv_key, sig_algo.oid);

   return make_cvc_cert(pk_signer, enc_public_key,
                        signer.get_car(),
                        signee.get_chr(),
                        signer.get_chat_value(),
                        ced, cex,
                        rng);
   }

EAC1_1_CVC sign_request(EAC1_1_CVC const& signer_cert,
                        Private_Key const& key,
                        EAC1_1_Req const& signee,
                        u32bit seqnr,
                        u32bit seqnr_len,
                        bool domestic,
                        u32bit dvca_validity_months,
                        u32bit ca_is_validity_months,
                        RandomNumberGenerator& rng)
   {
   ECDSA_PrivateKey const* priv_key = dynamic_cast<ECDSA_PrivateKey const*>(&key);
   if (priv_key == 0)
      {
      throw Invalid_Argument("CVC_EAC::create_self_signed_cert(): unsupported key type");
      }
   std::string chr_str = signee.get_chr().value();

   std::string seqnr_string = std::to_string(seqnr);

   while(seqnr_string.size() < seqnr_len)
      seqnr_string = '0' + seqnr_string;

   chr_str += seqnr_string;
   ASN1_Chr chr(chr_str);
   std::string padding_and_hash = padding_and_hash_from_oid(signee.signature_algorithm().oid);
   PK_Signer pk_signer(*priv_key, padding_and_hash);
   std::unique_ptr<Public_Key> pk(signee.subject_public_key());
   ECDSA_PublicKey*  subj_pk = dynamic_cast<ECDSA_PublicKey*>(pk.get());
   std::unique_ptr<Public_Key> signer_pk(signer_cert.subject_public_key());

   // for the case that the domain parameters are not set...
   // (we use those from the signer because they must fit)
   //subj_pk->set_domain_parameters(priv_key->domain_parameters());

   subj_pk->set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);

   AlgorithmIdentifier sig_algo(signer_cert.signature_algorithm());

   ASN1_Ced ced(std::chrono::system_clock::now());

   u32bit chat_val;
   u32bit chat_low = signer_cert.get_chat_value() & 0x3; // take the chat rights from signer
   ASN1_Cex cex(ced);
   if ((signer_cert.get_chat_value() & CVCA) == CVCA)
      {
      // we sign a dvca
      cex.add_months(dvca_validity_months);
      if (domestic)
         chat_val = DVCA_domestic | chat_low;
      else
         chat_val = DVCA_foreign | chat_low;
      }
   else if ((signer_cert.get_chat_value() & DVCA_domestic) == DVCA_domestic ||
            (signer_cert.get_chat_value() & DVCA_foreign) == DVCA_foreign)
      {
      cex.add_months(ca_is_validity_months);
      chat_val = IS | chat_low;
      }
   else
      {
      throw Invalid_Argument("sign_request(): encountered illegal value for CHAT");
      // (IS cannot sign certificates)
      }

   std::vector<byte> enc_public_key = eac_1_1_encoding(priv_key, sig_algo.oid);

   return make_cvc_cert(pk_signer, enc_public_key,
                        ASN1_Car(signer_cert.get_chr().iso_8859()),
                        chr,
                        chat_val,
                        ced,
                        cex,
                        rng);
   }

EAC1_1_Req create_cvc_req(Private_Key const& prkey,
                          ASN1_Chr const& chr,
                          std::string const& hash_alg,
                          RandomNumberGenerator& rng)
   {
   ECDSA_PrivateKey const* priv_key = dynamic_cast<ECDSA_PrivateKey const*>(&prkey);
   if (priv_key == 0)
      {
      throw Invalid_Argument("CVC_EAC::create_self_signed_cert(): unsupported key type");
      }
   ECDSA_PrivateKey key(*priv_key);
   key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
   return CVC_EAC::create_cvc_req(key, chr, hash_alg, rng);
   }

} // namespace DE_EAC

}
