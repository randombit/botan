/*
  (C) 2007 FlexSecure GmbH
      2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cvc_self.h>
#include <botan/cvc_cert.h>
#include <botan/cvc_ca.h>
#include <botan/alg_id.h>
#include <botan/cvc_key.h>
#include <botan/oids.h>
#include <botan/look_pk.h>
#include <botan/cvc_req.h>
#include <botan/cvc_ado.h>
#include <botan/util.h>
#include <sstream>

namespace Botan {

namespace {

/*******************************
* cvc CHAT values
*******************************/
enum CHAT_values{
      CVCA = 0xC0,
      DVCA_domestic = 0x80,
      DVCA_foreign =  0x40,
      IS   = 0x00,

      IRIS = 0x02,
      FINGERPRINT = 0x01
};

std::string padding_and_hash_from_oid(OID const& oid)
   {
   std::string padding_and_hash = OIDS::lookup(oid); // use the hash
   assert(padding_and_hash.substr(0,6) == "ECDSA/"); // can only be ECDSA for now
   assert(padding_and_hash.find("/",0) == 5);
   padding_and_hash.erase(0, padding_and_hash.find("/",0) + 1);
   return padding_and_hash;
   }
std::string fixed_len_seqnr(u32bit seqnr, u32bit len)
   {
   std::stringstream ss;
   std::string result;
   ss << seqnr;
   ss >> result;
   if (result.size() > len)
      {
      throw Invalid_Argument("fixed_len_seqnr(): number too high to be encoded in provided length");
      }
   while (result.size() < len)
      {
      result.insert(0,"0");
      }
   return result;
   }

}
namespace CVC_EAC
{

EAC1_1_CVC create_self_signed_cert(Private_Key const& key,
                                   EAC1_1_CVC_Options const& opt,
                                   RandomNumberGenerator& rng)
   {
   // NOTE: we ignore
   // the value
   // of opt.chr
   ECDSA_PrivateKey const* priv_key = dynamic_cast<ECDSA_PrivateKey const*>(&key);

   if (priv_key == 0)
      {
      throw Invalid_Argument("CVC_EAC::create_self_signed_cert(): unsupported key type");
      }

   ASN1_Chr chr(opt.car.value());

   AlgorithmIdentifier sig_algo;
   std::string padding_and_hash(eac_cvc_emsa + "(" + opt.hash_alg + ")");
   sig_algo.oid = OIDS::lookup(priv_key->algo_name() + "/" + padding_and_hash);
   sig_algo = AlgorithmIdentifier(sig_algo.oid, AlgorithmIdentifier::USE_NULL_PARAM);

   std::auto_ptr<Botan::PK_Signer> signer(get_pk_signer(*priv_key, padding_and_hash));

#if 0 // FIXME
   std::auto_ptr<EAC1_1_CVC_Encoder> enc(priv_key->cvc_eac1_1_encoder());
   MemoryVector<byte> enc_public_key = enc->public_key(sig_algo);
#else
   MemoryVector<byte> enc_public_key;
#endif

   return EAC1_1_CVC_CA::make_cert(signer, enc_public_key, opt.car, chr, opt.holder_auth_templ, opt.ced, opt.cex, rng);

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
   std::string padding_and_hash(eac_cvc_emsa + "(" + hash_alg + ")");
   sig_algo.oid = OIDS::lookup(priv_key->algo_name() + "/" + padding_and_hash);
   sig_algo = AlgorithmIdentifier(sig_algo.oid, AlgorithmIdentifier::USE_NULL_PARAM);

   std::auto_ptr<Botan::PK_Signer> signer(get_pk_signer(*priv_key, padding_and_hash));

#if 0 // FIXME
   std::auto_ptr<EAC1_1_CVC_Encoder> enc(priv_key->cvc_eac1_1_encoder());
   MemoryVector<byte> enc_public_key = enc->public_key(sig_algo);
#else
   MemoryVector<byte> enc_public_key;
#endif

   MemoryVector<byte> enc_cpi;
   enc_cpi.append(0x00);
   MemoryVector<byte> tbs = DER_Encoder()
      .encode(enc_cpi, OCTET_STRING, ASN1_Tag(41), APPLICATION)
      .raw_bytes(enc_public_key)
      .encode(chr)
      .get_contents();

   MemoryVector<byte> signed_cert = EAC1_1_gen_CVC<EAC1_1_Req>::make_signed(signer, EAC1_1_gen_CVC<EAC1_1_Req>::build_cert_body(tbs), rng);
   std::tr1::shared_ptr<DataSource> source(new DataSource_Memory(signed_cert));
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
   std::auto_ptr<Botan::PK_Signer> signer(get_pk_signer(*priv_key, padding_and_hash));
   SecureVector<byte> tbs_bits = req.BER_encode();
   tbs_bits.append(DER_Encoder().encode(car).get_contents());
   MemoryVector<byte> signed_cert = EAC1_1_ADO::make_signed(signer, tbs_bits, rng);
   std::tr1::shared_ptr<DataSource> source(new DataSource_Memory(signed_cert));
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
   const u64bit current_time = system_time();

   opts.ced = ASN1_Ced(current_time);
   opts.cex = ASN1_Cex(opts.ced);
   opts.cex.add_months(cvca_validity_months);
   opts.holder_auth_templ = (CVCA | (iris * IRIS) | (fingerpr * FINGERPRINT));
   opts.hash_alg = hash;
   return Botan::CVC_EAC::create_self_signed_cert(*priv_key, opts, rng);
   }



EAC1_1_CVC link_cvca(EAC1_1_CVC const& signer,
                     Private_Key const& key,
                     EAC1_1_CVC const& signee,
                     RandomNumberGenerator& rng)
   {
   ECDSA_PrivateKey const* priv_key = dynamic_cast<ECDSA_PrivateKey const*>(&key);
   if (priv_key == 0)
      {
      throw Invalid_Argument("CVC_EAC::create_self_signed_cert(): unsupported key type");
      }
   ASN1_Ced ced(system_time());
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
      throw Invalid_Argument("link_cvca(): signature algorithms of signer and signee don´t match");
      }
   AlgorithmIdentifier sig_algo = signer.signature_algorithm();
   std::string padding_and_hash = padding_and_hash_from_oid(sig_algo.oid);
   std::auto_ptr<Botan::PK_Signer> pk_signer(get_pk_signer(*priv_key, padding_and_hash));
   std::auto_ptr<Public_Key> pk = signee.subject_public_key();
   ECDSA_PublicKey*  subj_pk = dynamic_cast<ECDSA_PublicKey*>(pk.get());
   subj_pk->set_parameter_encoding(ENC_EXPLICIT);

#if 0 // FIXME
   std::auto_ptr<EAC1_1_CVC_Encoder> enc(subj_pk->cvc_eac1_1_encoder());
   MemoryVector<byte> enc_public_key = enc->public_key(sig_algo);
#else
   MemoryVector<byte> enc_public_key;
#endif

   return EAC1_1_CVC_CA::make_cert(pk_signer, enc_public_key,
                                   signer.get_car(),
                                   signee.get_chr(),
                                   signer.get_chat_value(),
                                   ced,
                                   cex,
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
   chr_str.append(fixed_len_seqnr(seqnr, seqnr_len));
   ASN1_Chr chr(chr_str);
   std::string padding_and_hash = padding_and_hash_from_oid(signee.signature_algorithm().oid);
   std::auto_ptr<Botan::PK_Signer> pk_signer(get_pk_signer(*priv_key, padding_and_hash));
   std::auto_ptr<Public_Key> pk = signee.subject_public_key();
   ECDSA_PublicKey*  subj_pk = dynamic_cast<ECDSA_PublicKey*>(pk.get());
   std::auto_ptr<Public_Key> signer_pk = signer_cert.subject_public_key();

   // for the case that the domain parameters are not set...
   // (we use those from the signer because they must fit)
   subj_pk->set_domain_parameters(priv_key->domain_parameters());

   subj_pk->set_parameter_encoding(ENC_IMPLICITCA);

#if 0 // FIXME
   std::auto_ptr<EAC1_1_CVC_Encoder> enc(subj_pk->cvc_eac1_1_encoder());
   MemoryVector<byte> enc_public_key = enc->public_key(sig_algo);
#else
   MemoryVector<byte> enc_public_key;
#endif

   AlgorithmIdentifier sig_algo(signer_cert.signature_algorithm());
   const u64bit current_time = system_time();
   ASN1_Ced ced(current_time);
   u32bit chat_val;
   u32bit chat_low = signer_cert.get_chat_value() & 0x3; // take the chat rights from signer
   ASN1_Cex cex(ced);
   if ((signer_cert.get_chat_value() & CVCA) == CVCA)
      {
      // we sign a dvca
      cex.add_months(dvca_validity_months);
      if (domestic)
         {
         chat_val = DVCA_domestic | chat_low;
         }
      else
         {
         chat_val = DVCA_foreign | chat_low;
         }
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
   return EAC1_1_CVC_CA::make_cert(pk_signer, enc_public_key,
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
   key.set_parameter_encoding(ENC_IMPLICITCA);
   return Botan::CVC_EAC::create_cvc_req(key, chr, hash_alg, rng);
   }

} // namespace DE_EAC

}
