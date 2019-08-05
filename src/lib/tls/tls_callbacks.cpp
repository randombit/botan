/*
* TLS Callbacks
* (C) 2016 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_callbacks.h>
#include <botan/tls_policy.h>
#include <botan/tls_algos.h>
#include <botan/x509path.h>
#include <botan/ocsp.h>
#include <botan/dh.h>
#include <botan/ecdh.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/ct_utils.h>

#if defined(BOTAN_HAS_CURVE_25519)
  #include <botan/curve25519.h>
#endif

namespace Botan {

void TLS::Callbacks::tls_inspect_handshake_msg(const Handshake_Message&)
   {
   // default is no op
   }

std::string TLS::Callbacks::tls_server_choose_app_protocol(const std::vector<std::string>&)
   {
   return "";
   }

std::string TLS::Callbacks::tls_peer_network_identity()
   {
   return "";
   }

void TLS::Callbacks::tls_modify_extensions(Extensions&, Connection_Side)
   {
   }

void TLS::Callbacks::tls_examine_extensions(const Extensions&, Connection_Side)
   {
   }

std::string TLS::Callbacks::tls_decode_group_param(Group_Params group_param)
   {
   return group_param_to_string(group_param);
   }

void TLS::Callbacks::tls_verify_cert_chain(
   const std::vector<X509_Certificate>& cert_chain,
   const std::vector<std::shared_ptr<const OCSP::Response>>& ocsp_responses,
   const std::vector<Certificate_Store*>& trusted_roots,
   Usage_Type usage,
   const std::string& hostname,
   const TLS::Policy& policy)
   {
   if(cert_chain.empty())
      throw Invalid_Argument("Certificate chain was empty");

   Path_Validation_Restrictions restrictions(policy.require_cert_revocation_info(),
                                             policy.minimum_signature_strength());

   Path_Validation_Result result =
      x509_path_validate(cert_chain,
                         restrictions,
                         trusted_roots,
                         (usage == Usage_Type::TLS_SERVER_AUTH ? hostname : ""),
                         usage,
                         std::chrono::system_clock::now(),
                         tls_verify_cert_chain_ocsp_timeout(),
                         ocsp_responses);

   if(!result.successful_validation())
      {
      throw TLS_Exception(Alert::BAD_CERTIFICATE,
                          "Certificate validation failure: " + result.result_string());
      }
   }

std::vector<uint8_t> TLS::Callbacks::tls_sign_message(
   const Private_Key& key,
   RandomNumberGenerator& rng,
   const std::string& emsa,
   Signature_Format format,
   const std::vector<uint8_t>& msg)
   {
   PK_Signer signer(key, rng, emsa, format);

   return signer.sign_message(msg, rng);
   }

bool TLS::Callbacks::tls_verify_message(
   const Public_Key& key,
   const std::string& emsa,
   Signature_Format format,
   const std::vector<uint8_t>& msg,
   const std::vector<uint8_t>& sig)
   {
   PK_Verifier verifier(key, emsa, format);

   return verifier.verify_message(msg, sig);
   }

std::pair<secure_vector<uint8_t>, std::vector<uint8_t>> TLS::Callbacks::tls_dh_agree(
   const std::vector<uint8_t>& modulus,
   const std::vector<uint8_t>& generator,
   const std::vector<uint8_t>& peer_public_value,
   const Policy& policy,
   RandomNumberGenerator& rng)
   {
   BigInt p = BigInt::decode(modulus);
   BigInt g = BigInt::decode(generator);
   BigInt Y = BigInt::decode(peer_public_value);

   /*
    * A basic check for key validity. As we do not know q here we
    * cannot check that Y is in the right subgroup. However since
    * our key is ephemeral there does not seem to be any
    * advantage to bogus keys anyway.
    */
   if(Y <= 1 || Y >= p - 1)
      throw TLS_Exception(Alert::ILLEGAL_PARAMETER,
                          "Server sent bad DH key for DHE exchange");

   DL_Group group(p, g);

   if(!group.verify_group(rng, false))
      throw TLS_Exception(Alert::INSUFFICIENT_SECURITY,
                          "DH group validation failed");

   DH_PublicKey peer_key(group, Y);

   policy.check_peer_key_acceptable(peer_key);

   DH_PrivateKey priv_key(rng, group);
   PK_Key_Agreement ka(priv_key, rng, "Raw");
   secure_vector<uint8_t> dh_secret = CT::strip_leading_zeros(
      ka.derive_key(0, peer_key.public_value()).bits_of());

   return std::make_pair(dh_secret, priv_key.public_value());
   }

std::pair<secure_vector<uint8_t>, std::vector<uint8_t>> TLS::Callbacks::tls_ecdh_agree(
   const std::string& curve_name,
   const std::vector<uint8_t>& peer_public_value,
   const Policy& policy,
   RandomNumberGenerator& rng,
   bool compressed)
   {
   secure_vector<uint8_t> ecdh_secret;
   std::vector<uint8_t> our_public_value;

   if(curve_name == "x25519")
      {
#if defined(BOTAN_HAS_CURVE_25519)
      if(peer_public_value.size() != 32)
         {
         throw TLS_Exception(Alert::HANDSHAKE_FAILURE, "Invalid X25519 key size");
         }

      Curve25519_PublicKey peer_key(peer_public_value);
      policy.check_peer_key_acceptable(peer_key);
      Curve25519_PrivateKey priv_key(rng);
      PK_Key_Agreement ka(priv_key, rng, "Raw");
      ecdh_secret = ka.derive_key(0, peer_key.public_value()).bits_of();

      // X25519 is always compressed but sent as "uncompressed" in TLS
      our_public_value = priv_key.public_value();
#else
      throw Internal_Error("Negotiated X25519 somehow, but it is disabled");
#endif
      }
   else
      {
      EC_Group group(OID::from_string(curve_name));
      ECDH_PublicKey peer_key(group, group.OS2ECP(peer_public_value));
      policy.check_peer_key_acceptable(peer_key);
      ECDH_PrivateKey priv_key(rng, group);
      PK_Key_Agreement ka(priv_key, rng, "Raw");
      ecdh_secret = ka.derive_key(0, peer_key.public_value()).bits_of();
      our_public_value = priv_key.public_value(compressed ? PointGFp::COMPRESSED : PointGFp::UNCOMPRESSED);
      }

   return std::make_pair(ecdh_secret, our_public_value);
   }

}
