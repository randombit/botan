/*
* TPM 2.0 RSA Key Wrappres
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_rsa.h>

#include <botan/hash.h>
#include <botan/pk_ops.h>
#include <botan/rsa.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/emsa.h>
#include <botan/internal/fmt.h>
#include <botan/internal/pss_params.h>
#include <botan/internal/scan_name.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_algo_mappings.h>
#include <botan/internal/tpm2_hash.h>
#include <botan/internal/tpm2_util.h>

#include <tss2/tss2_esys.h>

namespace Botan::TPM2 {

Botan::RSA_PublicKey rsa_pubkey_from_tss2_public(const TPM2B_PUBLIC* public_area) {
   BOTAN_ASSERT_NONNULL(public_area);
   const auto& pub = public_area->publicArea;
   BOTAN_ARG_CHECK(pub.type == TPM2_ALG_RSA, "Public key is not an RSA key");

   // TPM2 may report 0 when the exponent is 'the default' (2^16 + 1)
   const auto exponent = (pub.parameters.rsaDetail.exponent == 0) ? 65537 : pub.parameters.rsaDetail.exponent;

   return Botan::RSA_PublicKey(BigInt(as_span(pub.unique.rsa)), exponent);
}

RSA_PublicKey::RSA_PublicKey(Object handle, SessionBundle session_bundle, const TPM2B_PUBLIC* public_blob) :
      Botan::TPM2::PublicKey(std::move(handle), std::move(session_bundle)),
      Botan::RSA_PublicKey(rsa_pubkey_from_tss2_public(public_blob)) {}

RSA_PrivateKey::RSA_PrivateKey(Object handle,
                               SessionBundle session_bundle,
                               const TPM2B_PUBLIC* public_blob,
                               std::span<const uint8_t> private_blob) :
      Botan::TPM2::PrivateKey(std::move(handle), std::move(session_bundle), private_blob),
      Botan::RSA_PublicKey(rsa_pubkey_from_tss2_public(public_blob)) {}

std::unique_ptr<TPM2::PrivateKey> RSA_PrivateKey::create_unrestricted_transient(const std::shared_ptr<Context>& ctx,
                                                                                const SessionBundle& sessions,
                                                                                std::span<const uint8_t> auth_value,
                                                                                const TPM2::PrivateKey& parent,
                                                                                uint16_t keylength,
                                                                                std::optional<uint32_t> exponent) {
   BOTAN_ARG_CHECK(parent.is_parent(), "The passed key cannot be used as a parent key");

   TPM2B_SENSITIVE_CREATE sensitive_data = {
      .size = 0,  // ignored
      .sensitive =
         {
            .userAuth = copy_into<TPM2B_AUTH>(auth_value),

            // Architecture Document, Section 25.2.3
            //   When an asymmetric key is created, the caller is not allowed to
            //   provide the sensitive data of the key.
            .data = init_empty<TPM2B_SENSITIVE_DATA>(),
         },
   };

   TPMT_PUBLIC key_template = {
      .type = TPM2_ALG_RSA,

      // This is the algorithm for fingerprinting the newly created public key.
      // For best compatibility we always use SHA-256.
      .nameAlg = TPM2_ALG_SHA256,

      // This sets up the key to be both a decryption and a signing key, forbids
      // its duplication (fixed_tpm, fixed_parent) and ensures that the key's
      // private portion can be used only by a user with an HMAC or password
      // session.
      .objectAttributes = ObjectAttributes::render({
         .fixed_tpm = true,
         .fixed_parent = true,
         .sensitive_data_origin = true,
         .user_with_auth = true,
         .decrypt = true,
         .sign_encrypt = true,
      }),

      // We currently do not support policy-based authorization
      .authPolicy = init_empty<TPM2B_DIGEST>(),
      .parameters =
         {
            .rsaDetail =
               {
                  // Structures Document (Part 2), Section 12.2.3.5
                  //   If the key is not a restricted decryption key, this field
                  //   shall be set to TPM_ALG_NULL.
                  //
                  // TODO: Once we stop supporting TSS < 4.0, we could use
                  //       `.keyBits = {.null = {}}, .mode = {.null = {}}`
                  //       which better reflects our intention here.
                  .symmetric =
                     {
                        .algorithm = TPM2_ALG_NULL,
                        .keyBits = {.sym = 0},
                        .mode = {.sym = TPM2_ALG_NULL},
                     },

                  // Structures Document (Part 2), Section 12.2.3.5
                  //   When both sign and decrypt are SET, restricted shall be
                  //   CLEAR and scheme shall be TPM_ALG_NULL
                  //
                  // TODO: Once we stop supporting TSS < 4.0, we could use
                  //       `.details = {.null = {}}`
                  //       which better reflects our intention here.
                  .scheme =
                     {
                        .scheme = TPM2_ALG_NULL,
                        .details = {.anySig = {.hashAlg = TPM2_ALG_NULL}},
                     },
                  .keyBits = keylength,
                  .exponent = exponent.value_or(0 /* default value - 2^16 + 1*/),
               },
         },

      // For creating an asymmetric key this value is not used.
      .unique = {.rsa = init_empty<TPM2B_PUBLIC_KEY_RSA>()},
   };

   return create_transient_from_template(
      ctx, sessions, parent.handles().transient_handle(), key_template, sensitive_data);
}

namespace {

struct SignatureAlgorithmSelection {
      TPMT_SIG_SCHEME signature_scheme;
      std::string hash_name;
      std::string padding;
};

SignatureAlgorithmSelection select_signature_algorithms(std::string_view padding) {
   const SCAN_Name req(padding);
   if(req.arg_count() == 0) {
      throw Invalid_Argument("RSA signing padding scheme must at least specify a hash function");
   }

   auto sig_scheme = rsa_signature_scheme_botan_to_tss2(padding);
   if(!sig_scheme) {
      throw Not_Implemented(Botan::fmt("RSA signing with padding scheme {}", padding));
   }

   return {
      .signature_scheme = sig_scheme.value(),
      .hash_name = req.arg(0),
      .padding = std::string(padding),
   };
}

/**
 * Signing with a restricted key requires a validation ticket that is provided
 * when hashing the data to sign on the TPM. Otherwise, it is fine to hash the
 * data in software.
 *
 * @param key_handle  the key to create the signature with
 * @param sessions    the sessions to use for the TPM operations
 * @param hash_name   the name of the hash function to use
 *
 * @return a HashFunction that hashes in hardware if the key is restricted
 */
std::unique_ptr<Botan::HashFunction> create_hash_function(const Object& key_handle,
                                                          const SessionBundle& sessions,
                                                          std::string_view hash_name) {
   if(key_handle.attributes(sessions).restricted) {
      // TODO: this could also be ENDORSEMENT or PLATFORM, and we're not 100% sure
      //       that OWNER is always the right choice here.
      const TPMI_RH_HIERARCHY hierarchy = ESYS_TR_RH_OWNER;
      return std::make_unique<HashFunction>(key_handle.context(), hash_name, hierarchy, sessions);
   } else {
      return Botan::HashFunction::create_or_throw(hash_name);
   }
}

/**
 * If the key is restricted, this will transparently use the TPM to hash the
 * data to obtain a validation ticket.
 *
 * TPM Library, Part 1: Architecture", Section 11.4.6.3 (4)
 *    This ticket is used to indicate that a digest of external data is safe to
 *    sign using a restricted signing key. A restricted signing key may only
 *    sign a digest that was produced by the TPM. [...] This prevents forgeries
 *    of attestation data.
 */
class RSA_Signature_Operation final : public PK_Ops::Signature {
   private:
      RSA_Signature_Operation(const Object& object,
                              const SessionBundle& sessions,
                              SignatureAlgorithmSelection algorithms) :
            m_key_handle(object),
            m_sessions(sessions),
            m_scheme(algorithms.signature_scheme),
            m_hash(create_hash_function(m_key_handle, m_sessions, algorithms.hash_name)),
            m_padding(std::move(algorithms.padding)) {
         BOTAN_ASSERT_NONNULL(m_hash);
      }

   public:
      RSA_Signature_Operation(const Object& object, const SessionBundle& sessions, std::string_view padding) :
            RSA_Signature_Operation(object, sessions, select_signature_algorithms(padding)) {}

      void update(std::span<const uint8_t> msg) override { m_hash->update(msg); }

      std::vector<uint8_t> sign(Botan::RandomNumberGenerator& /* rng */) override {
         if(auto hash = dynamic_cast<HashFunction*>(m_hash.get())) {
            // This is a TPM2-based hash object that calculated the digest on
            // the TPM. We can use the validation ticket to create the signature.
            auto [digest, validation] = hash->final_with_ticket();
            return create_signature(digest.get(), validation.get());
         } else {
            // This is a software hash, so we have to stub the validation ticket
            // and create the signature without it.
            TPMT_TK_HASHCHECK dummy_validation = {
               .tag = TPM2_ST_HASHCHECK,
               .hierarchy = TPM2_RH_NULL,
               .digest = init_empty<TPM2B_DIGEST>(),
            };

            auto digest = init_with_size<TPM2B_DIGEST>(m_hash->output_length());
            m_hash->final(as_span(digest));
            return create_signature(&digest, &dummy_validation);
         }
      }

      size_t signature_length() const override {
         return m_key_handle._public_info(m_sessions, TPM2_ALG_RSA).pub->publicArea.parameters.rsaDetail.keyBits / 8;
      }

      std::string hash_function() const override { return m_hash->name(); }

      AlgorithmIdentifier algorithm_identifier() const override {
         // TODO: This is essentially a copy of the ::algorithm_identifier()
         //       in `rsa.h`. We should probably refactor this into a common
         //       function.

         // This EMSA object actually isn't required, we just need it to
         // conveniently figure out the algorithm identifier.
         //
         // TODO: This is a hack, and we should clean this up.
         const auto emsa = EMSA::create_or_throw(m_padding);
         const std::string emsa_name = emsa->name();

         try {
            const std::string full_name = "RSA/" + emsa_name;
            const OID oid = OID::from_string(full_name);
            return AlgorithmIdentifier(oid, AlgorithmIdentifier::USE_EMPTY_PARAM);
         } catch(Lookup_Error&) {}

         if(emsa_name.starts_with("EMSA4(")) {
            auto parameters = PSS_Params::from_emsa_name(emsa_name).serialize();
            return AlgorithmIdentifier("RSA/EMSA4", parameters);
         }

         throw Not_Implemented("No algorithm identifier defined for RSA with " + emsa_name);
      }

   private:
      std::vector<uint8_t> create_signature(const TPM2B_DIGEST* digest, const TPMT_TK_HASHCHECK* validation) {
         unique_esys_ptr<TPMT_SIGNATURE> signature;
         check_rc("Esys_Sign",
                  Esys_Sign(*m_key_handle.context(),
                            m_key_handle.transient_handle(),
                            m_sessions[0],
                            m_sessions[1],
                            m_sessions[2],
                            digest,
                            &m_scheme,
                            validation,
                            out_ptr(signature)));

         BOTAN_ASSERT_NONNULL(signature);
         const auto& sig = [&]() -> TPMS_SIGNATURE_RSA& {
            if(signature->sigAlg == TPM2_ALG_RSASSA) {
               return signature->signature.rsassa;
            } else if(signature->sigAlg == TPM2_ALG_RSAPSS) {
               return signature->signature.rsapss;
            }

            throw Invalid_State(fmt("TPM2 returned an unexpected signature scheme {}", signature->sigAlg));
         }();

         BOTAN_ASSERT_NOMSG(sig.hash == m_scheme.details.any.hashAlg);

         return copy_into<std::vector<uint8_t>>(sig.sig);
      }

   private:
      const Object& m_key_handle;
      const SessionBundle& m_sessions;
      TPMT_SIG_SCHEME m_scheme;
      std::unique_ptr<Botan::HashFunction> m_hash;
      std::string m_padding;
};

/**
 * Signature verification on the TPM. This does not require a validation ticket,
 * therefore the hash is always calculated in software.
 */
class RSA_Verification_Operation final : public PK_Ops::Verification {
   private:
      RSA_Verification_Operation(const Object& object,
                                 const SessionBundle& sessions,
                                 const SignatureAlgorithmSelection& algorithms) :
            m_key_handle(object),
            m_sessions(sessions),
            m_scheme(algorithms.signature_scheme),
            m_hash(Botan::HashFunction::create_or_throw(algorithms.hash_name)) {}

   public:
      RSA_Verification_Operation(const Object& object, const SessionBundle& sessions, std::string_view padding) :
            RSA_Verification_Operation(object, sessions, select_signature_algorithms(padding)) {}

      void update(std::span<const uint8_t> msg) override { m_hash->update(msg); }

      bool is_valid_signature(std::span<const uint8_t> sig_data) override {
         auto digest = init_with_size<TPM2B_DIGEST>(m_hash->output_length());
         m_hash->final(as_span(digest));

         const auto signature = [&]() -> TPMT_SIGNATURE {
            TPMT_SIGNATURE sig;
            sig.sigAlg = m_scheme.scheme;
            sig.signature.any.hashAlg = m_scheme.details.any.hashAlg;

            if(sig.sigAlg == TPM2_ALG_RSASSA) {
               copy_into(sig.signature.rsassa.sig, sig_data);
            } else if(sig.sigAlg == TPM2_ALG_RSAPSS) {
               copy_into(sig.signature.rsapss.sig, sig_data);
            } else {
               throw Invalid_State(fmt("Requested an unexpected signature scheme {}", sig.sigAlg));
            }

            return sig;
         }();

         // If the signature is not valid, this returns TPM2_RC_SIGNATURE.
         const auto rc = check_rc_expecting<TPM2_RC_SIGNATURE>("Esys_VerifySignature",
                                                               Esys_VerifySignature(*m_key_handle.context(),
                                                                                    m_key_handle.transient_handle(),
                                                                                    m_sessions[0],
                                                                                    m_sessions[1],
                                                                                    m_sessions[2],
                                                                                    &digest,
                                                                                    &signature,
                                                                                    nullptr /* validation */));

         return rc == TPM2_RC_SUCCESS;
      }

      std::string hash_function() const override { return m_hash->name(); }

   private:
      const Object& m_key_handle;
      const SessionBundle& m_sessions;
      TPMT_SIG_SCHEME m_scheme;
      std::unique_ptr<Botan::HashFunction> m_hash;
};

TPMT_RSA_DECRYPT select_encryption_algorithms(std::string_view padding) {
   auto scheme = rsa_encryption_scheme_botan_to_tss2(padding);
   if(!scheme) {
      throw Not_Implemented(Botan::fmt("RSA encryption with padding scheme {}", padding));
   }
   return scheme.value();
}

class RSA_Encryption_Operation final : public PK_Ops::Encryption {
   public:
      RSA_Encryption_Operation(const Object& object, const SessionBundle& sessions, std::string_view padding) :
            m_key_handle(object), m_sessions(sessions), m_scheme(select_encryption_algorithms(padding)) {}

      std::vector<uint8_t> encrypt(std::span<const uint8_t> msg, Botan::RandomNumberGenerator& /* rng */) override {
         const auto plaintext = copy_into<TPM2B_PUBLIC_KEY_RSA>(msg);

         // TODO: Figure out what this is for. Given that I didn't see any other
         //       way to pass an EME-OAEP label, I'm guessing that this is what
         //       it is for. But I'm not sure.
         //
         // Again, a follow-up of https://github.com/randombit/botan/pull/4318
         // that targets async encryption will probably be quite helpful here.
         const auto label = init_empty<TPM2B_DATA>();

         unique_esys_ptr<TPM2B_PUBLIC_KEY_RSA> ciphertext;
         check_rc("Esys_RSA_Encrypt",
                  Esys_RSA_Encrypt(*m_key_handle.context(),
                                   m_key_handle.transient_handle(),
                                   m_sessions[0],
                                   m_sessions[1],
                                   m_sessions[2],
                                   &plaintext,
                                   &m_scheme,
                                   &label,
                                   out_ptr(ciphertext)));
         BOTAN_ASSERT_NONNULL(ciphertext);
         return copy_into<std::vector<uint8_t>>(*ciphertext);
      }

      // This duplicates quite a bit of domain knowledge about those RSA
      // EMEs. And I'm quite certain that I screwed up somewhere.
      //
      // TODO: See if we can somehow share the logic with the software
      //       RSA implementation and also PKCS#11 (which I believe is plain wrong).
      size_t max_input_bits() const override {
         const auto max_ptext_bytes =
            (m_key_handle._public_info(m_sessions, TPM2_ALG_RSA).pub->publicArea.parameters.rsaDetail.keyBits - 1) / 8;
         auto hash_output_bytes = [](TPM2_ALG_ID hash) -> size_t {
            switch(hash) {
               case TPM2_ALG_SHA1:
                  return 160 / 8;
               case TPM2_ALG_SHA256:
               case TPM2_ALG_SHA3_256:
                  return 256 / 8;
               case TPM2_ALG_SHA384:
               case TPM2_ALG_SHA3_384:
                  return 384 / 8;
               case TPM2_ALG_SHA512:
               case TPM2_ALG_SHA3_512:
                  return 512 / 8;
               default:
                  throw Invalid_State("Unexpected hash algorithm");
            }
         };

         const auto max_input_bytes = [&]() -> size_t {
            switch(m_scheme.scheme) {
               case TPM2_ALG_RSAES:
                  return max_ptext_bytes - 10;
               case TPM2_ALG_OAEP:
                  return max_ptext_bytes - 2 * hash_output_bytes(m_scheme.details.oaep.hashAlg) - 1;
               case TPM2_ALG_NULL:
                  return max_ptext_bytes;
               default:
                  throw Invalid_State("Unexpected RSA encryption scheme");
            }
         }();

         return max_input_bytes * 8;
      }

      size_t ciphertext_length(size_t /* ptext_len */) const override {
         return m_key_handle._public_info(m_sessions, TPM2_ALG_RSA).pub->publicArea.parameters.rsaDetail.keyBits - 1;
      }

   private:
      const Object& m_key_handle;
      const SessionBundle& m_sessions;
      TPMT_RSA_DECRYPT m_scheme;
};

class RSA_Decryption_Operation final : public PK_Ops::Decryption {
   public:
      RSA_Decryption_Operation(const Object& object, const SessionBundle& sessions, std::string_view padding) :
            m_key_handle(object), m_sessions(sessions), m_scheme(select_encryption_algorithms(padding)) {}

      secure_vector<uint8_t> decrypt(uint8_t& valid_mask, std::span<const uint8_t> input) override {
         const auto ciphertext = copy_into<TPM2B_PUBLIC_KEY_RSA>(input);
         const auto label = init_empty<TPM2B_DATA>();  // TODO: implement? see encrypt operation
         unique_esys_ptr<TPM2B_PUBLIC_KEY_RSA> plaintext;

         // TODO: I'm not sure that TPM2_RC_FAILURE is the right error code for
         //       all cases here. It passed the test (with a faulty ciphertext),
         //       but I didn't find this to be clearly documented. :-(
         auto rc = check_rc_expecting<TPM2_RC_FAILURE>("Esys_RSA_Decrypt",
                                                       Esys_RSA_Decrypt(*m_key_handle.context(),
                                                                        m_key_handle.transient_handle(),
                                                                        m_sessions[0],
                                                                        m_sessions[1],
                                                                        m_sessions[2],
                                                                        &ciphertext,
                                                                        &m_scheme,
                                                                        &label,
                                                                        out_ptr(plaintext)));

         valid_mask = CT::Mask<uint8_t>::is_equal(rc, TPM2_RC_SUCCESS).value();
         if(rc == TPM2_RC_SUCCESS) {
            BOTAN_ASSERT_NONNULL(plaintext);
            return copy_into<secure_vector<uint8_t>>(*plaintext);
         } else {
            return {};
         }
      }

      size_t plaintext_length(size_t /* ciphertext_length */) const override {
         return m_key_handle._public_info(m_sessions, TPM2_ALG_RSA).pub->publicArea.parameters.rsaDetail.keyBits / 8;
      }

   private:
      const Object& m_key_handle;
      const SessionBundle& m_sessions;
      TPMT_RSA_DECRYPT m_scheme;
};

}  // namespace

std::unique_ptr<PK_Ops::Verification> RSA_PublicKey::create_verification_op(std::string_view params,
                                                                            std::string_view provider) const {
   BOTAN_UNUSED(provider);
   return std::make_unique<RSA_Verification_Operation>(handles(), sessions(), params);
}

std::unique_ptr<PK_Ops::Signature> RSA_PrivateKey::create_signature_op(Botan::RandomNumberGenerator& rng,
                                                                       std::string_view params,
                                                                       std::string_view provider) const {
   BOTAN_UNUSED(rng, provider);
   return std::make_unique<RSA_Signature_Operation>(handles(), sessions(), params);
}

std::unique_ptr<PK_Ops::Encryption> RSA_PublicKey::create_encryption_op(Botan::RandomNumberGenerator& rng,
                                                                        std::string_view params,
                                                                        std::string_view provider) const {
   BOTAN_UNUSED(rng, provider);
   return std::make_unique<RSA_Encryption_Operation>(handles(), sessions(), params);
}

std::unique_ptr<PK_Ops::Decryption> RSA_PrivateKey::create_decryption_op(Botan::RandomNumberGenerator& rng,
                                                                         std::string_view params,
                                                                         std::string_view provider) const {
   BOTAN_UNUSED(rng, provider);
   return std::make_unique<RSA_Decryption_Operation>(handles(), sessions(), params);
}

}  // namespace Botan::TPM2
