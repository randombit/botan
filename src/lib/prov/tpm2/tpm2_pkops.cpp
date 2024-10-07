/*
* TPM 2.0 Public Key Operations
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tpm2_pkops.h>

#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_algo_mappings.h>
#include <botan/internal/tpm2_hash.h>

namespace Botan::TPM2 {

namespace {

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

}  // namespace

Signature_Operation::Signature_Operation(const Object& object,
                                         const SessionBundle& sessions,
                                         const SignatureAlgorithmSelection& algorithms) :
      Botan::TPM2::Signature_Operation_Base<PK_Ops::Signature>(
         object, sessions, algorithms, create_hash_function(object, sessions, algorithms.hash_name)) {}

std::vector<uint8_t> Signature_Operation::sign(Botan::RandomNumberGenerator& rng) {
   BOTAN_UNUSED(rng);

   auto do_sign = [this](const TPM2B_DIGEST& digest, const TPMT_TK_HASHCHECK& validation) {
      unique_esys_ptr<TPMT_SIGNATURE> signature;
      check_rc("Esys_Sign",
               Esys_Sign(*key_handle().context(),
                         key_handle().transient_handle(),
                         sessions()[0],
                         sessions()[1],
                         sessions()[2],
                         &digest,
                         &scheme(),
                         &validation,
                         out_ptr(signature)));
      BOTAN_ASSERT_NONNULL(signature);
      BOTAN_ASSERT_NOMSG(signature->sigAlg == scheme().scheme);
      BOTAN_ASSERT_NOMSG(signature->signature.any.hashAlg == scheme().details.any.hashAlg);
      return signature;
   };

   auto signature = [&] {
      if(auto h = dynamic_cast<HashFunction*>(hash())) {
         // This is a TPM2-based hash object that calculated the digest on
         // the TPM. We can use the validation ticket to create the signature.
         auto [digest, validation] = h->final_with_ticket();
         BOTAN_ASSERT_NONNULL(digest);
         BOTAN_ASSERT_NONNULL(validation);
         return do_sign(*digest, *validation);
      } else {
         // This is a software hash, so we have to stub the validation ticket
         // and create the signature without it.
         TPM2B_DIGEST digest;
         hash()->final(as_span(digest, hash()->output_length()));
         return do_sign(digest,
                        TPMT_TK_HASHCHECK{
                           .tag = TPM2_ST_HASHCHECK,
                           .hierarchy = TPM2_RH_NULL,
                           .digest = init_empty<TPM2B_DIGEST>(),
                        });
      }
   }();

   return marshal_signature(*signature);
}

Verification_Operation::Verification_Operation(const Object& object,
                                               const SessionBundle& sessions,
                                               const SignatureAlgorithmSelection& algorithms) :
      Signature_Operation_Base<PK_Ops::Verification>(
         object, sessions, algorithms, Botan::HashFunction::create_or_throw(algorithms.hash_name)) {}

bool Verification_Operation::is_valid_signature(std::span<const uint8_t> sig_data) {
   TPM2B_DIGEST digest;
   hash()->final(as_span(digest, hash()->output_length()));

   const auto signature = unmarshal_signature(sig_data);

   // If the signature is not valid, this returns TPM2_RC_SIGNATURE.
   const auto rc = check_rc_expecting<TPM2_RC_SIGNATURE>("Esys_VerifySignature",
                                                         Esys_VerifySignature(*key_handle().context(),
                                                                              key_handle().transient_handle(),
                                                                              sessions()[0],
                                                                              sessions()[1],
                                                                              sessions()[2],
                                                                              &digest,
                                                                              &signature,
                                                                              nullptr /* validation */));

   return rc == TPM2_RC_SUCCESS;
}

}  // namespace Botan::TPM2
