/*
* TPM 2 TSS crypto callbacks backend
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tpm2_crypto_backend_impl.h>

#include <botan/cipher_mode.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/mem_ops.h>
#include <botan/pubkey.h>
#include <botan/tpm2_context.h>
#include <botan/tpm2_crypto_backend.h>
#include <botan/tpm2_key.h>

#if defined(BOTAN_HAS_RSA)
   #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_ECDH)
   #include <botan/ecdh.h>
#endif

#include <botan/internal/eme.h>
#include <botan/internal/fmt.h>
#include <botan/internal/tpm2_algo_mappings.h>
#include <botan/internal/tpm2_util.h>

#if defined(BOTAN_HAS_EME_OAEP)
   #include <botan/internal/oaep.h>
#endif

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>

#include <variant>

#if defined(BOTAN_TSS2_SUPPORTS_CRYPTO_CALLBACKS)

namespace {

/// Holds the hash state between update callback invocations
using DigestObject =
   std::variant<std::unique_ptr<Botan::HashFunction>, std::unique_ptr<Botan::MessageAuthenticationCode>>;

}  // namespace

extern "C" {

/**
 * Some ESYS crypto callbacks require to hold state between calls.
 * This struct is forward-declared in tss2_esys.h and we're implementing it here.
 */
typedef struct ESYS_CRYPTO_CONTEXT_BLOB {
      DigestObject ctx;
} DigestCallbackState;

}  // extern "C"

namespace {

/// Safely converts the @p blob to a Botan crypto object of type @p T.
template <typename T>
   requires std::constructible_from<DigestObject, std::unique_ptr<T>>
[[nodiscard]] std::optional<std::reference_wrapper<T>> get(DigestCallbackState* blob) noexcept {
   if(!blob) {
      return std::nullopt;
   }

   if(!std::holds_alternative<std::unique_ptr<T>>(blob->ctx)) {
      return std::nullopt;
   }

   return {std::ref(*std::get<std::unique_ptr<T>>(blob->ctx))};
}

template <typename T>
   requires std::constructible_from<DigestObject, std::unique_ptr<T>>
[[nodiscard]] std::optional<std::reference_wrapper<T>> get(DigestCallbackState** blob) noexcept {
   if(!blob) {
      return std::nullopt;
   }

   return get<T>(*blob);
}

/// Safely converts the @p userdata to the Botan crypto context object.
[[nodiscard]] std::optional<std::reference_wrapper<Botan::TPM2::CryptoCallbackState>> get(void* userdata) noexcept {
   if(!userdata) {
      return std::nullopt;
   }

   auto ccs = reinterpret_cast<Botan::TPM2::CryptoCallbackState*>(userdata);
   if(!ccs) {
      return std::nullopt;
   }

   return *ccs;
}

/**
 * Wraps the Botan-specific implementations of the TSS crypto callbacks into a
 * try-catch block and converts encountered exceptions to TSS2_RC error codes as
 * needed.
 */
template <std::invocable<> F>
   requires std::same_as<std::invoke_result_t<F>, TSS2_RC>
[[nodiscard]] TSS2_RC thunk(F f) noexcept {
   try {
      return f();
   } catch(const Botan::Invalid_Argument&) {
      return TSS2_ESYS_RC_BAD_VALUE;
   } catch(const Botan::Invalid_State&) {
      return TSS2_ESYS_RC_BAD_SEQUENCE;
   } catch(const Botan::Lookup_Error&) {
      return TSS2_ESYS_RC_NOT_IMPLEMENTED;
   } catch(const Botan::Invalid_Authentication_Tag&) {
      return TSS2_ESYS_RC_MALFORMED_RESPONSE;
   } catch(const Botan::Exception&) {
      return TSS2_ESYS_RC_GENERAL_FAILURE;
   } catch(...) {
      return TSS2_ESYS_RC_GENERAL_FAILURE;
   }
}

/**
 * Encrypts or decrypts @p data using the symmetric cipher specified.
 * The bytes in @p data are encrypted/decrypted in-place.
 */
[[nodiscard]] TSS2_RC symmetric_algo(Botan::Cipher_Dir direction,
                                     const uint8_t* key,
                                     TPM2_ALG_ID tpm_sym_alg,
                                     TPMI_AES_KEY_BITS key_bits,
                                     TPM2_ALG_ID tpm_mode,
                                     uint8_t* buffer,
                                     size_t buffer_size,
                                     const uint8_t* iv) noexcept {
   return thunk([&] {
      if(!key) {
         return (direction == Botan::Cipher_Dir::Encryption) ? TSS2_ESYS_RC_NO_ENCRYPT_PARAM
                                                             : TSS2_ESYS_RC_NO_DECRYPT_PARAM;
      }

      // nullptr buffer with size 0 is alright
      if(!buffer && buffer_size != 0) {
         return TSS2_ESYS_RC_BAD_VALUE;
      }

      const auto cipher_name = Botan::TPM2::cipher_tss2_to_botan({
         .algorithm = tpm_sym_alg,
         .keyBits = {.sym = key_bits},
         .mode = {.sym = tpm_mode},
      });
      if(!cipher_name) {
         return TSS2_ESYS_RC_NOT_SUPPORTED;
      }

      auto cipher = Botan::Cipher_Mode::create(cipher_name.value(), direction);
      if(!cipher) {
         return TSS2_ESYS_RC_NOT_IMPLEMENTED;
      }

      // AEADs aren't supported by the crypto callback API, as there's
      // no way to append the authentication tag to the ciphertext.
      if(cipher->authenticated()) {
         return TSS2_ESYS_RC_INSUFFICIENT_BUFFER;
      }

      BOTAN_ASSERT_NOMSG(key_bits % 8 == 0);
      const size_t keylength = static_cast<size_t>(key_bits) / 8;
      if(!cipher->valid_keylength(keylength)) {
         return TSS2_ESYS_RC_BAD_VALUE;
      }

      const auto s_data = std::span{buffer, buffer_size};
      const auto s_key = std::span{key, keylength};
      const auto s_iv = [&]() -> std::span<const uint8_t> {
         if(iv) {
            return {iv, cipher->default_nonce_length()};
         } else {
            return {};
         }
      }();

      cipher->set_key(s_key);
      cipher->start(s_iv);
      cipher->process(s_data);
      return TSS2_RC_SUCCESS;
   });
}

extern "C" {

/** Provide the context for the computation of a hash digest.
 *
 * The context will be created and initialized according to the hash function.
 * @param[out] context The created context (callee-allocated).
 * @param[in] hash_alg The hash algorithm for the creation of the context.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC hash_start(ESYS_CRYPTO_CONTEXT_BLOB** context, TPM2_ALG_ID hash_alg, void* userdata) {
   BOTAN_UNUSED(userdata);
   return thunk([&] {
      if(!context) {
         return TSS2_ESYS_RC_BAD_REFERENCE;
      }

      const auto hash_name = Botan::TPM2::hash_algo_tss2_to_botan(hash_alg);
      if(!hash_name) {
         return TSS2_ESYS_RC_NOT_SUPPORTED;
      }

      auto hash = Botan::HashFunction::create(hash_name.value());
      if(!hash) {
         return TSS2_ESYS_RC_NOT_IMPLEMENTED;
      }

      // Will be deleted in hash_abort() or hash_finish()
      *context = new DigestCallbackState{std::move(hash)};
      return TSS2_RC_SUCCESS;
   });
}

/** Update the digest value of a digest object from a byte buffer.
 *
 * The context of a digest object will be updated according to the hash
 * algorithm of the context. <
 * @param[in,out] context The context of the digest object which will be updated.
 * @param[in] buffer The data for the update.
 * @param[in] size The size of the data buffer.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC hash_update(ESYS_CRYPTO_CONTEXT_BLOB* context, const uint8_t* buffer, size_t size, void* userdata) {
   BOTAN_UNUSED(userdata);
   return thunk([&] {
      const auto hash = get<Botan::HashFunction>(context);
      if(!hash) {
         return TSS2_ESYS_RC_BAD_REFERENCE;
      }

      // nullptr buffer with size 0 is alright
      if(!buffer && size != 0) {
         return TSS2_ESYS_RC_BAD_VALUE;
      }

      hash->get().update(std::span{buffer, size});
      return TSS2_RC_SUCCESS;
   });
}

/** Get the digest value of a digest object and close the context.
 *
 * The digest value will written to a passed buffer and the resources of the
 * digest object are released.
 * @param[in,out] context The context of the digest object to be released
 * @param[out] buffer The buffer for the digest value (caller-allocated).
 * @param[out] size The size of the digest.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC hash_finish(ESYS_CRYPTO_CONTEXT_BLOB** context, uint8_t* buffer, size_t* size, void* userdata) {
   BOTAN_UNUSED(userdata);
   if(size != nullptr) {
      *size = 0;
   }

   return thunk([&] {
      auto hash = get<Botan::HashFunction>(context);
      if(!hash || !buffer) {
         return TSS2_ESYS_RC_BAD_REFERENCE;
      }

      const auto digest_size = hash->get().output_length();
      hash->get().final(std::span{buffer, digest_size});
      if(size != nullptr) {
         *size = digest_size;
      }

      delete *context;  // allocated in hash_start()
      *context = nullptr;
      return TSS2_RC_SUCCESS;
   });
}

/** Release the resources of a digest object.
 *
 * The assigned resources will be released and the context will be set to NULL.
 * @param[in,out] context The context of the digest object.
 * @param[in,out] userdata information.
 */
void hash_abort(ESYS_CRYPTO_CONTEXT_BLOB** context, void* userdata) {
   BOTAN_UNUSED(userdata);
   if(context) {
      delete *context;  // allocated in hash_start()
      *context = nullptr;
   }
}

/** Provide the context an HMAC digest object from a byte buffer key.
 *
 * The context will be created and initialized according to the hash function
 * and the used HMAC key.
 * @param[out] context The created context (callee-allocated).
 * @param[in] hash_alg The hash algorithm for the HMAC computation.
 * @param[in] key The byte buffer of the HMAC key.
 * @param[in] size The size of the HMAC key.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC hmac_start(
   ESYS_CRYPTO_CONTEXT_BLOB** context, TPM2_ALG_ID hash_alg, const uint8_t* key, size_t size, void* userdata) {
   BOTAN_UNUSED(userdata);
   return thunk([&] {
      if(!context || !key) {
         return TSS2_ESYS_RC_BAD_REFERENCE;
      }

      const auto hash_name = Botan::TPM2::hash_algo_tss2_to_botan(hash_alg);
      if(!hash_name) {
         return TSS2_ESYS_RC_NOT_SUPPORTED;
      }

      auto hmac = Botan::MessageAuthenticationCode::create(Botan::fmt("HMAC({})", hash_name.value()));
      if(!hmac) {
         return TSS2_ESYS_RC_NOT_IMPLEMENTED;
      }

      hmac->set_key(std::span{key, size});

      // Will be deleted in hmac_abort() or hmac_finish()
      *context = new DigestCallbackState{std::move(hmac)};
      return TSS2_RC_SUCCESS;
   });
}

/** Update and HMAC digest value from a byte buffer.
 *
 * The context of a digest object will be updated according to the hash
 * algorithm and the key of the context.
 * @param[in,out] context The context of the digest object which will be updated.
 * @param[in] buffer The data for the update.
 * @param[in] size The size of the data buffer.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC hmac_update(ESYS_CRYPTO_CONTEXT_BLOB* context, const uint8_t* buffer, size_t size, void* userdata) {
   BOTAN_UNUSED(userdata);
   return thunk([&] {
      auto hmac = get<Botan::MessageAuthenticationCode>(context);
      if(!hmac) {
         return TSS2_ESYS_RC_BAD_REFERENCE;
      }

      // nullptr buffer with size 0 is alright
      if(!buffer && size != 0) {
         return TSS2_ESYS_RC_BAD_VALUE;
      }

      hmac->get().update(std::span{buffer, size});
      return TSS2_RC_SUCCESS;
   });
}

/** Write the HMAC digest value to a byte buffer and close the context.
 *
 * The digest value will written to a passed buffer and the resources of the
 * HMAC object are released.
 * @param[in,out] context The context of the HMAC object.
 * @param[out] buffer The buffer for the digest value (caller-allocated).
 * @param[out] size The size of the digest.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC hmac_finish(ESYS_CRYPTO_CONTEXT_BLOB** context, uint8_t* buffer, size_t* size, void* userdata) {
   BOTAN_UNUSED(userdata);
   if(size != nullptr) {
      *size = 0;
   }

   return thunk([&] {
      auto hmac = get<Botan::MessageAuthenticationCode>(context);
      if(!hmac || !buffer) {
         return TSS2_ESYS_RC_BAD_REFERENCE;
      }

      const auto digest_size = hmac->get().output_length();
      hmac->get().final(std::span{buffer, digest_size});
      if(size != nullptr) {
         *size = digest_size;
      }

      delete *context;  // allocated in hmac_start()
      *context = nullptr;
      return TSS2_RC_SUCCESS;
   });
}

/** Release the resources of an HMAC object.
 *
 * The assigned resources will be released and the context will be set to NULL.
 * @param[in,out] context The context of the HMAC object.
 * @param[in,out] userdata information.
 */
void hmac_abort(ESYS_CRYPTO_CONTEXT_BLOB** context, void* userdata) {
   BOTAN_UNUSED(userdata);
   if(context) {
      delete *context;  // allocated in hmac_start()
      *context = nullptr;
   }
}

/** Compute random TPM2B data.
 *
 * The random data will be generated and written to a passed TPM2B structure.
 * @param[out] nonce The TPM2B structure for the random data (caller-allocated).
 * @param[in] num_bytes The number of bytes to be generated.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval USER_DEFINED user defined errors on failure.
 * @note: the TPM should not be used to obtain the random data
 */
TSS2_RC get_random2b(TPM2B_NONCE* nonce, size_t num_bytes, void* userdata) {
   return thunk([&] {
      auto ccs = get(userdata);
      if(!ccs || !ccs->get().rng || !nonce) {
         return TSS2_ESYS_RC_BAD_REFERENCE;
      }

      ccs->get().rng->randomize(Botan::TPM2::as_span(*nonce, num_bytes));
      return TSS2_RC_SUCCESS;
   });
}

/** Encryption of a buffer using a public (RSA) key.
 *
 * Encrypting a buffer using a public key is used for example during
 * Esys_StartAuthSession in order to encrypt the salt value.
 * @param[in] pub_tpm_key The key to be used for encryption.
 * @param[in] in_size The size of the buffer to be encrypted.
 * @param[in] in_buffer The data buffer to be encrypted.
 * @param[in] max_out_size The maximum size for the output encrypted buffer.
 * @param[out] out_buffer The encrypted buffer.
 * @param[out] out_size The size of the encrypted output.
 * @param[in] label The label used in the encryption scheme.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC rsa_pk_encrypt(TPM2B_PUBLIC* pub_tpm_key,
                       size_t in_size,
                       BYTE* in_buffer,
                       size_t max_out_size,
                       BYTE* out_buffer,
                       size_t* out_size,
                       const char* label,
                       void* userdata) {
   if(out_size != nullptr) {
      *out_size = 0;
   }

   // TODO: This is currently a dumpster fire of code duplication and
   //       YOLO manual padding.
   //
   //       I'm hoping that a follow-up of Jack's work will help clean
   //       this up. See the extensive discussions in:
   //
   //       https://github.com/randombit/botan/pull/4318#issuecomment-2297682058
   #if defined(BOTAN_HAS_RSA)
   auto create_eme = [&](
                        const TPMT_RSA_SCHEME& scheme,
                        [[maybe_unused]] TPM2_ALG_ID name_algo,
                        [[maybe_unused]] TPMU_ASYM_SCHEME scheme_detail) -> std::optional<std::unique_ptr<Botan::EME>> {
      // OAEP is more complex by requiring a hash function and an optional
      // label. To avoid marshalling this into Botan's algorithm descriptor
      // we create an OAEP instance manually.
      auto create_oaep = [&]() -> std::optional<std::unique_ptr<Botan::EME>> {
      #if defined(BOTAN_HAS_EME_OAEP)
         // TPM Library, Part 1: Architecture, Annex B.4
         //    The RSA key's scheme hash algorithm (or, if it is TPM_ALG_NULL,
         //    the RSA key's Name algorithm) is used to compute H(label).
         const auto label_hash = Botan::TPM2::hash_algo_tss2_to_botan(
            (scheme_detail.oaep.hashAlg == TPM2_ALG_NULL || scheme_detail.oaep.hashAlg == TPM2_ALG_ERROR)
               ? pub_tpm_key->publicArea.nameAlg
               : scheme_detail.oaep.hashAlg);

         // TPM Library, Part 1: Architecture, Annex B.4
         //    The mask-generation function uses the Name algorithm of the RSA
         //    key as the hash algorithm.
         const auto mgf1_hash = Botan::TPM2::hash_algo_tss2_to_botan(name_algo);
         if(!label_hash || !mgf1_hash) {
            return std::nullopt;  // -> not supported
         }

         auto H_label = Botan::HashFunction::create(label_hash.value());
         auto H_mgf1 = Botan::HashFunction::create(mgf1_hash.value());
         if(!H_label || !H_mgf1) {
            return nullptr;  // -> not implemented
         }

         // TPM Library, Part 1: Architecture, Annex B.4
         //    [...] is used to compute lhash := H(label), and the null
         //    termination octet is included in the digest.
         std::string_view label_with_zero_terminator{label, std::strlen(label) + 1};
         return std::make_unique<Botan::OAEP>(std::move(H_label), std::move(H_mgf1), label_with_zero_terminator);
      #else
         BOTAN_UNUSED(label);
         return nullptr;  // -> not implemented
      #endif
      };

      try {  // EME::create throws if algorithm is not available
         switch(scheme.scheme) {
            case TPM2_ALG_OAEP:
               return create_oaep();
            case TPM2_ALG_NULL:
               return Botan::EME::create("Raw");
            case TPM2_ALG_RSAES:
               return Botan::EME::create("PKCS1v15");
            default:
               return std::nullopt;  // -> not supported
         }
      } catch(const Botan::Algorithm_Not_Found&) {
         /* ignore */
      }

      return nullptr;  // -> not implemented (EME::create() threw)
   };

   return thunk([&] {
      auto ccs = get(userdata);
      if(!ccs || !pub_tpm_key || !in_buffer || !out_buffer || !ccs->get().rng) {
         return TSS2_ESYS_RC_BAD_REFERENCE;
      }

      Botan::RandomNumberGenerator& rng = *ccs->get().rng;

      BOTAN_ASSERT_NOMSG(pub_tpm_key->publicArea.type == TPM2_ALG_RSA);

      const auto maybe_eme = create_eme(pub_tpm_key->publicArea.parameters.rsaDetail.scheme,
                                        pub_tpm_key->publicArea.nameAlg,
                                        pub_tpm_key->publicArea.parameters.rsaDetail.scheme.details);
      if(!maybe_eme.has_value()) {
         return TSS2_ESYS_RC_NOT_SUPPORTED;
      }

      const auto& eme = maybe_eme.value();
      if(!eme) {
         return TSS2_ESYS_RC_NOT_IMPLEMENTED;
      }

      // The code below is duplicated logic with Botan's PK_Encryptor_EME.
      // Currently, there's no way to instantiate the encryptor without
      // marshalling the optional `label` into Botan's algorithm name.
      //
      // The label contains characters that are not allowed in Botan's string-
      // based algorithm names, namely the \0 terminator. We currently handle
      // the padding manually and then encrypt the padded data with raw RSA.
      //
      // TODO: Provide a way to instantiate an PK_Encryptor_EME that accepts a
      //       pre-made EME object. See: https://github.com/randombit/botan/pull/4318

      const auto pubkey = Botan::TPM2::rsa_pubkey_from_tss2_public(pub_tpm_key);
      const auto keybits = pubkey.key_length();
      const auto output_size = keybits / 8;
      if(eme->maximum_input_size(keybits) < in_size) {
         return TSS2_ESYS_RC_BAD_VALUE;
      }

      if(output_size > max_out_size) {
         return TSS2_ESYS_RC_INSUFFICIENT_BUFFER;
      }

      const auto max_raw_bits = keybits - 1;
      const auto max_raw_bytes = (max_raw_bits + 7) / 8;
      const auto padded_bytes = eme->pad({out_buffer, max_raw_bytes}, {in_buffer, in_size}, max_raw_bits, rng);

      // PK_Encryptor_EME does not provide a way to pass in an output buffer.
      // TODO: provide an `.encrypt()` overload that accepts an output buffer.
      Botan::PK_Encryptor_EME encryptor(pubkey, rng, "Raw");
      const auto encrypted = encryptor.encrypt({out_buffer, padded_bytes}, rng);
      BOTAN_DEBUG_ASSERT(encrypted.size() == output_size);

      // We abused the `out_buffer` to hold the result of the padding. Hence, we
      // now have to copy the encrypted data over the padded plaintext data.
      Botan::copy_mem(std::span{out_buffer, encrypted.size()}, encrypted);
      if(out_size != nullptr) {
         *out_size = encrypted.size();
      }

      return TSS2_RC_SUCCESS;
   });
   #else
   BOTAN_UNUSED(pub_tpm_key, in_size, in_buffer, max_out_size, out_buffer, label, userdata);
   return TSS2_ESYS_RC_NOT_IMPLEMENTED;
   #endif
}

/** Computation of an ephemeral ECC key and shared secret Z.
 *
 * According to the description in TPM spec part 1 C 6.1 a shared secret
 * between application and TPM is computed (ECDH). An ephemeral ECC key and a
 * TPM key are used for the ECDH key exchange.
 * @param[in] key The key to be used for ECDH key exchange.
 * @param[in] max_out_size the max size for the output of the public key of the
 *            computed ephemeral key.
 * @param[out] Z The computed shared secret.
 * @param[out] Q The public part of the ephemeral key in TPM format.
 * @param[out] out_buffer The public part of the ephemeral key will be marshaled
 *             to this buffer.
 * @param[out] out_size The size of the marshaled output.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC get_ecdh_point(TPM2B_PUBLIC* key,
                       size_t max_out_size,
                       TPM2B_ECC_PARAMETER* Z,
                       TPMS_ECC_POINT* Q,
                       BYTE* out_buffer,
                       size_t* out_size,
                       void* userdata) {
   if(out_size != nullptr) {
      *out_size = 0;
   }

   #if defined(BOTAN_HAS_ECDH)
   return thunk([&] {
      auto ccs = get(userdata);
      if(!ccs || !key || !Z || !Q || !out_buffer | !ccs->get().rng) {
         return TSS2_ESYS_RC_BAD_REFERENCE;
      }

      Botan::RandomNumberGenerator& rng = *ccs->get().rng;

      // 1: Get TPM public key
      const auto [tpm_ec_group, tpm_ec_point] = Botan::TPM2::ecc_pubkey_from_tss2_public(key);
      const auto tpm_sw_pubkey = Botan::ECDH_PublicKey(tpm_ec_group, tpm_ec_point.to_legacy_point());

      const auto curve_order_byte_size = tpm_sw_pubkey.domain().get_p_bytes();

      // 2: Generate ephemeral key
      const auto eph_key = Botan::ECDH_PrivateKey(rng, tpm_sw_pubkey.domain());

      // Serialize public key coordinates into TPM2B_ECC_PARAMETER with Big Endian encoding.
      // This ensures bn_{x,y}.bytes() <= curve_order_byte_size.
      const auto& eph_pub_point = eph_key._public_ec_point();
      eph_pub_point.serialize_x_to(Botan::TPM2::as_span(Q->x, curve_order_byte_size));
      eph_pub_point.serialize_y_to(Botan::TPM2::as_span(Q->y, curve_order_byte_size));

      // 3: ECDH Key Agreement
      Botan::PK_Key_Agreement ecdh(eph_key, rng, "Raw" /*No KDF used here*/);
      const auto shared_secret = ecdh.derive_key(0 /*Ignored for raw KDF*/, tpm_sw_pubkey.public_value()).bits_of();

      Botan::TPM2::copy_into(*Z, shared_secret);

      Botan::TPM2::check_rc("Tss2_MU_TPMS_ECC_POINT_Marshal",
                            Tss2_MU_TPMS_ECC_POINT_Marshal(Q, out_buffer, max_out_size, out_size));

      return TSS2_RC_SUCCESS;
   });
   #else
   BOTAN_UNUSED(key, max_out_size, Z, Q, out_buffer, userdata);
   return TSS2_ESYS_RC_NOT_IMPLEMENTED;
   #endif
}

/** Encrypt data with AES.
 *
 * @param[in] key key used for AES.
 * @param[in] tpm_sym_alg AES type in TSS2 notation (must be TPM2_ALG_AES).
 * @param[in] key_bits Key size in bits.
 * @param[in] tpm_mode Block cipher mode of opertion in TSS2 notation (CFB).
 *            For parameter encryption only CFB can be used.
 * @param[in,out] buffer Data to be encrypted. The encrypted date will be stored
 *                in this buffer.
 * @param[in] buffer_size size of data to be encrypted.
 * @param[in] iv The initialization vector.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC aes_encrypt(uint8_t* key,
                    TPM2_ALG_ID tpm_sym_alg,
                    TPMI_AES_KEY_BITS key_bits,
                    TPM2_ALG_ID tpm_mode,
                    uint8_t* buffer,
                    size_t buffer_size,
                    uint8_t* iv,
                    void* userdata) {
   BOTAN_UNUSED(userdata);
   if(tpm_sym_alg != TPM2_ALG_AES) {
      return TSS2_ESYS_RC_BAD_VALUE;
   }

   return symmetric_algo(Botan::Cipher_Dir::Encryption, key, tpm_sym_alg, key_bits, tpm_mode, buffer, buffer_size, iv);
}

/** Decrypt data with AES.
 *
 * @param[in] key key used for AES.
 * @param[in] tpm_sym_alg AES type in TSS2 notation (must be TPM2_ALG_AES).
 * @param[in] key_bits Key size in bits.
 * @param[in] tpm_mode Block cipher mode of opertion in TSS2 notation (CFB).
 *            For parameter encryption only CFB can be used.
 * @param[in,out] buffer Data to be decrypted. The decrypted date will be stored
 *                in this buffer.
 * @param[in] buffer_size size of data to be encrypted.
 * @param[in] iv The initialization vector.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC aes_decrypt(uint8_t* key,
                    TPM2_ALG_ID tpm_sym_alg,
                    TPMI_AES_KEY_BITS key_bits,
                    TPM2_ALG_ID tpm_mode,
                    uint8_t* buffer,
                    size_t buffer_size,
                    uint8_t* iv,
                    void* userdata) {
   BOTAN_UNUSED(userdata);
   if(tpm_sym_alg != TPM2_ALG_AES) {
      return TSS2_ESYS_RC_BAD_VALUE;
   }

   return symmetric_algo(Botan::Cipher_Dir::Decryption, key, tpm_sym_alg, key_bits, tpm_mode, buffer, buffer_size, iv);
}

   #if defined(BOTAN_TSS2_SUPPORTS_SM4_IN_CRYPTO_CALLBACKS)

/** Encrypt data with SM4.
 *
 * @param[in] key key used for SM4.
 * @param[in] tpm_sym_alg SM4 type in TSS2 notation (must be TPM2_ALG_SM4).
 * @param[in] key_bits Key size in bits.
 * @param[in] tpm_mode Block cipher mode of opertion in TSS2 notation (CFB).
 *            For parameter encryption only CFB can be used.
 * @param[in,out] buffer Data to be encrypted. The encrypted date will be stored
 *                in this buffer.
 * @param[in] buffer_size size of data to be encrypted.
 * @param[in] iv The initialization vector.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC sm4_encrypt(uint8_t* key,
                    TPM2_ALG_ID tpm_sym_alg,
                    TPMI_SM4_KEY_BITS key_bits,
                    TPM2_ALG_ID tpm_mode,
                    uint8_t* buffer,
                    size_t buffer_size,
                    uint8_t* iv,
                    void* userdata) {
   BOTAN_UNUSED(userdata);
   if(tpm_sym_alg != TPM2_ALG_SM4) {
      return TSS2_ESYS_RC_BAD_VALUE;
   }

   return symmetric_algo(Botan::Cipher_Dir::Encryption, key, tpm_sym_alg, key_bits, tpm_mode, buffer, buffer_size, iv);
}

/** Decrypt data with SM4.
 *
 * @param[in] key key used for SM4.
 * @param[in] tpm_sym_alg SM4 type in TSS2 notation (must be TPM2_ALG_SM4).
 * @param[in] key_bits Key size in bits.
 * @param[in] tpm_mode Block cipher mode of opertion in TSS2 notation (CFB).
 *            For parameter encryption only CFB can be used.
 * @param[in,out] buffer Data to be decrypted. The decrypted date will be stored
 *                in this buffer.
 * @param[in] buffer_size size of data to be encrypted.
 * @param[in] iv The initialization vector.
 * @param[in,out] userdata information.
 * @retval TSS2_RC_SUCCESS on success
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC sm4_decrypt(uint8_t* key,
                    TPM2_ALG_ID tpm_sym_alg,
                    TPMI_SM4_KEY_BITS key_bits,
                    TPM2_ALG_ID tpm_mode,
                    uint8_t* buffer,
                    size_t buffer_size,
                    uint8_t* iv,
                    void* userdata) {
   BOTAN_UNUSED(userdata);
   if(tpm_sym_alg != TPM2_ALG_SM4) {
      return TSS2_ESYS_RC_BAD_VALUE;
   }

   return symmetric_algo(Botan::Cipher_Dir::Decryption, key, tpm_sym_alg, key_bits, tpm_mode, buffer, buffer_size, iv);
}

   #endif /* TPM2_ALG_SM4 */

/** Initialize crypto backend.
 *
 * Initialize internal tables of crypto backend.
 *
 * @param[in,out] userdata Optional userdata pointer.
 *
 * @retval TSS2_RC_SUCCESS ong success.
 * @retval USER_DEFINED user defined errors on failure.
 */
TSS2_RC init(void* userdata) {
   BOTAN_UNUSED(userdata);
   return TSS2_RC_SUCCESS;
}

}  // extern "C"

}  // namespace

#endif /* BOTAN_TSS2_SUPPORTS_CRYPTO_CALLBACKS */

namespace Botan::TPM2 {

/**
 * Enable the Botan crypto callbacks for the given ESYS context.
 *
 * The callbacks may maintain two types of state:
 *
 *  * 'userdata' is a pointer to a CryptoCallbackState object that is passed
 *               to all callback functions. This provides access to a random
 *               number generator specified by the user.
 *               The lifetime of this object is bound to the TPM2::Context.
 *
 *  * 'context'  is a pointer to a DigestCallbackState object that contains
 *               either a HashFunction or a MessageAuthenticationCode object.
 *               This holds the hash state between update callback invocations.
 *               The lifetime of this object is bound to the digest callbacks,
 *               hence *_finish() and *_abort() will delete the object.
 *
 * The runtime crypto backend is available since TSS2 4.0.0 and later. Explicit
 * support for SM4 was added in TSS2 4.1.0.
 *
 * Note that the callback implementations should be defensive in regard to the
 * input parameters. All pointers should be checked for nullptr before being
 * dereferenced. Some output parameters (e.g. out-buffer lengths) may be
 * regarded as optional, and should be checked for nullptr before being written
 * to.
 *
 * Error code conventions:
 *
 *  * TSS2_ESYS_RC_BAD_REFERENCE:   reference (typically userdata) invalid
 *  * TSS2_ESYS_RC_BAD_VALUE:       invalid input (e.g. size != 0 w/ nullptr buffer)
 *  * TSS2_ESYS_RC_NOT_SUPPORTED:   algorithm identifier not mapped to Botan
 *  * TSS2_ESYS_RC_NOT_IMPLEMENTED: algorithm not available (e.g. disabled)
 */
void set_crypto_callbacks(ESYS_CONTEXT* ctx, void* callback_state) {
#if defined(BOTAN_TSS2_SUPPORTS_CRYPTO_CALLBACKS)
   BOTAN_ASSERT_NONNULL(ctx);

   // clang-format off
   ESYS_CRYPTO_CALLBACKS callbacks{
      .rsa_pk_encrypt = &rsa_pk_encrypt,
      .hash_start     = &hash_start,
      .hash_update    = &hash_update,
      .hash_finish    = &hash_finish,
      .hash_abort     = &hash_abort,
      .hmac_start     = &hmac_start,
      .hmac_update    = &hmac_update,
      .hmac_finish    = &hmac_finish,
      .hmac_abort     = &hmac_abort,
      .get_random2b   = &get_random2b,
      .get_ecdh_point = &get_ecdh_point,
      .aes_encrypt    = &aes_encrypt,
      .aes_decrypt    = &aes_decrypt,
#if defined(BOTAN_TSS2_SUPPORTS_SM4_IN_CRYPTO_CALLBACKS)
      .sm4_encrypt    = &sm4_encrypt,
      .sm4_decrypt    = &sm4_decrypt,
#endif
      .init           = &init,
      .userdata       = callback_state,
   };
   // clang-format on

   check_rc("Esys_SetCryptoCallbacks", Esys_SetCryptoCallbacks(ctx, &callbacks));
#else
   BOTAN_UNUSED(ctx, callback_state);
   throw Not_Implemented(
      "This build of botan was compiled with a TSS2 version lower than 4.0.0, "
      "which does not support custom runtime crypto backends");
#endif
}

}  // namespace Botan::TPM2
