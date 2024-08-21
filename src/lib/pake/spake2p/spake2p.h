/*
* (C) 2024,2025,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PAKE_SPAKE2PLUS_H_
#define BOTAN_PAKE_SPAKE2PLUS_H_

#include <botan/ec_apoint.h>
#include <botan/ec_group.h>
#include <botan/ec_scalar.h>
#include <botan/secmem.h>
#include <botan/types.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Botan {

class RandomNumberGenerator;

}

/**
* SPAKE2+ (RFC 9383) password authenticated key exchange
*
* SPAKE2+ is an augmented PAKE; the two sides are asymmetric. The prover
* knows the password itself, while the verifier stores only a registration
* record derived from the password. An attacker who steals the registration
* record cannot impersonate the prover without first performing a dictionary
* attack on the record.
*
* The expected message flow is
*
*  - The prover calls ProverContext::generate_message and sends the result
*    (shareP) to the verifier.
*  - The verifier calls VerifierContext::process_message and sends the
*    result (shareV followed by confirmV) to the prover.
*  - The prover calls ProverContext::process_message, which checks the
*    verifier's key confirmation, and sends the result (confirmP) to the
*    verifier.
*  - The verifier calls VerifierContext::verify_confirmation
*
* After the final confirmation step both sides can call shared_secret to
* obtain the session key (K_shared in RFC 9383)
*
* Protocols which embed SPAKE2+ and perform the prover's key confirmation
* themselves (such as the proposed TLS PAKE extension) may instead call
* VerifierContext::skip_confirmation in place of the final step.
*/
namespace Botan::SPAKE2p {

/**
* SPAKE2+ (RFC 9383) System Parameters
*
* This selects the elliptic curve group, the M/N group elements, and the
* hash function; the hash also fixes the KDF (HKDF) and the MAC (HMAC)
*/
class BOTAN_PUBLIC_API(3, 13) SystemParameters final {
   public:
      /**
      * The RFC 9383 ciphersuite P256-SHA256-HKDF-HMAC-SHA256
      */
      static SystemParameters rfc9383_p256_sha256();

      /**
      * The RFC 9383 ciphersuite P256-SHA512-HKDF-HMAC-SHA512
      */
      static SystemParameters rfc9383_p256_sha512();

      /**
      * The RFC 9383 ciphersuite P384-SHA256-HKDF-HMAC-SHA256
      */
      static SystemParameters rfc9383_p384_sha256();

      /**
      * The RFC 9383 ciphersuite P384-SHA512-HKDF-HMAC-SHA512
      */
      static SystemParameters rfc9383_p384_sha512();

      /**
      * The RFC 9383 ciphersuite P521-SHA512-HKDF-HMAC-SHA512
      */
      static SystemParameters rfc9383_p521_sha512();

      /**
      * SPAKE2+ custom system parameters for an arbitrary group
      *
      * The M/N values will be derived from the seed using hash2curve;
      * note that not all groups support hash2curve.
      *
      * RFC 9383 Section 3.2: "Applications MAY use different M and N
      * values, provided they are computed, e.g., using different input
      * seeds to the algorithm in Appendix B, as random elements for
      * which the discrete log is unknown."
      *
      * If the seed includes the identities of the participants, this
      * additionally makes the scheme "quantum annoying", in that an attacker
      * with a discrete logarithm oracle must compute a new discrete log for
      * each (user, verifier) pair they wish to attack.
      *
      * @param group the elliptic curve group to use
      * @param seed the seed bytes used to derive M and N
      * @param hash_fn the hash function to use (eg "SHA-256")
      */
      static SystemParameters custom(const EC_Group& group, std::span<const uint8_t> seed, std::string_view hash_fn);

      const EC_Group& group() const { return m_group; }

      const EC_AffinePoint& spake2p_m() const { return m_spake2p_m; }

      const EC_AffinePoint& spake2p_n() const { return m_spake2p_n; }

      const std::string& hash_function() const { return m_hash_fn; }

      /**
      * Return the size in bytes of a key share (shareP or shareV)
      */
      size_t share_size() const;

      /**
      * Return the size in bytes of a key confirmation message (confirmP or confirmV)
      */
      size_t confirmation_size() const;

   private:
      SystemParameters(EC_Group group, EC_AffinePoint m, EC_AffinePoint n, std::string_view hash_fn);

      EC_Group m_group;
      EC_AffinePoint m_spake2p_m;
      EC_AffinePoint m_spake2p_n;
      std::string m_hash_fn;
};

class ProverSecret;

/**
* SPAKE2+ Registration Record
*
* This is the information (w0 and L in RFC 9383) which the verifier
* stores in order to authenticate the prover.
*/
class BOTAN_PUBLIC_API(3, 13) RegistrationRecord final {
   public:
      /**
      * Perform password registration, returning the registration record
      *
      * This derives the record from the password using Argon2id; see
      * ProverSecret::from_password for the details. The same password,
      * identities, and salt must later be used to create the prover's secret.
      *
      * The identities and salt may be empty.
      */
      static RegistrationRecord from_password(const SystemParameters& params,
                                              std::string_view password,
                                              std::span<const uint8_t> prover_id,
                                              std::span<const uint8_t> verifier_id,
                                              std::span<const uint8_t> salt,
                                              RandomNumberGenerator& rng);

      /**
      * Deserialize a RegistrationRecord previously serialized by serialize
      */
      static RegistrationRecord deserialize(const SystemParameters& params, std::span<const uint8_t> record);

      /**
      * Serialize the registration record
      *
      * @warning the return value is the unencrypted registration record, which
      * is a sensitive value allowing password guessing attacks. Encrypt it for
      * persistent storage if possible.
      */
      secure_vector<uint8_t> serialize() const;

   private:
      friend class ProverSecret;
      friend class VerifierContext;

      RegistrationRecord(EC_Scalar w0, EC_AffinePoint l) : m_w0(std::move(w0)), m_l(std::move(l)) {}

      EC_Scalar m_w0;
      EC_AffinePoint m_l;
};

/**
* SPAKE2+ Prover Secret
*
* This is the information (w0 and w1 in RFC 9383) which the prover
* derives from the password in order to authenticate itself.
*/
class BOTAN_PUBLIC_API(3, 13) ProverSecret final {
   public:
      /**
      * Derive the prover secret from a password
      *
      * The derivation uses Argon2id with the memory-constrained parameters
      * from RFC 9106, namely m=64 MiB, t=3, p=4. Following RFC 9383, the
      * Argon2id passphrase input is the concatenation
      *
      *    len(pw) || pw || len(idProver) || idProver || len(idVerifier) || idVerifier
      *
      * with each length an 8-byte little-endian count of bytes, and the salt
      * is provided to Argon2id directly. The Argon2id output is split in two
      * halves, each of which is reduced modulo the group order.
      *
      * The identities and salt may be empty; if a salt is available it
      * should be used, as this prevents precomputed dictionary attacks.
      */
      static ProverSecret from_password(const SystemParameters& params,
                                        std::string_view password,
                                        std::span<const uint8_t> prover_id,
                                        std::span<const uint8_t> verifier_id,
                                        std::span<const uint8_t> salt);

      /**
      * Create a prover secret from already derived scalars
      *
      * @warning This interface is potentially unsafe, depending upon how the
      * scalars are derived from the password. They must be uniformly random,
      * and preferably computed in a way such that testing password guesses is
      * expensive for an attacker. It exists to support testing, as well as
      * applications which require using a different password hashing scheme
      * than the default one implemented by from_password.
      */
      static ProverSecret from_prehashed(EC_Scalar w0, EC_Scalar w1);

      /**
      * Deserialize a ProverSecret previously serialized by serialize
      */
      static ProverSecret deserialize(const SystemParameters& params, std::span<const uint8_t> secret);

      /**
      * Serialize the prover secret
      *
      * @warning the return value is password equivalent; encrypt it for
      * persistent storage if possible.
      */
      secure_vector<uint8_t> serialize() const;

      /**
      * Compute the registration record (w0 and L=w1*P) for this secret
      *
      * This would typically be done once, when the password is first
      * registered with the verifier.
      */
      RegistrationRecord registration_record(RandomNumberGenerator& rng) const;

   private:
      friend class ProverContext;

      ProverSecret(EC_Scalar w0, EC_Scalar w1) : m_w0(std::move(w0)), m_w1(std::move(w1)) {}

      EC_Scalar m_w0;
      EC_Scalar m_w1;
};

/**
* SPAKE2+ (RFC 9383) Prover
*
* The prover knows the password secret (w0 and w1) and authenticates
* itself to a verifier which knows the matching registration record.
*/
class BOTAN_PUBLIC_API(3, 13) ProverContext final {
   public:
      /**
      * Set up for an execution of the protocol
      *
      * The identities and context must be agreed upon by both parties; the
      * identities must additionally match the values used during password
      * registration. Both the identities and the context may be empty.
      */
      ProverContext(const SystemParameters& params,
                    const ProverSecret& secret,
                    std::span<const uint8_t> prover_id,
                    std::span<const uint8_t> verifier_id,
                    std::span<const uint8_t> context = {});

      /**
      * Generate the prover's key share (shareP), which is sent to the verifier.
      *
      * This can be called only once.
      */
      std::vector<uint8_t> generate_message(RandomNumberGenerator& rng);

      /**
      * Consume the message from the verifier (shareV followed by confirmV)
      * and return the prover's key confirmation (confirmP), which is sent
      * to the verifier.
      *
      * Throws Decoding_Error if the message is malformed, and
      * Invalid_Authentication_Tag if the verifier's key confirmation is
      * wrong (typically due to a password mismatch).
      */
      std::vector<uint8_t> process_message(std::span<const uint8_t> peer_message, RandomNumberGenerator& rng);

      /**
      * Return the shared secret (K_shared)
      *
      * This may be called only after process_message has succeeded.
      */
      secure_vector<uint8_t> shared_secret() const;

      const SystemParameters& parameters() const { return m_params; }

   private:
      enum class State : uint8_t { Initial, ShareGenerated, Complete, Failed };

      SystemParameters m_params;
      ProverSecret m_secret;
      std::vector<uint8_t> m_prover_id;
      std::vector<uint8_t> m_verifier_id;
      std::vector<uint8_t> m_context;
      std::optional<std::pair<std::vector<uint8_t>, EC_Scalar>> m_our_message;
      secure_vector<uint8_t> m_shared_secret;
      State m_state = State::Initial;
};

/**
* SPAKE2+ (RFC 9383) Verifier
*
* The verifier does not know the password itself; it stores only the
* registration record.
*/
class BOTAN_PUBLIC_API(3, 13) VerifierContext final {
   public:
      /**
      * Set up for an execution of the protocol
      *
      * The identities and context must be agreed upon by both parties; the
      * identities must additionally match the values used during password
      * registration. Both the identities and the context may be empty.
      */
      VerifierContext(const SystemParameters& params,
                      const RegistrationRecord& record,
                      std::span<const uint8_t> prover_id,
                      std::span<const uint8_t> verifier_id,
                      std::span<const uint8_t> context = {});

      /**
      * Consume the prover's key share (shareP) and return the verifier's
      * response (shareV followed by confirmV), which is sent to the prover.
      *
      * This can be called only once. Throws Decoding_Error if the key
      * share is malformed.
      */
      std::vector<uint8_t> process_message(std::span<const uint8_t> peer_message, RandomNumberGenerator& rng);

      /**
      * Check the prover's key confirmation (confirmP)
      *
      * Throws Invalid_Authentication_Tag if the confirmation is wrong,
      * meaning the prover does not know the password.
      */
      void verify_confirmation(std::span<const uint8_t> confirmation);

      /**
      * Skip checking the prover's key confirmation (confirmP)
      *
      * This can be called after process_message, in place of
      * verify_confirmation, to allow extracting the shared secret without
      * having checked the prover's key confirmation.
      *
      * @warning After calling this, nothing is known about the peer; only
      * a prover which knows the password can compute the same shared
      * secret, but no evidence of this has been received. It is intended
      * solely for protocols which embed SPAKE2+ and perform the prover's
      * key confirmation themselves, for example the proposed TLS PAKE
      * extension, where the TLS handshake takes the place of confirmP.
      * Anywhere else, use verify_confirmation.
      */
      void skip_confirmation();

      /**
      * Return the shared secret (K_shared)
      *
      * This may be called only after verify_confirmation has succeeded,
      * or after skip_confirmation.
      *
      * RFC 9383 Section 3.3: "The Verifier MUST NOT send application data
      * to the Prover until it has received and verified the confirmation
      * message."
      */
      secure_vector<uint8_t> shared_secret() const;

      const SystemParameters& parameters() const { return m_params; }

   private:
      enum class State : uint8_t { Initial, Responded, Complete, Failed };

      SystemParameters m_params;
      RegistrationRecord m_record;
      std::vector<uint8_t> m_prover_id;
      std::vector<uint8_t> m_verifier_id;
      std::vector<uint8_t> m_context;
      std::vector<uint8_t> m_expected_confirmation;
      secure_vector<uint8_t> m_shared_secret;
      State m_state = State::Initial;
};

}  // namespace Botan::SPAKE2p

#endif
