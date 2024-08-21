/*
* (C) 2024,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PAKE_SPAKE2PLUS_H_
#define BOTAN_PAKE_SPAKE2PLUS_H_

#include <botan/ec_apoint.h>
#include <botan/ec_group.h>
#include <botan/ec_scalar.h>
#include <botan/types.h>
#include <span>
#include <string_view>

namespace Botan {

class RandomNumberGenerator;

}

namespace Botan::SPAKE2p {

/**
* SPAKE2+ (RFC 9383) System Parameters
*/
class BOTAN_PUBLIC_API(3, 10) SystemParameters final {
   public:
      /**
      * SPAKE2+ default system parameters
      *
      * If the group is not P-256, P-384, or P-521, then the group must support RFC 9380
      * hash to curve. Curves with a cofactor are not supported.
      *
      * If per_user_params is true, this uses the "quantum annoying" variant where N/M are
      * the output of hash to curve; this requires an attacker with a quantum computer to
      * perform a discrete logarithm calculation per PAKE, rather than just once for the
      * default (fixed) SPAKE2 parameters. This is allowed by RFC 9383 section 3.2
      *
      * @param group the elliptic curve group to operate in
      * @param a_identity the (optional) identity string of peer A
      * @param b_identity the (optional) identity string of peer B
      * @param context an optional context string (for example a protocol identifier)
      * @param hash the hash function to use (SHA-512 highly recommended)
      * @param per_user_params if true then per-user N/M are used
      */
      explicit SystemParameters(const EC_Group& group);

      /**
      * SPAKE2+ system parameters
      *
      * If the group is not P-256, P-384, or P-521, then the group must support RFC 9380
      * hash to curve. Curves with a cofactor are not supported.
      *
      * If per_user_params is true, this uses the "quantum annoying" variant where N/M are
      * the output of hash to curve; this requires an attacker with a quantum computer to
      * perform a discrete logarithm calculation per PAKE, rather than just once for the
      * default (fixed) SPAKE2 parameters. This is allowed by RFC 9383 section 3.2
      *
      * @param group the elliptic curve group to operate in
      * @param a_identity the (optional) identity string of peer A
      * @param b_identity the (optional) identity string of peer B
      * @param context an optional context string (for example a protocol identifier)
      * @param hash the hash function to use (SHA-512 highly recommended)
      * @param per_user_params if true then per-user N/M are used
      */
      explicit SystemParameters(const EC_Group& group,
                                std::span<const uint8_t> a_identity = {},
                                std::span<const uint8_t> b_identity = {},
                                std::span<const uint8_t> context = {},
                                std::string_view hash = "SHA-512")

      const EC_Group& group() const { return m_group; }

      const EC_AffinePoint& spake2_m() const { return m_params.first; }

      const EC_AffinePoint& spake2_n() const { return m_params.second; }

      const std::string& hash_function() const { return m_hash_fn; }

      std::span<const uint8_t> a_identity() const { return m_a_identity; }

      std::span<const uint8_t> b_identity() const { return m_b_identity; }

      std::span<const uint8_t> context() const { return m_context; }

   private:
      // TODO shared_ptr pimpl
      EC_Group m_group;
      std::pair<EC_AffinePoint, EC_AffinePoint> m_params;
      std::string m_hash_fn;
      std::vector<uint8_t> m_a_identity;
      std::vector<uint8_t> m_b_identity;
      std::vector<uint8_t> m_context;
};

/**
* SPAKE2+ Registraton Record
*/
class BOTAN_PUBLIC_API(3, 10) RegistrationRecord final {
   public:
      RegistrationRecord(const SystemParameters& params, std::string_view shared_secret);

      /*
      * @warning This interface is potentially unsafe, depending upon how shared_secret is
      * derived from the password. The scalar value must be uniform random, and preferably
      * computed in a way such that testing values is expensive for an attacker. It exists
      * to support testing, as well as applications which require using a different
      * password hashing scheme than the default one implemented by `hash_shared_secret`
      */
      RegistrationRecord(const SystemParameters& params, const EC_Scalar& shared_secret);

      static RegistrationRecord deserialize(const SystemParameters& params, std::span<const uint8_t> record);

      secure_vector<uint8_t> serialize() const;

   private:
      EC_Scalar m_w0;
      EC_Point m_L;
};

/**
* SPAKE2+ Prover Secret
*/
class BOTAN_PUBLIC_API(3, 10) ProverSecret final {
   public:
      ProverSecret(const SystemParameters& params,
                   std::string_view shared_secret);

      /*
      * @warning This interface is potentially unsafe, depending upon how shared_secret is
      * derived from the password. The scalar value must be uniform random, and preferably
      * computed in a way such that testing values is expensive for an attacker. It exists
      * to support testing, as well as applications which require using a different
      * password hashing scheme than the default one implemented by `hash_shared_secret`
      */
      ProverSecret(const SystemParameters& params,
                   const EC_Scalar& shared_secret);

   private:
      friend class ProverContext;

      EC_Scalar m_w0;
      EC_Scalar m_w1;
};

/*
* SPAKE2 (RFC 9383) Prover Context
*
* This implementation of SPAKE2 requires asymmetric exchange, ie that
* each party knows if it is A or B.
*
* The key confirmation step is omitted; it is assumed that further
* uses of the shared secret will confirm the key. The shared secret is
* equivalent to Hash(TT) in RFC 9383 so it is possible to implement
* RFC 9383 conformant key confirmation if necessary.
*/
class BOTAN_PUBLIC_API(3, 10) ProverContext final {
   public:
      ProverContext(const SystemParameters& params, const ProverSecret& secret) :
         m_params(params), m_secret(secret) {}

      /**
      * Generate a message for the peer. This can be called only once.
      */
      std::vector<uint8_t> generate_message();

      /**
      * Consume the message from the peer and return the shared secret.
      *
      * The context should not be used anymore after this point
      */
      secure_vector<uint8_t> process_message(std::span<const uint8_t> peer_message);

   private:
      SystemParameters m_params;
      ProverSecret m_secret;
      std::optional<std::pair<std::vector<uint8_t>, EC_Scalar>> m_our_message;
};

/*
* SPAKE2 (RFC 9383) Verifier Context
*
* This implementation of SPAKE2 requires asymmetric exchange, ie that
* each party knows if it is A or B.
*
* The key confirmation step is omitted; it is assumed that further
* uses of the shared secret will confirm the key. The shared secret is
* equivalent to Hash(TT) in RFC 9383 so it is possible to implement
* RFC 9383 conformant key confirmation if necessary.
*/
class BOTAN_PUBLIC_API(3, 10) VerifierContext final {
   public:
      VerifierContext(const SystemParameters& params, const RegistrationRecord& record) :
         m_params(params), m_record(record) {}

      /**
      * Generate a message for the peer. This can be called only once.
      */
      std::vector<uint8_t> generate_message(RandomNumberGenerator& rng);

      /**
      * Consume the message from the peer and return the shared secret.
      *
      * The context should not be used anymore after this point
      */
      secure_vector<uint8_t> process_message(std::span<const uint8_t> peer_message, RandomNumberGenerator& rng);

   private:
      SystemParameters m_params;
      RegistrationRecord m_record;
      std::optional<std::pair<std::vector<uint8_t>, EC_Scalar>> m_our_message;
};

}  // namespace Botan::SPAKE2p

#endif
