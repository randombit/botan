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
class BOTAN_PUBLIC_API(3, 13) SystemParameters final {
   public:
      /**
      * SPAKE2+ default system parameters for P-256
      */
      static SystemParameters rfc9383_p256(const EC_Group& group);

      /**
      * SPAKE2+ default system parameters for P-384
      */
      static SystemParameters rfc9383_p384(const EC_Group& group);

      /**
      * SPAKE2+ default system parameters for P-521
      */
      static SystemParameters rfc9383_p521(const EC_Group& group);

      /**
      * SPAKE2+ custom system parameters for an arbitrary group
      *
      * Note that the group must support hash2curve
      *
      * The M/N values will be derived using hash2curve along with the
      * provided context string
      *
      * @param group the elliptic curve group to use
      * @param context the context string to hash to derive M/N
      * @param hash_fn the hash function to use
      */
      static SystemParameters custom(const EC_Group& group,
                                     std::span<const uint8_t> context,
                                     const std::string& hash_fn);

      const EC_Group& group() const { return m_group; }

      const EC_AffinePoint& spake2_m() const { return m_spake2p_m; }

      const EC_AffinePoint& spake2_n() const { return m_spake2p_n; }

      const std::string& hash_function() const { return m_hash_fn; }

   private:
      // TODO shared_ptr pimpl
      const EC_Group m_group;
      const EC_AffinePoint m_spake2p_m;
      const EC_AffinePoint m_spake2p_n;
      const std::string m_hash_fn;
};

/**
* SPAKE2+ Registraton Record
*/
class BOTAN_PUBLIC_API(3, 13) RegistrationRecord final {
   public:
      /**
      * Hash a shared secret and return the registration record
      */
     static RegistrationRecord
     from_shared_secret(const SystemParameters &params,
                        std::string_view shared_secret,
                        std::span<const uint8_t> id_prover,
                        std::span<const uint8_t> id_verifier);

      /*
      * @warning This interface is potentially unsafe, depending upon how shared_secret is
      * derived from the password. The scalar value must be uniform random, and preferably
      * computed in a way such that testing values is expensive for an attacker. It exists
      * to support testing, as well as applications which require using a different
      * password hashing scheme than the default one implemented by `from_shared_secret`
      */
      static RegistrationRecord from_prehashed(const SystemParameters& params, const EC_Scalar& shared_secret);

      /**
      * Deserialize a RegistrationRecord previously serialized by serialize
      */
      static RegistrationRecord deserialize(const SystemParameters& params, std::span<const uint8_t> record);

      /**
      * Serialize the registration record
      *
      * @warning the return value is the unencrypted registration record, which
      * is a sensitive value allowing password guessing attacks. Encrypt for
      * persistent storage.
      */
      secure_vector<uint8_t> serialize() const;

   private:
      RegistrationRecord(const SystemParameters& params, const EC_Scalar& shared_secret);

      // TODO pimpl
      EC_Scalar m_w0;
      EC_Point m_L;
};

/**
* SPAKE2+ Prover Secret
*/
class BOTAN_PUBLIC_API(3, 13) ProverSecret final {
   public:
     static ProverSecret from_shared_secret(const SystemParameters &params,
                                            std::string_view shared_secret,
                                            std::span<const uint8_t> salt);

      /*
      * @warning This interface is potentially unsafe, depending upon how shared_secret is
      * derived from the password. The scalar value must be uniform random, and preferably
      * computed in a way such that testing values is expensive for an attacker. It exists
      * to support testing, as well as applications which require using a different
      * password hashing scheme than the default one implemented by `from_shared_secret`
      */
      static ProverSecret from_prehashed(const SystemParameters& params,
                                         const EC_Scalar& shared_secret);

   private:
      friend class ProverContext;

      // TODO pimpl
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
class BOTAN_PUBLIC_API(3, 13) ProverContext final {
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
      // TODO pimpl
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
class BOTAN_PUBLIC_API(3, 13) VerifierContext final {
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
      // TODO pimpl
      SystemParameters m_params;
      RegistrationRecord m_record;
      std::optional<std::pair<std::vector<uint8_t>, EC_Scalar>> m_our_message;
};

}  // namespace Botan::SPAKE2p

#endif
