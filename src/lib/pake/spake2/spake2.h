/*
* (C) 2024,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PAKE_SPAKE2_H_
#define BOTAN_PAKE_SPAKE2_H_

#include <botan/ec_apoint.h>
#include <botan/ec_group.h>
#include <botan/ec_scalar.h>
#include <botan/types.h>
#include <span>
#include <string_view>

namespace Botan {

class RandomNumberGenerator;

}

namespace Botan::SPAKE2 {

/**
* Identifies which peer we are in the protocol
*/
enum class PeerId : uint8_t {
   PeerA,
   PeerB,
};

/**
* SPAKE2 (RFC 9382) Parameters
*
* This implementation of SPAKE2 requires asymmetric exchange, ie that
* each party knows if it is A or B.
*
* The key confirmation step is omitted; it is assumed that further
* uses of the shared secret will confirm the key. The shared secret is
* equivalent to Hash(TT) in RFC 9382 so it is possible to implement
* RFC 9382 conformant key confirmation if necessary.
*/
class BOTAN_PUBLIC_API(3, 10) Parameters final {
   public:
      /**
      * RFC 9382 compatible SPAKE2 configuration
      *
      * The shared secret is hashed with Argon2id M=131072,t=3,p=1 and with the context
      * string as the AD
      *
      * If the group is not P-256, P-384, or P-521, then the group must support RFC 9380
      * hash to curve. Curves with a cofactor are not supported.
      *
      * If per_user_params is true, this uses the "quantum annoying" variant where N/M are
      * the output of hash to curve; this requires an attacker with a quantum computer to
      * perform a discrete logarithm calculation per PAKE, rather than just once for the
      * default (fixed) SPAKE2 parameters. This variant is described in RFC 9382 section 5,
      * however note that a different input is used to hash_to_curve which includes not
      * just the user identifiers but also the context string.
      *
      * @param group the elliptic curve group to operate in
      * @param shared_secret the shared secret (eg a password)
      * @param a_identity the (optional) identity string of peer A
      * @param b_identity the (optional) identity string of peer B
      * @param context an optional context string (for example a protocol identifier)
      * @param hash the hash function to use (SHA-512 highly recommended)
      * @param per_user_params if true then per-user N/M are used
      */
      Parameters(const EC_Group& group,
                 std::string_view shared_secret,
                 std::span<const uint8_t> a_identity = {},
                 std::span<const uint8_t> b_identity = {},
                 std::span<const uint8_t> context = {},
                 std::string_view hash = "SHA-512",
                 bool per_user_params = true);

      /**
      * RFC 9382 compatible SPAKE2 configuration
      *
      * If the group is not P-256, P-384, or P-521, then the group must support RFC 9380
      * hash to curve. Curves with a cofactor are not supported.
      *
      * If per_user_params is true, this uses the "quantum annoying" variant where N/M are
      * the output of hash to curve; this requires an attacker with a quantum computer to
      * perform a discrete logarithm calculation per PAKE, rather than just once for the
      * default (fixed) SPAKE2 parameters.
      *
      * Here the shared secret a random scalar. It should have been generated using a
      * memory hard function such as Argon2id.
      *
      * @warning This interface is potentially unsafe, depending upon how shared_secret is
      * derived from the password. The scalar value must be uniform random, and preferably
      * computed in a way such that testing values is expensive for an attacker. It exists
      * to support testing, as well as applications which require using a different
      * password hashing scheme than the default one implemented by `hash_shared_secret`
      *
      * @param group the elliptic curve group to operate in
      * @param shared_secret an integer that is the hash of a shared secret
      * @param a_identity the (optional) identity string of peer A
      * @param b_identity the (optional) identity string of peer B
      * @param context an optional context string (for example a protocol identifier)
      * @param hash the hash function to use (SHA-512 highly recommended)
      * @param per_user_params if true then per-user N/M are used
      */
      Parameters(const EC_Group& group,
                 const EC_Scalar& shared_secret,
                 std::span<const uint8_t> a_identity = {},
                 std::span<const uint8_t> b_identity = {},
                 std::span<const uint8_t> context = {},
                 std::string_view hash = "SHA-512",
                 bool per_user_params = true);

      /**
      * Return the default mapping from a shared secret (plus identifiers) to
      * an elliptic curve scalar.
      *
      * The shared secret is hashed with Argon2id M=131072,t=3,p=1
      *
      * The output is converted to a scalar by generating a bytestring of length
      * equal to the scalar, plus 128 bits. This is then reduced modulo the order.
      * Note this differs from the recommendation in RFC 9382 to use 64 excess bits.
      */
      static EC_Scalar hash_shared_secret(const EC_Group& group,
                                          std::string_view shared_secret,
                                          std::span<const uint8_t> a_identity = {},
                                          std::span<const uint8_t> b_identity = {},
                                          std::span<const uint8_t> context = {});

      const EC_Group& group() const { return m_group; }

      const EC_AffinePoint& spake2_m() const { return m_params.first; }

      const EC_AffinePoint& spake2_n() const { return m_params.second; }

      const EC_Scalar& spake2_w() const { return m_w; }

      const std::string& hash_function() const { return m_hash_fn; }

      std::span<const uint8_t> a_identity() const { return m_a_identity; }

      std::span<const uint8_t> b_identity() const { return m_b_identity; }

      std::span<const uint8_t> context() const { return m_context; }

   private:
      EC_Group m_group;
      std::pair<EC_AffinePoint, EC_AffinePoint> m_params;
      EC_Scalar m_w;
      std::string m_hash_fn;
      std::vector<uint8_t> m_a_identity;
      std::vector<uint8_t> m_b_identity;
      std::vector<uint8_t> m_context;
};

/*
* SPAKE2 (RFC 9382) Protocol Context
*
* This implementation of SPAKE2 requires asymmetric exchange, ie that
* each party knows if it is A or B.
*
* The key confirmation step is omitted; it is assumed that further
* uses of the shared secret will confirm the key. The shared secret is
* equivalent to Hash(TT) in RFC 9382 so it is possible to implement
* RFC 9382 conformant key confirmation if necessary.
*/
class BOTAN_PUBLIC_API(3, 10) Context final {
   public:
      Context(PeerId whoami, const Parameters& params, RandomNumberGenerator& rng) :
            m_rng(rng), m_whoami(whoami), m_params(params) {}

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
      RandomNumberGenerator& m_rng;
      PeerId m_whoami;
      Parameters m_params;
      std::optional<std::pair<std::vector<uint8_t>, EC_Scalar>> m_our_message;
};

}  // namespace Botan::SPAKE2

#endif
