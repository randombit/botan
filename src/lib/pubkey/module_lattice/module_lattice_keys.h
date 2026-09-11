/*
 * Common private key interface for the module-lattice schemes ML-KEM and ML-DSA
 *
 * (C) 2026 Jack Lloyd
 * (C) 2026 Falko Strenzke - cryptosource GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_MODULE_LATTICE_KEYS_H_
#define BOTAN_MODULE_LATTICE_KEYS_H_

#include <botan/pk_keys.h>

namespace Botan {

/**
 * Encoding format of an ML-KEM or ML-DSA private key
 */
enum class MlPrivateKeyFormat : uint8_t {
   /**
    * Only the private random seed from which the key pair is expanded.
    *
    *  - ML-KEM: the 64-byte seed d || z (FIPS 203)
    *  - ML-DSA: the 32-byte seed xi (FIPS 204); as content of the PKCS#8
    *    privateKey field this is the RFC 9881 "seed" CHOICE alternative
    *    ([0] IMPLICIT OCTET STRING)
    *
    * Not available for the pre-standard Kyber and Dilithium round 3 variants.
    */
   Seed,
   /**
    * The expanded private key as specified in FIPS 203 (ML-KEM) or FIPS 204
    * (ML-DSA). For ML-DSA the content of the PKCS#8 privateKey field is the
    * RFC 9881 "expandedKey" CHOICE alternative (OCTET STRING).
    *
    * This is the only format supported by the pre-standard Kyber and
    * Dilithium round 3 variants.
    */
   Expanded,
   /**
    * Seed and expanded key together. Currently only supported for ML-DSA, where
    * the content of the PKCS#8 privateKey field is the RFC 9881 "both" CHOICE
    * alternative (SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING }).
    *
    * There is no raw (non-ASN.1) encoding of this format.
    */
   Both,
};

/**
 * Interface shared by the private keys of the module-lattice schemes
 * ML-KEM/Kyber (Kyber_PrivateKey) and ML-DSA/Dilithium (Dilithium_PrivateKey).
 *
 * Such keys can be represented by their private seed, by the expanded key of
 * FIPS 203/204, or (ML-DSA only) by both. A key remembers the format it was
 * loaded from, or the scheme's default format when it was freshly generated;
 * private_key_bits(), private_key_info() and raw_private_key_bits() use that
 * format. Keys that contain the seed can additionally be exported in any other
 * format, whereas keys loaded from an expanded encoding cannot be exported as a
 * seed.
 *
 * Given a generic Private_Key, this interface is obtained via
 * dynamic_cast<const Module_Lattice_PrivateKey*>(&key).
 */
class BOTAN_PUBLIC_API(3, 13) Module_Lattice_PrivateKey : public virtual Private_Key {
   public:
      ~Module_Lattice_PrivateKey() override;

      /**
       * The private key format this key was loaded from or, for a freshly
       * generated key, the default format of the scheme. This is the format
       * used by private_key_bits(), private_key_info() and raw_private_key_bits().
       */
      virtual MlPrivateKeyFormat private_key_format() const = 0;

      /**
       * The raw private key material in the given @p format without any
       * ASN.1 wrapping, i.e. the bare seed bytes or the expanded key as
       * specified in FIPS 203/204.
       *
       * @throws Encoding_Error if the key cannot be encoded in @p format.
       *         This is the case for MlPrivateKeyFormat::Both, which has no
       *         raw encoding, for MlPrivateKeyFormat::Seed if the key does not
       *         contain the seed, and for anything but
       *         MlPrivateKeyFormat::Expanded on Kyber or Dilithium round 3 keys.
       */
      virtual secure_vector<uint8_t> formatted_raw_private_key_bits(MlPrivateKeyFormat format) const = 0;

      /**
       * The private key encoded in the given @p format as it appears in the
       * privateKey OCTET STRING of a PKCS#8 PrivateKeyInfo structure. This is
       * what private_key_bits() returns for a key whose private_key_format()
       * is @p format.
       *
       *  - ML-DSA: the ML-DSA-PrivateKey CHOICE encoding of RFC 9881
       *  - ML-KEM: the ASN.1 wrapping of RFC 9935 is not yet implemented.
       *    Currently the same bytes as formatted_raw_private_key_bits() are
       *    returned. This is a known interim limitation that will change in a
       *    future release.
       *  - Kyber and Dilithium round 3: the raw expanded key
       *
       * @throws Encoding_Error if the key cannot be encoded in @p format
       *         (see formatted_raw_private_key_bits()).
       */
      virtual secure_vector<uint8_t> formatted_private_key_bits(MlPrivateKeyFormat format) const = 0;

      /**
       * Equivalent to formatted_private_key_bits(private_key_format())
       */
      secure_vector<uint8_t> private_key_bits() const override;

      /**
       * Equivalent to formatted_raw_private_key_bits(private_key_format()).
       *
       * @note ML-DSA keys in the format MlPrivateKeyFormat::Both, which has no
       *       raw encoding, return the seed instead.
       */
      secure_vector<uint8_t> raw_private_key_bits() const override;
};

}  // namespace Botan

#endif
