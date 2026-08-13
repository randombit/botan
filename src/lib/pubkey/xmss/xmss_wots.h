/*
 * XMSS WOTS
 * (C) 2016,2018 Matthias Gierlings
 *     2023      René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSS_WOTS_H_
#define BOTAN_XMSS_WOTS_H_

#include <botan/secmem.h>
#include <botan/xmss_parameters.h>
#include <botan/internal/xmss_address.h>
#include <span>
#include <vector>

namespace Botan {

class XMSS_Hash;
class XMSS_WOTS_PrivateKey;

typedef std::vector<secure_vector<uint8_t>> wots_keysig_t;

class XMSS_WOTS_Base {
   public:
      explicit XMSS_WOTS_Base(XMSS_WOTS_Parameters params) : m_params(params) {}

      XMSS_WOTS_Base(XMSS_WOTS_Parameters params, wots_keysig_t key_data) :
            m_params(params), m_key_data(std::move(key_data)) {}

      const wots_keysig_t& key_data() const { return m_key_data; }

   protected:
      XMSS_WOTS_Parameters m_params;  // NOLINT(*non-private-member-variable*)
      wots_keysig_t m_key_data;       // NOLINT(*non-private-member-variable*)
};

/**
 * A Winternitz One Time Signature public key for use with Extended Hash-Based
 * Signatures.
 **/
class XMSS_WOTS_PublicKey : public XMSS_WOTS_Base {
   public:
      /**
       * Creates a XMSS_WOTS_PublicKey from a message and signature using
       * Algorithm 6 WOTS_pkFromSig defined in the XMSS standard. This
       * overload is used to verify a message using a public key.
       *
       * @param params      The WOTS parameters to use
       * @param public_seed The public seed to derive the key with
       * @param signature   A WOTS signature for msg.
       * @param msg         A message.
       * @param adrs        The address of the key to retrieve.
       * @param hash        Instance of XMSS_Hash, that may only be used by the
       *                    thread executing at.
       */
      XMSS_WOTS_PublicKey(XMSS_WOTS_Parameters params,
                          std::span<const uint8_t> public_seed,
                          wots_keysig_t signature,
                          const secure_vector<uint8_t>& msg,
                          XMSS_Address adrs,
                          XMSS_Hash& hash);
};

/** A Winternitz One Time Signature private key for use with Extended Hash-Based
 * Signatures.
 **/
class XMSS_WOTS_PrivateKey : public XMSS_WOTS_Base {
   public:
      /**
       * Algorithm 3: "Generating a WOTS+ Private Key".
       * Generates a private key.
       *
       * Note that this is implemented according to the recommendations
       * in NIST SP.800-208 Section 6.2 to avoid a multi-target attack
       * vulnerability. This _does not_ influence the sign/verify
       * interoperability with implementations that do not implement this
       * recommendation.
       *
       * This overload is used in multithreaded scenarios, where it is
       * required to provide separate instances of XMSS_Hash to each thread.
       *
       * @param params       The WOTS parameters to use
       * @param public_seed  The public seed for the private key generation
       * @param private_seed The private seed for the private key generation
       * @param adrs         The address of the key to retrieve.
       * @param hash         Instance of XMSS_Hash, that may only be used by the
       *                     thread executing at.
       **/
      XMSS_WOTS_PrivateKey(XMSS_WOTS_Parameters params,
                           std::span<const uint8_t> public_seed,
                           std::span<const uint8_t> private_seed,
                           XMSS_Address adrs,
                           XMSS_Hash& hash);

      /**
       * Constructor for the old derivation logic.
       * Creates a WOTS+ private key using the old key derivation logic, i.e.
       * the logic WITHOUT the recommendations in NIST SP.800-208. It is used
       * to support XMSS_PrivateKeys created before the derivation logic was
       * updated.
       *
       * @param params       The WOTS parameters to use
       * @param private_seed The private seed for the private key generation
       * @param adrs         The address of the key to retrieve.
       * @param hash         Instance of XMSS_Hash, that may only be used by the
       *                     thread executing it.
       **/
      XMSS_WOTS_PrivateKey(XMSS_WOTS_Parameters params,
                           std::span<const uint8_t> private_seed,
                           XMSS_Address adrs,
                           XMSS_Hash& hash);

      /**
       * Algorithm 5: "WOTS_sign"
       * Generates a signature from a private key and a message.
       *
       * This overload is used in multithreaded scenarios, where it is
       * required to provide separate instances of XMSS_Hash to each
       * thread.
       *
       * @param msg A message to sign.
       * @param public_seed The public seed to use for the signature
       * @param adrs An OTS hash address identifying the WOTS+ key pair
       *        used for signing.
       * @param hash Instance of XMSS_Hash, that may only be used by the
       *        thread executing sign.
       *
       * @return signature for msg.
       **/
      wots_keysig_t sign(const secure_vector<uint8_t>& msg,
                         std::span<const uint8_t> public_seed,
                         XMSS_Address adrs,
                         XMSS_Hash& hash);
};

/**
 * Algorithm 2: Chaining Function, applied to many WOTS+ chains in lock-step.
 *
 * For each chain i the hash addresses [from[i], to[i]) are applied to
 * the i'th n-byte node of nodes, batching the hash calls across all
 * chains active in each step.
 *
 * @param params The WOTS parameters to use
 * @param[in,out] nodes The chain nodes, transformed in place
 * @param from Per chain, the first hash address to apply
 * @param to Per chain, the hash address to stop at (exclusive)
 * @param[in,out] addrs Per chain, its OTS hash address with the chain
 *        address set. The hash address and key/mask mode are modified.
 * @param seed The public seed
 * @param hash Instance of XMSS_Hash, that may only be used by the thread
 *        executing xmss_wots_chains.
 **/
void xmss_wots_chains(const XMSS_WOTS_Parameters& params,
                      std::span<uint8_t> nodes,
                      std::span<const uint8_t> from,
                      std::span<const uint8_t> to,
                      std::span<XMSS_Address> addrs,
                      std::span<const uint8_t> seed,
                      XMSS_Hash& hash);

}  // namespace Botan

#endif
