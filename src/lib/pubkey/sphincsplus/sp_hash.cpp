/*
 * SPHINCS+ Hashes
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include "botan/hash.h"
#include <botan/exceptn.h>
#include <botan/sp_parameters.h>
#include <botan/stream_cipher.h>
#include <botan/assert.h>
#include <botan/internal/shake_cipher.h>
#include <botan/internal/sp_hash.h>
#include <botan/internal/stl_util.h>
#include <botan/internal/mgf1.h>

#include <cstdint>
#include <memory>

namespace Botan {

Sphincs_Hash_Functions::Sphincs_Hash_Functions(const Sphincs_Parameters& params)
   {
   switch(params.hash_type())
      {
      case Sphincs_Hash_Type::Sha256:
         throw Not_Implemented("MGF1-SHA-256 XOF is not yet implemented");
      case Sphincs_Hash_Type::Haraka:
         throw Not_Implemented("XOF based on Haraka is not yet implemented");
      case Sphincs_Hash_Type::Shake256:
         break;
      }
   m_hash = HashFunction::create_or_throw(params.hash_name());
   }

Sphincs_Hash_Functions::~Sphincs_Hash_Functions() = default;


void Sphincs_Hash_Functions::PRF(std::span<uint8_t> out,
                                 const SphincsPublicSeed& pub_seed,
                                 const SphincsSecretSeed& sk_seed,
                                 const Sphincs_Address& address)
   {
   // TODO: Optimization potential: We could pre-compute the internal hash state of pub_seed
   //       and avoid re-calculating this for each hash application.
   m_hash->update(pub_seed);
   address.apply_to_hash(*m_hash);
   m_hash->update(sk_seed);
   m_hash->final(out);
   }

void Sphincs_Hash_Functions::PRF_msg(std::span<uint8_t> out,
                                     const SphincsSecretPRF& sk_prf,
                                     const SphincsOptionalRandomness& opt_rand,
                                     std::span<const uint8_t> in)
   {
   m_hash->update(sk_prf);
   m_hash->update(opt_rand);
   m_hash->update(in);
   m_hash->final(out);
   }


void Sphincs_Hash_Functions::F(std::span<uint8_t> out,
                               const SphincsPublicSeed& pub_seed,
                               const Sphincs_Address& address,
                               std::span<const uint8_t> in1)
   {
   auto& tweaked_hash = T(pub_seed, address);
   tweaked_hash.update(in1);
   tweaked_hash.final(out);
   }

void Sphincs_Hash_Functions::H(std::span<uint8_t> out,
                               const SphincsPublicSeed& pub_seed,
                               const Sphincs_Address& address,
                               std::span<const uint8_t> in1,
                               std::span<const uint8_t> in2)
   {
   auto& tweaked_hash = T(pub_seed, address);
   tweaked_hash.update(in1);
   tweaked_hash.update(in2);
   tweaked_hash.final(out);
   }

HashFunction& Sphincs_Hash_Functions::T(const SphincsPublicSeed& pub_seed,
                                        const Sphincs_Address& address)
   {
   // TODO: For SHA the pub_seed must be adapted using "BlockPad()" (see Spec 3.1 p. 40)
   // TODO: Optimization potential: We could pre-compute the internal hash state of pub_seed
   //       and avoid re-calculating this for each hash application.
   m_hash->update(pub_seed);
   address.apply_to_hash(*m_hash);
   return *m_hash;
   }

}
