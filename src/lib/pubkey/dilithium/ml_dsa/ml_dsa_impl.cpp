/*
* Asymmetric primitives for ML-DSA
* (C) 2024 Jack Lloyd
* (C) 2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "botan/asn1_obj.h"
#include "botan/exceptn.h"
#include <botan/internal/ml_dsa_impl.h>

#include <botan/internal/dilithium_algos.h>

#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <string>


namespace {
typedef Botan::DilithiumInternalKeypair (*decoding_func)(std::span<const uint8_t> key_bits, Botan::DilithiumConstants mode);


    Botan::DilithiumInternalKeypair try_decode_seed_only(std::span<const uint8_t> key_bits,
                                                                        Botan::DilithiumConstants mode)
    {
        Botan::secure_vector<uint8_t> seed;
        Botan::BER_Decoder(key_bits).decode(seed, Botan::ASN1_Type::OctetString, Botan::ASN1_Type(0), Botan::ASN1_Class::ContextSpecific).verify_end();
        return Botan::Dilithium_Algos::expand_keypair(Botan::DilithiumSeedRandomness(seed), std::move(mode));
    }
    Botan::DilithiumInternalKeypair try_decode_expanded_only(std::span<const uint8_t> /*key_bits*/,
                                                                        Botan::DilithiumConstants /*mode*/)
    {
        throw Botan::Decoding_Error("ML-DSA private format 'expanded-only' not supported");
    }
    Botan::DilithiumInternalKeypair try_decode_both(std::span<const uint8_t> /*key_bits*/,
                                                                        Botan::DilithiumConstants /*mode*/)
    {
        throw Botan::Decoding_Error("ML-DSA private format 'both' not supported");
    }

}

namespace Botan {

secure_vector<uint8_t> ML_DSA_Expanding_Keypair_Codec::encode_keypair(
    DilithiumInternalKeypair keypair) const {
  BOTAN_ASSERT_NONNULL(keypair.second);
  const auto &seed = keypair.second->seed();
  BOTAN_ARG_CHECK(
      seed.has_value(),
      "Cannot encode keypair without the private seed"); // TODO: WHEN NOT 
                                                         // HAVING SEED,
                                                         // ENCODE AS
                                                         // EXPANDED-ONLY IN 
                                                         // CASE OF ML-DSA.
                                                         // DILITHIUM FAILS WITHOUT SEED.
  if(!keypair.second->mode().is_ml_dsa()) 
  {
      // return the raw seed for dilithium
      return seed.value().get();
  }
  secure_vector<uint8_t> result;
  DER_Encoder der_enc(result);
  der_enc.encode(seed.value().get(),
                 ASN1_Type(Botan::ASN1_Type::OctetString) /*real_type*/,
                 ASN1_Type(Botan::ASN1_Type(0)),
                 Botan::ASN1_Class::ContextSpecific);
  /* 
     *
            <80 20>
          0  32: [0]
               :   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
               :   10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
     *
     *  The previous format, which only contains the seed as OS without the [0]-tag, it can decode. Apparentyl, it has this feature as a non-standard compatibility fallback for legacy formats.
     * Reason: it has to look like this test vector from :
     */
   return result; 
}

DilithiumInternalKeypair ML_DSA_Expanding_Keypair_Codec::decode_keypair(std::span<const uint8_t> private_key_bits,
                                                                        DilithiumConstants mode) const {
    if(private_key_bits.size() == 32) 
    {
        // backwards compatibility (not RFC 9881 conforming) to raw seed format.
        return Botan::Dilithium_Algos::expand_keypair(Botan::DilithiumSeedRandomness(private_key_bits), std::move(mode));
    }
    /* we have to check 3 different format: "seed-only", "expanded-only", and "both"
     */
    decoding_func fn_arr [3] = {try_decode_both, try_decode_seed_only, try_decode_expanded_only};
        for(auto fn : fn_arr)
        {
            try 
            {
                return fn(private_key_bits, mode);
            }
            catch (Botan::Decoding_Error const& e)
            {
                // pass
            }
        } 
    throw Decoding_Error("unsupported ML-DSA private key format, key size in bytes: " + std::to_string(private_key_bits.size()));
}

}  // namespace Botan
