/*
* Asymmetric primitives for ML-DSA
* (C) 2024 Jack Lloyd
* (C) 2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "botan/asn1_obj.h"
#include <botan/internal/ml_dsa_impl.h>

#include <botan/internal/dilithium_algos.h>

#include <botan/der_enc.h>

#include <iostream>

namespace Botan {

secure_vector<uint8_t> ML_DSA_Expanding_Keypair_Codec::encode_keypair(DilithiumInternalKeypair keypair) const {
   BOTAN_ASSERT_NONNULL(keypair.second);
   const auto& seed = keypair.second->seed();
   const DilithiumSerializedPrivateKey& expandedKey_strong = Dilithium_Algos::encode_keypair(keypair);
   BOTAN_ARG_CHECK(seed.has_value(), "Cannot encode keypair without the private seed");
    secure_vector<uint8_t> result;
    DER_Encoder der_enc(result);
    der_enc.start_context_specific(0).encode(seed.value().get(), ASN1_Type(Botan::ASN1_Type::OctetString) ).end_cons();
    
    /* 
     * der_enc.start_context_specific(0).encode(seed.value().get(), ASN1_Type(Botan::ASN1_Type::OctetString) ).end_cons();
     * leads to 
     *
            <A0 22>
          0  34: [0] {
            <04 20>
          2  32:   OCTET STRING
               :     BF B1 FE C1 89 8C F2 38 02 79 3C 34 98 1D C1 4D
               :     DC 18 10 0B F0 79 57 42 F5 FE FD E3 78 60 8F D2
               :   }
     * which OpenSSL cannot decode. The previous format, which only contains the seed as OS without the [0]-tag, it can decode. 
     * Reason: it has to look like this test vector from :
            <80 20>
          0  32: [0]
               :   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
               :   10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
           */
    std::cerr << "println encoder called\n";
   return result; 
   //return seed.value().get(); 
}

DilithiumInternalKeypair ML_DSA_Expanding_Keypair_Codec::decode_keypair(std::span<const uint8_t> private_key_seed,
                                                                        DilithiumConstants mode) const {
   return Dilithium_Algos::expand_keypair(DilithiumSeedRandomness(private_key_seed), std::move(mode));
}

}  // namespace Botan
