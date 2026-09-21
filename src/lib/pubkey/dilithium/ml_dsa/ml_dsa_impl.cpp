/*
* Asymmetric primitives for ML-DSA
* (C) 2024 Jack Lloyd
* (C) 2024 Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ml_dsa_impl.h>

#include <botan/asn1_obj.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/dilithium_algos.h>
#include <botan/internal/dilithium_types.h>
#include <utility>

namespace Botan {

namespace {

DilithiumInternalKeypair decode_seed_only(std::span<const uint8_t> key_bits, DilithiumConstants mode) {
   DilithiumSeedRandomness seed;
   BER_Decoder(key_bits).decode(seed, ASN1_Type::OctetString, ASN1_Type(0), ASN1_Class::ContextSpecific).verify_end();
   if(seed.size() != DilithiumConstants::SEED_RANDOMNESS_BYTES) {
      throw Decoding_Error("invalid length of ML-DSA private key seed");
   }
   return Dilithium_Algos::expand_keypair(std::move(seed), std::move(mode));
}

DilithiumInternalKeypair decode_expanded_only(std::span<const uint8_t> key_bits, DilithiumConstants mode) {
   DilithiumSerializedPrivateKey expanded;
   BER_Decoder(key_bits).decode(expanded, ASN1_Type::OctetString).verify_end();
   if(expanded.size() != mode.private_key_bytes()) {
      throw Decoding_Error("invalid length of ML-DSA (or Dilithium) expanded private key byte string");
   }
   // decode_keypair() takes a strong span, hence no std::move
   return Dilithium_Algos::decode_keypair(expanded, std::move(mode));
}

DilithiumInternalKeypair decode_seed_plus_expanded(std::span<const uint8_t> key_bits, DilithiumConstants mode) {
   DilithiumSerializedPrivateKey expanded;
   DilithiumSeedRandomness seed;
   BER_Decoder(key_bits)
      .start_sequence()
      .decode(seed, ASN1_Type::OctetString)
      .decode(expanded, ASN1_Type::OctetString)
      .end_cons()
      .verify_end();
   if(expanded.size() != mode.private_key_bytes()) {
      throw Decoding_Error("invalid length of ML-DSA expanded private key byte string");
   }
   // The expanded key is not parsed on its own: it must be byte-identical to the
   // canonical encoding of the key pair expanded from the seed, which is what is returned.
   const DilithiumInternalKeypair key_pair_from_seed =
      Dilithium_Algos::expand_keypair(std::move(seed), std::move(mode));
   const DilithiumSerializedPrivateKey expanded_from_seed = Dilithium_Algos::encode_keypair(key_pair_from_seed);
   // both operands are secret key material, hence the constant-time comparison
   if(!constant_time_compare(expanded_from_seed.get(), expanded.get())) {
      throw Decoding_Error("seed and expanded key in ML-DSA serialized key do not match");
   }
   return key_pair_from_seed;
}

}  // namespace

secure_vector<uint8_t> ML_DSA_Expanding_Keypair_Codec::encode_keypair(const DilithiumInternalKeypair& keypair,
                                                                      MlPrivateKeyFormat format) const {
   BOTAN_ASSERT_NONNULL(keypair.second);
   const auto& seed = keypair.second->seed();
   if(format != MlPrivateKeyFormat::Expanded && !seed.has_value()) {
      throw Encoding_Error("ML-DSA private key does not contain the seed, cannot encode it in the requested format");
   }

   secure_vector<uint8_t> result;
   DER_Encoder der_enc(result);
   switch(format) {
      case MlPrivateKeyFormat::Seed:
         /*
          * RFC 9881 "seed" CHOICE alternative: [0] IMPLICIT OCTET STRING, i.e.
          *
          * <80 20>
          * 0  32: [0]
          *      :   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
          *      :   10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
          *
          * Note: The previous, non-standard format, which only contained the
          * seed as a raw byte string, is still accepted by decode_keypair().
          */
         der_enc.encode(seed->get(), ASN1_Type::OctetString, ASN1_Type(0), ASN1_Class::ContextSpecific);
         break;
      case MlPrivateKeyFormat::Expanded:
         // RFC 9881 "expandedKey" CHOICE alternative: OCTET STRING
         der_enc.encode(Dilithium_Algos::encode_keypair(keypair).get(), ASN1_Type::OctetString);
         break;
      case MlPrivateKeyFormat::Both:
         // RFC 9881 "both" CHOICE alternative:
         // SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING }
         der_enc.start_sequence()
            .encode(seed->get(), ASN1_Type::OctetString)
            .encode(Dilithium_Algos::encode_keypair(keypair).get(), ASN1_Type::OctetString)
            .end_cons();
         break;
   }

   return result;
}

DilithiumDecodedKeypair ML_DSA_Expanding_Keypair_Codec::decode_keypair(std::span<const uint8_t> private_key_bits,
                                                                       DilithiumConstants mode) const {
   if(private_key_bits.size() == DilithiumConstants::SEED_RANDOMNESS_BYTES) {
      // backwards compatibility (not RFC 9881 conforming) to the raw seed format
      return {
         .keypair = Dilithium_Algos::expand_keypair(DilithiumSeedRandomness(private_key_bits), std::move(mode)),
         .format = MlPrivateKeyFormat::Seed,
      };
   }
   if(private_key_bits.size() == mode.private_key_bytes()) {
      // raw expanded key in the FIPS 204 sk encoding without ASN.1 wrapping (not RFC 9881 conforming),
      // as used e.g. by the NIST ACVP and Wycheproof test vectors. The length cannot collide with any
      // of the RFC 9881 encodings.
      return {
         .keypair = Dilithium_Algos::decode_keypair(StrongSpan<const DilithiumSerializedPrivateKey>(private_key_bits),
                                                    std::move(mode)),
         .format = MlPrivateKeyFormat::Expanded,
      };
   }
   // "seed-only" format from RFC 9881
   BER_Decoder ber_dec(private_key_bits);
   auto obj = ber_dec.peek_next_object();
   if(obj.type() == ASN1_Type(0) && obj.class_tag() == ASN1_Class::ContextSpecific) {
      return {
         .keypair = decode_seed_only(private_key_bits, std::move(mode)),
         .format = MlPrivateKeyFormat::Seed,
      };
   }
   // now it could still be "expanded-only" or "both"
   if(obj.type() == ASN1_Type::OctetString && obj.class_tag() == ASN1_Class::Universal) {
      return {
         .keypair = decode_expanded_only(private_key_bits, std::move(mode)),
         .format = MlPrivateKeyFormat::Expanded,
      };
   }
   return {
      .keypair = decode_seed_plus_expanded(private_key_bits, std::move(mode)),
      .format = MlPrivateKeyFormat::Both,
   };
}

}  // namespace Botan
