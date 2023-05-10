/*
* WOTS+ - Winternitz One Time Signature+
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include <botan/internal/sp_hash.h>
#include <botan/internal/sp_wots.h>

namespace Botan
{

void gen_chain(std::span<uint8_t> out,
                         std::span<const uint8_t> wots_chain_key,
                         uint8_t start, uint8_t steps,
                         const SphincsPublicSeed& public_seed, Sphincs_Address& addr,
                         Sphincs_Hash_Functions& hashes, const Sphincs_Parameters& params)
{
   /* Initialize out with the value at position 'start'. */
   std::copy(wots_chain_key.begin(), wots_chain_key.end(), out.begin());

   /* Iterate 'steps' calls to the hash function. */
   for (uint8_t i = start; i < (start+steps) && i < params.w(); i++)
      {
      addr.set_hash(i);

      hashes.T(out, public_seed, addr, out);
      }
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
WotsBaseWChunks base_w(const uint32_t out_len,
                       const std::vector<uint8_t>& input, const Sphincs_Parameters& params)
{
   WotsBaseWChunks output(out_len);
   size_t in = 0;
   size_t out = 0;
   uint8_t total;
   int8_t bits = 0;

   for (uint32_t consumed = 0; consumed < out_len; consumed++, out++)
       {
       if (bits == 0)
           {
           total = input.at(in);
           in++;
           bits += 8;
           }
       bits -= params.log_w();
       output.get()[out] = (total >> bits) & (params.w() - 1);
       }

   return output;
}

/* Computes the WOTS+ checksum over a message (in base_w). */
WotsBaseWChunks wots_checksum(const WotsBaseWChunks& msg_base_w, const Sphincs_Parameters& params)
   {
   uint32_t csum = 0;

   size_t csum_bytes_size = (params.wots_len_2() * params.log_w() + 7) / 8;
   std::vector<uint8_t> csum_bytes(4);

   /* Compute checksum. */
   for (uint8_t i = 0; i < params.wots_len_1(); i++)
      {
      csum += params.w() - 1 - msg_base_w.get().at(i);
      }

   /* Convert checksum to base_w. */
   csum = csum << ((8 - ((params.wots_len_2() * params.log_w()) % 8)) % 8);
   store_be(csum, csum_bytes.data());
   csum_bytes = std::vector<uint8_t>(csum_bytes.end() - csum_bytes_size, csum_bytes.end());
   return base_w(params.wots_len_2(), csum_bytes, params);
   }

/* Takes a message and derives the matching chain lengths. */
WotsBaseWChunks chain_lengths(const SphincsHashedMessage& msg, const Sphincs_Parameters& params)
   {
   WotsBaseWChunks lengths_msg = base_w(params.wots_len_1(), msg.get(), params);
   WotsBaseWChunks lengths_checksum = wots_checksum(lengths_msg, params);

   lengths_msg.get().insert(lengths_msg.end(), lengths_checksum.begin(), lengths_checksum.end() ); //lengths_msg || lengths_checksum
   return lengths_msg;
   }

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 */
WotsPublicKey wots_public_key_from_signature(const SphincsHashedMessage& hashed_message,
                                             const WotsSignature& signature,
                                             const SphincsPublicSeed& public_seed,
                                             Sphincs_Address& address,
                                             const Sphincs_Parameters& params,
                                             Sphincs_Hash_Functions& hashes)
   {
   WotsBaseWChunks lengths = chain_lengths(hashed_message, params);
   WotsPublicKey pk(params.wots_len() * params.n());

   for (uint32_t i = 0; i < params.wots_len(); i++)
      {
      address.set_chain(i);
      auto pk_location = std::span(pk).subspan(i*params.n(), params.n());
      auto sig_location = std::span(signature).subspan(i*params.n(), params.n());
      gen_chain(pk_location, sig_location,
              lengths.get().at(i), params.w() - 1 - lengths.get().at(i), public_seed, address, hashes, params);
      }

   return pk;
   }

void wots_gen_leaf_spec(std::span<uint8_t> sig_out,
                        std::span<uint8_t> pk_out,
                        const SphincsSecretSeed& secret_seed,
                        const SphincsPublicSeed& public_seed,
                        uint32_t leaf_idx,
                        uint32_t sign_leaf_idx,
                        WotsBaseWChunks& wots_steps,
                        Sphincs_Address& leaf_addr,
                        Sphincs_Address& pk_addr,
                        const Sphincs_Parameters& params,
                        Sphincs_Hash_Functions& hashes)
   {
   std::vector<uint8_t> wots_sig;
   std::vector<uint8_t> pk_buffer(params.wots_bytes());

   uint32_t wots_k_mask;

   if (leaf_idx == sign_leaf_idx) {
      /* We're traversing the leaf that's signing; generate the WOTS */
      /* signature */
      wots_k_mask = 0;
   } else {
      /* Nope, we're just generating pk's; turn off the signature logic */
      wots_k_mask = static_cast<uint32_t>(~0);
   }

   leaf_addr.set_keypair(leaf_idx);
   pk_addr.set_keypair(leaf_idx);

   for(uint32_t i = 0; i < params.wots_len(); i++)
      {
      uint32_t wots_k = wots_steps.get().at(i) | wots_k_mask; /* Set wots_k to */
      /* the step if we're generating a signature, ~0 if we're not */

      /* Start with the secret seed */
      leaf_addr.set_chain(i);
      leaf_addr.set_hash(0);
      leaf_addr.set_type(Sphincs_Address_Type::WotsKeyGeneration);

      auto buffer = std::span(pk_buffer).subspan(i * params.n(), params.n());

      hashes.PRF(buffer, public_seed, secret_seed, leaf_addr);

      leaf_addr.set_type(Sphincs_Address_Type::WotsHash);

      /* Iterate down the WOTS chain */
      for (size_t k=0;; k++)
         {
         /* Check if this is the value that needs to be saved as a */
         /* part of the WOTS signature */
         if (k == wots_k)
            {
            auto sig_location = sig_out.subspan(i * params.n(), params.n());
            std::copy(buffer.begin(), buffer.end(), sig_location.begin());
            }

         /* Check if we hit the top of the chain */
         if (k == params.w() - 1) break;

         /* Iterate one step on the chain */
         leaf_addr.set_hash(k);

         hashes.T(buffer, public_seed, leaf_addr, buffer);
         }
      }

   /* Do the final thash to generate the public keys */
   hashes.T(pk_out, public_seed, pk_addr, pk_buffer);
   }

}