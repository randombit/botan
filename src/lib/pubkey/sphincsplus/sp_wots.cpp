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

WotsChainValue gen_chain(/*std::span<uint8_t> out,*/
                         const WotsChainKey in,
                         uint8_t start, uint8_t steps,
                         const SphincsPublicSeed& public_seed, Sphincs_Address& addr,
                         Sphincs_Hash_Functions& hashes, const Sphincs_Parameters& params)
{
   /* Initialize out with the value at position 'start'. */
   WotsChainValue out(in.get());

   /* Iterate 'steps' calls to the hash function. */
   for (uint8_t i = start; i < (start+steps) && i < params.w(); i++)
      {
      addr.set_hash(i);

      hashes.T(out, public_seed, addr, out);
      }

    return out;
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
WotsBaseWChunks base_w(const uint32_t out_len,
                       const WotsBaseWChunks& input, const Sphincs_Parameters& params)
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
           total = input.get().at(in);
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
   //unsigned char csum_bytes[(params.wots_len_2() * params.log_w() + 7) / 8];

   /* Compute checksum. */
   for (uint8_t i = 0; i < params.wots_len_1(); i++)
      {
      csum += params.w() - 1 - msg_base_w.get().at(i);
      }

   /* Convert checksum to base_w. 10010 0000 0000 */
   csum = csum << ((8 - ((params.wots_len_2() * params.log_w()) % 8)) % 8);
   store_be(csum, csum_bytes.data());
   //ull_to_bytes(csum_bytes, csum_bytes.size(), csum);
   //csum_bytes.resize(csum_bytes_size); // TODO: Validate
   csum_bytes = std::vector<uint8_t>(csum_bytes.end() - csum_bytes_size, csum_bytes.end());
   return base_w(params.wots_len_2(), WotsBaseWChunks(csum_bytes), params);
   }

/* Takes a message and derives the matching chain lengths. */
WotsBaseWChunks chain_lengths(const WotsBaseWChunks msg, const Sphincs_Parameters& params)
   {
   WotsBaseWChunks lengths_msg = base_w(params.wots_len_1(), msg, params);
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
   WotsBaseWChunks msg(hashed_message);
   WotsBaseWChunks lengths = chain_lengths(msg, params);
   WotsPublicKey pk;

   lengths = chain_lengths(msg, params);
   for (uint32_t i = 0; i < params.wots_len(); i++)
      {
      address.set_chain(i);
      WotsChainKey sig_location = WotsChainKey(std::vector<uint8_t>(signature.begin() + i*params.n(), signature.begin() + (i+1)*params.n()));
      auto pk_element = gen_chain(sig_location,
              lengths.get().at(i), params.w() - 1 - lengths.get().at(i), public_seed, address, hashes, params);
      pk.get().insert(pk.end(), pk_element.begin(), pk_element.end());
      //pk.get().emplace_back(gen_chain(sig_location,
      //   lengths.get().at(i), params.w() - 1 - lengths.get().at(i), public_seed, address, hashes, params).g);
      }

    return pk;
   }

std::pair<WotsPublicKey, WotsSignature> wots_sign(const SphincsHashedMessage& hashed_message,
                                                                 const SphincsSecretSeed& secret_seed,
                                                                 const SphincsPublicSeed& public_seed,
                                                                 const Sphincs_Address& address,
                                                                 const Sphincs_Parameters& params,
                                                                 Sphincs_Hash_Functions& hash)
   {

   //TODO

   }



}