#include <botan/ec_group.h>
#include <botan/hash.h>
#include <vector>
#include <span>

#include <iostream>
#include <botan/hex.h>

namespace Botan {


void leb128_encode(size_t len, std::vector<uint8_t>& out) {
   while(len > 0) {
      const uint8_t next = static_cast<uint8_t>(len & 0x7F);
      if(len < 128) {
         out.push_back(next);
      } else {
         out.push_back(next | 0x80);
      }
      len >>= 7;
   }
}

void prepend_length(std::string_view s, std::vector<uint8_t>& out) {
   leb128_encode(s.size(), out);
   const uint8_t* b = reinterpret_cast<const uint8_t*>(s.data());
   out.insert(out.end(), b, b + s.size());
}

void prepend_length(std::span<const uint8_t> s, std::vector<uint8_t>& out) {
   leb128_encode(s.size(), out);
   out.insert(out.end(), s.begin(), s.end());
}

std::string cpace_domain_sep(const EC_Group& group) {
   const OID& oid = group.get_curve_oid();

   // secp256r1
   if(oid == OID{1, 2, 840, 10045, 3, 1, 7}) {
      return "CPaceP256_XMD:SHA-256_SSWU_NU_";
   }
   // secp384r1
   if(oid == OID{1, 3, 132, 0, 34}) {
      return "CPaceP384_XMD:SHA-384_SSWU_NU_";
   }
   // secp521r1
   if(oid == OID{1, 3, 132, 0, 35}) {
      return "CPaceP521_XMD:SHA-512_SSWU_NU_";
   }

   throw Not_Implemented("CPACE is not implemented for this group");
}

std::vector<uint8_t> generator_string(
   std::string_view domain_separator,
   std::string_view password,
   std::span<const uint8_t> channel_id,
   std::span<const uint8_t> session_id,
   size_t hash_block_size) {

   std::vector<uint8_t> gs;

   prepend_length(domain_separator, gs);
   prepend_length(password, gs);

   if(gs.size() < hash_block_size) {
      size_t len_zpad = hash_block_size - gs.size() - 1;
      prepend_length(std::vector<uint8_t>(len_zpad), gs);
   }

   prepend_length(channel_id, gs);
   prepend_length(session_id, gs);

   /*
   *  generator_string(G.DSI, PRS, CI, sid, s_in_bytes) denotes a
      function that returns the string lv_cat(G.DSI, PRS,
      zero_bytes(len_zpad), CI, sid).

   *  len_zpad = MAX(0, s_in_bytes - len(prepend_len(PRS)) -
      len(prepend_len(G.DSI)) - 1)
   */

   return gs;
}

EC_Point cpace_generator(const EC_Group& group,
                         std::string_view password,
                         std::span<const uint8_t> channel_id,
                         std::span<const uint8_t> session_id) {

   std::string hash_fn = "SHA-256";
   size_t hash_block_size = 64;
   std::string ds = cpace_domain_sep(group);

   printf("%s\n", ds.c_str());

   auto gs = generator_string(ds,
                              password,
                              channel_id,
                              session_id,
                              hash_block_size);

   std::string ds2 = "P256_XMD:SHA-256_SSWU_NU_";
   std::cout << "GS: " << hex_encode(gs) << "\n";
   return group.hash_to_curve(hash_fn, gs.data(), gs.size(),
                              reinterpret_cast<const uint8_t*>(ds2.data()),
                              ds2.size(), false);
}



}

int main() {
   const std::string password = "Password";
   const std::vector<uint8_t> channel_id = Botan::hex_decode("0a41696e69746961746f720a42726573706f6e646572");
   const std::vector<uint8_t> sid = Botan::hex_decode("34b36454cab2e7842c389f7d88ecb7df");
   //DSI = b'CPaceP256_XMD:SHA-256_SSWU_NU_'
   const Botan::EC_Group group("secp256r1");

   /*
1e4350616365503235365f584d443a5348412d3235365f535357555f4e555f0850617373776f7264170000000000000000000000000000000000000000000000160a41696e69746961746f720a42726573706f6e6465721034b36454cab2e7842c389f7d88ecb7df

1E4350616365503235365F584D443A5348412D3235365F535357555F4E555F0850617373776F7264170000000000000000000000000000000000000000000000160A41696E69746961746F720A42726573706F6E6465721034B36454CAB2E7842C389F7D88ECB7DF
   */
   auto point = Botan::cpace_generator(group, password, channel_id, sid);

   std::cout << "G = " << Botan::hex_encode(point.encode(Botan::EC_Point_Format::Uncompressed)) << "\n";
}
