/*
* (C) 2022 Jack Lloyd
* (C) 2022 René Meusel - neXenio GmbH
* (C) 2022 Lukas Zeller - neXenio GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/internal/tls_handshake_layer_13.h>
#include <botan/internal/tls_transcript_hash_13.h>

namespace {

Botan::TLS::Handshake_Layer prepare(std::span<const uint8_t> data) {
   Botan::TLS::Handshake_Layer hl(Botan::TLS::Connection_Side::Client);
   hl.copy_data(data);
   return hl;
}

}  // namespace

void fuzz(std::span<const uint8_t> in) {
   static Botan::TLS::Default_Policy policy;

   try {
      auto hl1 = prepare(in);
      Botan::TLS::Transcript_Hash_State ths("SHA-256");
      while(hl1.next_message(policy, ths).has_value()) {};

      auto hl2 = prepare(in);
      while(hl2.next_post_handshake_message(policy).has_value()) {};
   } catch(Botan::Exception& e) {}
}
