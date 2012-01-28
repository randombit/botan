/*
* Finished Message
* (C) 2004-2006,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <memory>

namespace Botan {

namespace TLS {

namespace {

/*
* Compute the verify_data
*/
MemoryVector<byte> finished_compute_verify(Handshake_State* state,
                                           Connection_Side side)
   {
   if(state->version == Protocol_Version::SSL_V3)
      {
      const byte SSL_CLIENT_LABEL[] = { 0x43, 0x4C, 0x4E, 0x54 };
      const byte SSL_SERVER_LABEL[] = { 0x53, 0x52, 0x56, 0x52 };

      Handshake_Hash hash = state->hash; // don't modify state

      MemoryVector<byte> ssl3_finished;

      if(side == CLIENT)
         hash.update(SSL_CLIENT_LABEL, sizeof(SSL_CLIENT_LABEL));
      else
         hash.update(SSL_SERVER_LABEL, sizeof(SSL_SERVER_LABEL));

      return hash.final_ssl3(state->keys.master_secret());
      }
   else
      {
      const byte TLS_CLIENT_LABEL[] = {
         0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x66, 0x69, 0x6E, 0x69,
         0x73, 0x68, 0x65, 0x64 };

      const byte TLS_SERVER_LABEL[] = {
         0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x66, 0x69, 0x6E, 0x69,
         0x73, 0x68, 0x65, 0x64 };

      std::auto_ptr<KDF> prf(state->protocol_specific_prf());

      MemoryVector<byte> input;
      if(side == CLIENT)
         input += std::make_pair(TLS_CLIENT_LABEL, sizeof(TLS_CLIENT_LABEL));
      else
         input += std::make_pair(TLS_SERVER_LABEL, sizeof(TLS_SERVER_LABEL));

      input += state->hash.final(state->version, state->suite.mac_algo());

      return prf->derive_key(12, state->keys.master_secret(), input);
      }
   }

}

/*
* Create a new Finished message
*/
Finished::Finished(Record_Writer& writer,
                   Handshake_State* state,
                   Connection_Side side)
   {
   verification_data = finished_compute_verify(state, side);
   send(writer, state->hash);
   }

/*
* Serialize a Finished message
*/
MemoryVector<byte> Finished::serialize() const
   {
   return verification_data;
   }

/*
* Deserialize a Finished message
*/
Finished::Finished(const MemoryRegion<byte>& buf)
   {
   verification_data = buf;
   }

/*
* Verify a Finished message
*/
bool Finished::verify(Handshake_State* state,
                      Connection_Side side)
   {
   return (verification_data == finished_compute_verify(state, side));
   }

}

}
