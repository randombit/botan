/*
* Finished Message
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/prf_tls.h>

namespace Botan {

/**
* Create a new Finished message
*/
Finished::Finished(Record_Writer& writer,
                   Version_Code version, Connection_Side side,
                   const MemoryRegion<byte>& master_secret,
                   HandshakeHash& hash)
   {
   verification_data = compute_verify(master_secret, hash, side, version);
   send(writer, hash);
   }

/**
* Serialize a Finished message
*/
SecureVector<byte> Finished::serialize() const
   {
   return verification_data;
   }

/**
* Deserialize a Finished message
*/
void Finished::deserialize(const MemoryRegion<byte>& buf)
   {
   verification_data = buf;
   }

/**
* Verify a Finished message
*/
bool Finished::verify(const MemoryRegion<byte>& secret, Version_Code version,
                      const HandshakeHash& hash, Connection_Side side)
   {
   SecureVector<byte> computed = compute_verify(secret, hash, side, version);
   if(computed == verification_data)
      return true;
   return false;
   }

/**
* Compute the verify_data
*/
SecureVector<byte> Finished::compute_verify(const MemoryRegion<byte>& secret,
                                            HandshakeHash hash,
                                            Connection_Side side,
                                            Version_Code version)
   {
   if(version == SSL_V3)
      {
      const byte SSL_CLIENT_LABEL[] = { 0x43, 0x4C, 0x4E, 0x54 };
      const byte SSL_SERVER_LABEL[] = { 0x53, 0x52, 0x56, 0x52 };

      SecureVector<byte> ssl3_finished;

      if(side == CLIENT)
         hash.update(SSL_CLIENT_LABEL, sizeof(SSL_CLIENT_LABEL));
      else
         hash.update(SSL_SERVER_LABEL, sizeof(SSL_SERVER_LABEL));

      return hash.final_ssl3(secret);
      }
   else if(version == TLS_V10 || version == TLS_V11)
      {
      const byte TLS_CLIENT_LABEL[] = {
         0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x66, 0x69, 0x6E, 0x69,
         0x73, 0x68, 0x65, 0x64 };

      const byte TLS_SERVER_LABEL[] = {
         0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x66, 0x69, 0x6E, 0x69,
         0x73, 0x68, 0x65, 0x64 };

      TLS_PRF prf;

      SecureVector<byte> input;
      if(side == CLIENT)
         input += std::make_pair(TLS_CLIENT_LABEL, sizeof(TLS_CLIENT_LABEL));
      else
         input += std::make_pair(TLS_SERVER_LABEL, sizeof(TLS_SERVER_LABEL));
      input += hash.final();

      return prf.derive_key(12, secret, input);
      }
   else
      throw Invalid_Argument("Finished message: Unknown protocol version");
   }

}
