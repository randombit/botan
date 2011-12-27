/*
* TLS Session Management
* (C) 2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_session_state.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/asn1_str.h>
#include <botan/bigint.h>
#include <ctime>

namespace Botan {

TLS_Session_Params::TLS_Session_Params(const MemoryRegion<byte>& session_id,
                                       const MemoryRegion<byte>& master_secret,
                                       Version_Code version,
                                       u16bit ciphersuite,
                                       byte compression_method,
                                       Connection_Side side,
                                       const X509_Certificate* cert,
                                       const std::string& sni_hostname,
                                       const std::string& srp_identity) :
   session_start_time(time(0)),
   session_id(session_id),
   master_secret(master_secret),
   version(version),
   ciphersuite(ciphersuite),
   compression_method(compression_method),
   connection_side(side),
   sni_hostname(sni_hostname),
   srp_identity(srp_identity)
   {
   if(cert)
      peer_certificate = cert->BER_encode();
   }

TLS_Session_Params::TLS_Session_Params(const byte ber[], size_t ber_len)
   {
   // todo
   }

SecureVector<byte> TLS_Session_Params::BER_encode() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode(static_cast<size_t>(TLS_SESSION_PARAM_STRUCT_VERSION))
         .encode(session_id, OCTET_STRING)
         .encode(BigInt(session_start_time))
         .encode(static_cast<size_t>(version))
         .encode(static_cast<size_t>(ciphersuite))
         .encode(static_cast<size_t>(compression_method))
         .encode(static_cast<size_t>((connection_side == SERVER) ? 1 : 2))
         .encode(master_secret, OCTET_STRING)
         .encode(peer_certificate, OCTET_STRING)
         .encode(ASN1_String(sni_hostname, UTF8_STRING))
         .encode(ASN1_String(srp_identity, UTF8_STRING))
      .end_cons()
   .get_contents();
   }

bool TLS_Session_Manager_In_Memory::find(const MemoryVector<byte>& session_id,
                                         TLS_Session_Params& params,
                                         Connection_Side side)
   {
   std::map<std::string, TLS_Session_Params>::const_iterator i =
      sessions.find(hex_encode(session_id));

   if(i != sessions.end() && i->second.connection_side == side)
      {
      params = i->second;
      return true;
      }

   return false;
   }

void TLS_Session_Manager_In_Memory::prohibit_resumption(const MemoryVector<byte>& session_id)
   {
   std::map<std::string, TLS_Session_Params>::iterator i =
      sessions.find(hex_encode(session_id));

   if(i != sessions.end())
      sessions.erase(i);
   }

void TLS_Session_Manager_In_Memory::save(const TLS_Session_Params& session_data)
   {
   if(max_sessions != 0)
      {
      while(sessions.size() >= max_sessions)
         sessions.erase(sessions.begin());
      }

   sessions[hex_encode(session_data.session_id)] = session_data;
   }

}
