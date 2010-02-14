/**
* TLS Hello Messages
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_messages.h>
#include <botan/loadstor.h>

namespace Botan {

/**
* Encode and send a Handshake message
*/
void HandshakeMessage::send(Record_Writer& writer, HandshakeHash& hash) const
   {
   SecureVector<byte> buf = serialize();
   SecureVector<byte> send_buf(4);

   u32bit buf_size = buf.size();

   send_buf[0] = type();
   send_buf[1] = get_byte(1, buf_size);
   send_buf[2] = get_byte(2, buf_size);
   send_buf[3] = get_byte(3, buf_size);

   send_buf.append(buf);

   hash.update(send_buf);

   writer.send(HANDSHAKE, send_buf, send_buf.size());
   writer.flush();
   }

/**
* Create a new Hello Request message
*/
Hello_Request::Hello_Request(Record_Writer& writer)
   {
   HandshakeHash dummy; // FIXME: *UGLY*
   send(writer, dummy);
   }

/**
* Serialize a Hello Request message
*/
SecureVector<byte> Hello_Request::serialize() const
   {
   return SecureVector<byte>();
   }

/**
* Deserialize a Hello Request message
*/
void Hello_Request::deserialize(const MemoryRegion<byte>& buf)
   {
   if(buf.size())
      throw Decoding_Error("Hello_Request: Must be empty, and is not");
   }

/**
* Create a new Client Hello message
*/
Client_Hello::Client_Hello(RandomNumberGenerator& rng,
                           Record_Writer& writer, const Policy* policy,
                           HandshakeHash& hash)
   {
   c_random.resize(32);
   rng.randomize(c_random, c_random.size());

   suites = policy->ciphersuites();
   comp_algos = policy->compression();
   c_version = policy->pref_version();

   send(writer, hash);
   }

/**
* Serialize a Client Hello message
*/
SecureVector<byte> Client_Hello::serialize() const
   {
   SecureVector<byte> buf;

   buf.append(static_cast<byte>(c_version >> 8));
   buf.append(static_cast<byte>(c_version     ));
   buf.append(c_random);
   buf.append(static_cast<byte>(sess_id.size()));
   buf.append(sess_id);

   u16bit suites_size = 2*suites.size();

   buf.append(get_byte(0, suites_size));
   buf.append(get_byte(1, suites_size));
   for(u32bit j = 0; j != suites.size(); j++)
      {
      buf.append(get_byte(0, suites[j]));
      buf.append(get_byte(1, suites[j]));
      }

   buf.append(static_cast<byte>(comp_algos.size()));
   for(u32bit j = 0; j != comp_algos.size(); j++)
      buf.append(comp_algos[j]);

   return buf;
   }

/**
* Deserialize a Client Hello message
*/
void Client_Hello::deserialize(const MemoryRegion<byte>& buf)
   {
   if(buf.size() == 0)
      throw Decoding_Error("Client_Hello: Packet corrupted");

   if(buf.size() < 41)
      throw Decoding_Error("Client_Hello: Packet corrupted");

   c_version = static_cast<Version_Code>(make_u16bit(buf[0], buf[1]));
   if(c_version != SSL_V3 && c_version != TLS_V10)
      throw TLS_Exception(PROTOCOL_VERSION, "Client_Hello: Bad version code");

   c_random.set(buf + 2, 32);

   u32bit session_id_len = buf[34];
   if(session_id_len > 32 || session_id_len + 41 > buf.size())
      throw Decoding_Error("Client_Hello: Packet corrupted");
   sess_id.copy(buf + 35, session_id_len);

   u32bit offset = 2+32+1+session_id_len;

   u16bit suites_size = make_u16bit(buf[offset], buf[offset+1]);
   offset += 2;
   if(suites_size % 2 == 1 || offset + suites_size + 2 > buf.size())
      throw Decoding_Error("Client_Hello: Packet corrupted");

   for(u32bit j = 0; j != suites_size; j += 2)
      {
      u16bit suite = make_u16bit(buf[offset+j], buf[offset+j+1]);
      suites.push_back(suite);
      }
   offset += suites_size;

   byte comp_algo_size = buf[offset];
   offset += 1;
   if(offset + comp_algo_size > buf.size())
      throw Decoding_Error("Client_Hello: Packet corrupted");

   for(u32bit j = 0; j != comp_algo_size; j++)
      comp_algos.push_back(buf[offset+j]);
   }

/**
* Check if we offered this ciphersuite
*/
bool Client_Hello::offered_suite(u16bit ciphersuite) const
   {
   for(u32bit j = 0; j != suites.size(); j++)
      if(suites[j] == ciphersuite)
         return true;
   return false;
   }

/**
* Create a new Server Hello message
*/
Server_Hello::Server_Hello(RandomNumberGenerator& rng,
                           Record_Writer& writer, const Policy* policy,
                           const std::vector<X509_Certificate>& certs,
                           const Client_Hello& c_hello, Version_Code ver,
                           HandshakeHash& hash)
   {
   bool have_rsa = false, have_dsa = false;
   for(u32bit j = 0; j != certs.size(); j++)
      {
      X509_PublicKey* key = certs[j].subject_public_key();
      if(key->algo_name() == "RSA") have_rsa = true;
      if(key->algo_name() == "DSA") have_dsa = true;
      }

   suite = policy->choose_suite(c_hello.ciphersuites(), have_rsa, have_dsa);
   comp_algo = policy->choose_compression(c_hello.compression_algos());

   s_version = ver;
   s_random.resize(32);
   rng.randomize(s_random, s_random.size());

   send(writer, hash);
   }

/**
* Serialize a Server Hello message
*/
SecureVector<byte> Server_Hello::serialize() const
   {
   SecureVector<byte> buf;

   buf.append(static_cast<byte>(s_version >> 8));
   buf.append(static_cast<byte>(s_version     ));
   buf.append(s_random);
   buf.append(static_cast<byte>(sess_id.size()));
   buf.append(sess_id);

   buf.append(get_byte(0, suite));
   buf.append(get_byte(1, suite));

   buf.append(comp_algo);

   return buf;
   }

/**
* Deserialize a Server Hello message
*/
void Server_Hello::deserialize(const MemoryRegion<byte>& buf)
   {
   if(buf.size() < 38)
      throw Decoding_Error("Server_Hello: Packet corrupted");

   s_version = static_cast<Version_Code>(make_u16bit(buf[0], buf[1]));
   if(s_version != SSL_V3 && s_version != TLS_V10)
      throw TLS_Exception(PROTOCOL_VERSION,
                          "Server_Hello: Unsupported server version");

   s_random.set(buf + 2, 32);

   u32bit session_id_len = buf[2+32];
   if(session_id_len > 32 || session_id_len + 38 != buf.size())
      throw Decoding_Error("Server_Hello: Packet corrupted");
   sess_id.copy(buf + 2 + 32 + 1, session_id_len);

   suite = make_u16bit(buf[2+32+1+session_id_len],
                       buf[2+32+1+session_id_len+1]);
   comp_algo = buf[2+32+1+session_id_len+2];
   }


/**
* Create a new Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(Record_Writer& writer,
                                     HandshakeHash& hash)
   {
   send(writer, hash);
   }

/**
* Serialize a Server Hello Done message
*/
SecureVector<byte> Server_Hello_Done::serialize() const
   {
   return SecureVector<byte>();
   }

/**
* Deserialize a Server Hello Done message
*/
void Server_Hello_Done::deserialize(const MemoryRegion<byte>& buf)
   {
   if(buf.size())
      throw Decoding_Error("Server_Hello_Done: Must be empty, and is not");
   }

}
