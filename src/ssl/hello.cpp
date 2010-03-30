/**
* TLS Hello Messages
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_messages.h>
#include <botan/internal/tls_reader.h>

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
                           Record_Writer& writer, const TLS_Policy* policy,
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
   for(u32bit i = 0; i != suites.size(); i++)
      {
      buf.append(get_byte(0, suites[i]));
      buf.append(get_byte(1, suites[i]));
      }

   buf.append(static_cast<byte>(comp_algos.size()));
   for(u32bit i = 0; i != comp_algos.size(); i++)
      buf.append(comp_algos[i]);

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

   TLS_Data_Reader reader(buf);

   c_version = static_cast<Version_Code>(reader.get_u16bit());
   c_random = reader.get_fixed<byte>(32);

   sess_id = reader.get_range<byte>(1, 0, 32);

   suites = reader.get_range_vector<u16bit>(2, 1, 32767);

   comp_algos = reader.get_range_vector<byte>(1, 1, 255);

#if 0
   if(offset != buf.size()) // extensions?
      {
      if(buf.size() - offset < 2)
         throw Decoding_Error("Client_Hello: Packet corrupted");

      const u16bit extens_size = make_u16bit(buf[offset], buf[offset+1]);
      offset += 2;

      /*
      RFC 3546 says if Extensions are present in the Client Hello,
      then there is no other data following, and we MUST fail in this
      case.
      */
      if(buf.size() - offset != extens_size)
         throw Decoding_Error("Client_Hello: Packet corrupted");

      while(offset < buf.size())
         {
         if(buf.size() - offset < 4)
            throw Decoding_Error("Client_Hello: Packet corrupted");

         u16bit extn_code = make_u16bit(buf[offset  ], buf[offset+1]);
         u16bit extn_size = make_u16bit(buf[offset+2], buf[offset+3]);

         offset += 4;

         if(buf.size() - offset < extn_size)
            throw Decoding_Error("Client_Hello: Packet corrupted");

         if(extn_code == 0) // server name indication
            {
            if(extn_size < 2)
               throw Decoding_Error("Client_Hello: Packet corrupted");

            u16bit name_count = make_u16bit(buf[offset], buf[offset+1]);

            for(u32bit i = 0; i != name_count; ++i)
               {

               }
            }
         else
            offset += extn_size; // skip it
         }
      }
#endif
   }

/**
* Check if we offered this ciphersuite
*/
bool Client_Hello::offered_suite(u16bit ciphersuite) const
   {
   for(u32bit i = 0; i != suites.size(); i++)
      if(suites[i] == ciphersuite)
         return true;
   return false;
   }

/**
* Create a new Server Hello message
*/
Server_Hello::Server_Hello(RandomNumberGenerator& rng,
                           Record_Writer& writer, const TLS_Policy* policy,
                           const std::vector<X509_Certificate>& certs,
                           const Client_Hello& c_hello, Version_Code ver,
                           HandshakeHash& hash)
   {
   bool have_rsa = false, have_dsa = false;

   for(u32bit i = 0; i != certs.size(); i++)
      {
      Public_Key* key = certs[i].subject_public_key();
      if(key->algo_name() == "RSA")
         have_rsa = true;

      if(key->algo_name() == "DSA")
         have_dsa = true;
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

   TLS_Data_Reader reader(buf);

   s_version = static_cast<Version_Code>(reader.get_u16bit());

   if(s_version != SSL_V3 && s_version != TLS_V10 && s_version != TLS_V11)
      {
      throw TLS_Exception(PROTOCOL_VERSION,
                          "Server_Hello: Unsupported server version");
      }

   s_random = reader.get_fixed<byte>(32);

   sess_id = reader.get_range<byte>(1, 0, 32);

   suite = reader.get_u16bit();

   comp_algo = reader.get_byte();
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
