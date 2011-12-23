/*
* TLS Hello Messages
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>

namespace Botan {

/*
* Encode and send a Handshake message
*/
void HandshakeMessage::send(Record_Writer& writer, HandshakeHash& hash) const
   {
   SecureVector<byte> buf = serialize();
   SecureVector<byte> send_buf(4);

   const size_t buf_size = buf.size();

   send_buf[0] = type();

   for(size_t i = 1; i != 4; ++i)
     send_buf[i] = get_byte<u32bit>(i, buf_size);

   send_buf += buf;

   hash.update(send_buf);

   writer.send(HANDSHAKE, &send_buf[0], send_buf.size());
   writer.flush();
   }

/*
* Create a new Hello Request message
*/
Hello_Request::Hello_Request(Record_Writer& writer)
   {
   HandshakeHash dummy; // FIXME: *UGLY*
   send(writer, dummy);
   }

/*
* Serialize a Hello Request message
*/
SecureVector<byte> Hello_Request::serialize() const
   {
   return SecureVector<byte>();
   }

/*
* Deserialize a Hello Request message
*/
void Hello_Request::deserialize(const MemoryRegion<byte>& buf)
   {
   if(buf.size())
      throw Decoding_Error("Hello_Request: Must be empty, and is not");
   }

/*
* Create a new Client Hello message
*/
Client_Hello::Client_Hello(RandomNumberGenerator& rng,
                           Record_Writer& writer,
                           const TLS_Policy& policy,
                           HandshakeHash& hash)
   {
   c_random = rng.random_vec(32);

   suites = policy.ciphersuites();
   comp_algos = policy.compression();
   c_version = policy.pref_version();

   send(writer, hash);
   }

/*
* Serialize a Client Hello message
*/
SecureVector<byte> Client_Hello::serialize() const
   {
   SecureVector<byte> buf;

   buf.push_back(static_cast<byte>(c_version >> 8));
   buf.push_back(static_cast<byte>(c_version     ));
   buf += c_random;

   append_tls_length_value(buf, sess_id, 1);
   append_tls_length_value(buf, suites, 2);
   append_tls_length_value(buf, comp_algos, 1);

   return buf;
   }

void Client_Hello::deserialize_sslv2(const MemoryRegion<byte>& buf)
   {
   if(buf.size() < 12 || buf[0] != 1)
      throw Decoding_Error("Client_Hello: SSLv2 hello corrupted");

   const size_t cipher_spec_len = make_u16bit(buf[3], buf[4]);
   const size_t sess_id_len = make_u16bit(buf[5], buf[6]);
   const size_t challenge_len = make_u16bit(buf[7], buf[8]);

   const size_t expected_size =
      (9 + sess_id_len + cipher_spec_len + challenge_len);

   if(buf.size() != expected_size)
      throw Decoding_Error("Client_Hello: SSLv2 hello corrupted");

   if(sess_id_len != 0 || cipher_spec_len % 3 != 0 ||
      (challenge_len < 16 || challenge_len > 32))
      {
      throw Decoding_Error("Client_Hello: SSLv2 hello corrupted");
      }

   for(size_t i = 9; i != 9 + cipher_spec_len; i += 3)
      {
      if(buf[i] != 0) // a SSLv2 cipherspec; ignore it
         continue;

      suites.push_back(make_u16bit(buf[i+1], buf[i+2]));
      }

   c_version = static_cast<Version_Code>(make_u16bit(buf[1], buf[2]));

   c_random.resize(challenge_len);
   copy_mem(&c_random[0], &buf[9+cipher_spec_len+sess_id_len], challenge_len);
   }

/*
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

   if(reader.has_remaining())
      {
      const u16bit all_extn_size = reader.get_u16bit();

      if(reader.remaining_bytes() != all_extn_size)
         throw Decoding_Error("Client_Hello: Bad extension size");

      while(reader.has_remaining())
         {
         const u16bit extension_code = reader.get_u16bit();
         const u16bit extension_size = reader.get_u16bit();

         if(extension_code == TLSEXT_SERVER_NAME_INDICATION)
            {
            u16bit name_bytes = reader.get_u16bit();

            while(name_bytes)
               {
               byte name_type = reader.get_byte();
               name_bytes--;

               if(name_type == 0) // DNS
                  {
                  std::vector<byte> name =
                     reader.get_range_vector<byte>(2, 1, 65535);

                  requested_hostname.assign(
                    reinterpret_cast<const char*>(&name[0]),
                    name.size());

                  name_bytes -= (2 + name.size());
                  }
               else
                  {
                  reader.discard_next(name_bytes);
                  name_bytes = 0;
                  }
               }
            }
         else if(extension_code == TLSEXT_SRP_IDENTIFIER)
            {
            std::vector<byte> name = reader.get_range_vector<byte>(1, 1, 255);

            requested_srp_id.assign(
               reinterpret_cast<char*>(&name[0]),
               name.size());
            }
         else
            {
            reader.discard_next(extension_size);
            }
         }
      }
   }

/*
* Check if we offered this ciphersuite
*/
bool Client_Hello::offered_suite(u16bit ciphersuite) const
   {
   for(size_t i = 0; i != suites.size(); ++i)
      if(suites[i] == ciphersuite)
         return true;
   return false;
   }

/*
* Create a new Server Hello message
*/
Server_Hello::Server_Hello(RandomNumberGenerator& rng,
                           Record_Writer& writer,
                           const TLS_Policy& policy,
                           const std::vector<X509_Certificate>& certs,
                           const Client_Hello& c_hello,
                           Version_Code ver,
                           HandshakeHash& hash)
   {
   bool have_rsa = false, have_dsa = false;

   for(size_t i = 0; i != certs.size(); ++i)
      {
      Public_Key* key = certs[i].subject_public_key();
      if(key->algo_name() == "RSA")
         have_rsa = true;

      if(key->algo_name() == "DSA")
         have_dsa = true;
      }

   suite = policy.choose_suite(c_hello.ciphersuites(), have_rsa, have_dsa);

   if(suite == 0)
      throw TLS_Exception(PROTOCOL_VERSION,
                          "Can't agree on a ciphersuite with client");

   comp_algo = policy.choose_compression(c_hello.compression_algos());

   s_version = ver;
   s_random = rng.random_vec(32);

   send(writer, hash);
   }

/*
* Serialize a Server Hello message
*/
SecureVector<byte> Server_Hello::serialize() const
   {
   SecureVector<byte> buf;

   buf.push_back(static_cast<byte>(s_version >> 8));
   buf.push_back(static_cast<byte>(s_version     ));
   buf += s_random;

   append_tls_length_value(buf, sess_id, 1);

   buf.push_back(get_byte(0, suite));
   buf.push_back(get_byte(1, suite));

   buf.push_back(comp_algo);

   return buf;
   }

/*
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

/*
* Create a new Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(Record_Writer& writer,
                                     HandshakeHash& hash)
   {
   send(writer, hash);
   }

/*
* Serialize a Server Hello Done message
*/
SecureVector<byte> Server_Hello_Done::serialize() const
   {
   return SecureVector<byte>();
   }

/*
* Deserialize a Server Hello Done message
*/
void Server_Hello_Done::deserialize(const MemoryRegion<byte>& buf)
   {
   if(buf.size())
      throw Decoding_Error("Server_Hello_Done: Must be empty, and is not");
   }

}
