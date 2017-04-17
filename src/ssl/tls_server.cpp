/*
* TLS Server
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_server.h>
#include <botan/internal/tls_alerts.h>
#include <botan/internal/tls_state.h>
#include <botan/loadstor.h>
#include <botan/rsa.h>
#include <botan/dh.h>

namespace Botan {

namespace {

/*
* Choose what version to respond with
*/
Version_Code choose_version(Version_Code client, Version_Code minimum)
   {
   if(client < minimum)
      throw TLS_Exception(PROTOCOL_VERSION,
                          "Client version is unacceptable by policy");

   if(client == SSL_V3 || client == TLS_V10 || client == TLS_V11)
      return client;
   return TLS_V11;
   }

// FIXME: checks are wrong for session reuse (add a flag for that)
/*
* Verify the state transition is allowed
*/
void server_check_state(Handshake_Type new_msg, Handshake_State* state)
   {
   class State_Transition_Error : public Unexpected_Message
      {
      public:
         State_Transition_Error(const std::string& err) :
            Unexpected_Message("State transition error from " + err) {}
      };

   if(new_msg == CLIENT_HELLO || new_msg == CLIENT_HELLO_SSLV2)
      {
      if(state->server_hello)
         throw State_Transition_Error("ClientHello");
      }
   else if(new_msg == CERTIFICATE)
      {
      if(!state->do_client_auth || !state->cert_req ||
         !state->server_hello_done || state->client_kex)
         throw State_Transition_Error("ClientCertificate");
      }
   else if(new_msg == CLIENT_KEX)
      {
      if(!state->server_hello_done || state->client_verify ||
         state->got_client_ccs)
         throw State_Transition_Error("ClientKeyExchange");
      }
   else if(new_msg == CERTIFICATE_VERIFY)
      {
      if(!state->cert_req || !state->client_certs || !state->client_kex ||
         state->got_client_ccs)
         throw State_Transition_Error("CertificateVerify");
      }
   else if(new_msg == HANDSHAKE_CCS)
      {
      if(!state->client_kex || state->client_finished)
         throw State_Transition_Error("ClientChangeCipherSpec");
      }
   else if(new_msg == FINISHED)
      {
      if(!state->got_client_ccs)
         throw State_Transition_Error("ClientFinished");
      }
   else
      throw Unexpected_Message("Unexpected message in handshake");
   }

}

/*
* TLS Server Constructor
*/
TLS_Server::TLS_Server(std::tr1::function<size_t (unsigned char[], size_t)> input_fn,
                       std::tr1::function<void (const unsigned char[], size_t)> output_fn,
                       const TLS_Policy& policy,
                       RandomNumberGenerator& rng,
                       const X509_Certificate& cert,
                       const Private_Key& cert_key) :
   input_fn(input_fn),
   policy(policy),
   rng(rng),
   writer(output_fn)
   {
   state = 0;

   cert_chain.push_back(cert);
   private_key = PKCS8::copy_key(cert_key, rng);

   try {
      active = false;
      writer.set_version(TLS_V10);
      do_handshake();
      active = true;
   }
   catch(std::exception& e)
      {
      if(state)
         {
         delete state;
         state = 0;
         }

      writer.alert(FATAL, HANDSHAKE_FAILURE);
      throw Stream_IO_Error(std::string("TLS_Server: Handshake failed: ") +
                            e.what());
      }
   }

/*
* TLS Server Destructor
*/
TLS_Server::~TLS_Server()
   {
   close();
   delete private_key;
   delete state;
   }

/*
* Return the peer's certificate chain
*/
std::vector<X509_Certificate> TLS_Server::peer_cert_chain() const
   {
   return peer_certs;
   }

/*
* Write to a TLS connection
*/
void TLS_Server::write(const byte buf[], size_t length)
   {
   if(!active)
      throw Internal_Error("TLS_Server::write called while closed");

   writer.send(APPLICATION_DATA, buf, length);
   }

/*
* Read from a TLS connection
*/
size_t TLS_Server::read(byte out[], size_t length)
   {
   if(!active)
      throw Internal_Error("TLS_Server::read called while closed");

   writer.flush();

   while(read_buf.size() == 0)
      {
      state_machine();
      if(active == false)
         break;
      }

   size_t got = std::min<size_t>(read_buf.size(), length);
   read_buf.read(out, got);
   return got;
   }

/*
* Check connection status
*/
bool TLS_Server::is_closed() const
   {
   if(!active)
      return true;
   return false;
   }

/*
* Close a TLS connection
*/
void TLS_Server::close()
   {
   close(WARNING, CLOSE_NOTIFY);
   }

/*
* Close a TLS connection
*/
void TLS_Server::close(Alert_Level level, Alert_Type alert_code)
   {
   if(active)
      {
      try {
         active = false;
         writer.alert(level, alert_code);
         writer.flush();
      }
      catch(...) {}
      }
   }

/*
* Iterate the TLS state machine
*/
void TLS_Server::state_machine()
   {
   byte rec_type = CONNECTION_CLOSED;
   SecureVector<byte> record(1024);

   size_t bytes_needed = reader.get_record(rec_type, record);

   while(bytes_needed)
      {
      size_t to_get = std::min<size_t>(record.size(), bytes_needed);
      size_t got = input_fn(&record[0], to_get);

      if(got == 0)
         {
         rec_type = CONNECTION_CLOSED;
         break;
         }

      reader.add_input(&record[0], got);

      bytes_needed = reader.get_record(rec_type, record);
      }

   if(rec_type == CONNECTION_CLOSED)
      {
      active = false;
      reader.reset();
      writer.reset();
      }
   else if(rec_type == APPLICATION_DATA)
      {
      if(active)
         read_buf.write(&record[0], record.size());
      else
         throw Unexpected_Message("Application data before handshake done");
      }
   else if(rec_type == HANDSHAKE || rec_type == CHANGE_CIPHER_SPEC)
      read_handshake(rec_type, record);
   else if(rec_type == ALERT)
      {
      Alert alert(record);

      if(alert.is_fatal() || alert.type() == CLOSE_NOTIFY)
         {
         if(alert.type() == CLOSE_NOTIFY)
            writer.alert(WARNING, CLOSE_NOTIFY);

         reader.reset();
         writer.reset();
         active = false;
         }
      }
   else
      throw Unexpected_Message("Unknown message type received");
   }

/*
* Split up and process handshake messages
*/
void TLS_Server::read_handshake(byte rec_type,
                                const MemoryRegion<byte>& rec_buf)
   {
   if(rec_type == HANDSHAKE)
      {
      if(!state)
         state = new Handshake_State;
      state->queue.write(&rec_buf[0], rec_buf.size());
      }

   while(true)
      {
      Handshake_Type type = HANDSHAKE_NONE;
      SecureVector<byte> contents;

      if(rec_type == HANDSHAKE)
         {
         if(state->queue.size() >= 4)
            {
            byte head[4] = { 0 };
            state->queue.peek(head, 4);

            const size_t length = make_u32bit(0, head[1], head[2], head[3]);

            if(state->queue.size() >= length + 4)
               {
               type = static_cast<Handshake_Type>(head[0]);
               contents.resize(length);
               state->queue.read(head, 4);
               state->queue.read(&contents[0], contents.size());
               }
            }
         }
      else if(rec_type == CHANGE_CIPHER_SPEC)
         {
         if(state->queue.size() == 0 && rec_buf.size() == 1 && rec_buf[0] == 1)
            type = HANDSHAKE_CCS;
         else
            throw Decoding_Error("Malformed ChangeCipherSpec message");
         }
      else
         throw Decoding_Error("Unknown message type in handshake processing");

      if(type == HANDSHAKE_NONE)
         break;

      process_handshake_msg(type, contents);

      if(type == HANDSHAKE_CCS || !state)
         break;
      }
   }

/*
* Process a handshake message
*/
void TLS_Server::process_handshake_msg(Handshake_Type type,
                                       const MemoryRegion<byte>& contents)
   {
   rng.add_entropy(&contents[0], contents.size());

   if(state == 0)
      throw Unexpected_Message("Unexpected handshake message");

   if(active && (type == CLIENT_HELLO || type == CLIENT_HELLO_SSLV2))
      {
      delete state;
      state = 0;
      writer.alert(WARNING, NO_RENEGOTIATION);
      return;
      }

   if(type != HANDSHAKE_CCS && type != FINISHED)
      {
      if(type != CLIENT_HELLO_SSLV2)
         {
         state->hash.update(static_cast<byte>(type));

         const size_t record_length = contents.size();
         for(size_t i = 0; i != 3; i++)
            state->hash.update(get_byte<u32bit>(i+1, record_length));
         }

      state->hash.update(contents);
      }

   if(type == CLIENT_HELLO || type == CLIENT_HELLO_SSLV2)
      {
      server_check_state(type, state);

      state->client_hello = new Client_Hello(contents, type);

      client_requested_hostname = state->client_hello->hostname();

      state->version = choose_version(state->client_hello->version(),
                                      policy.min_version());

      writer.set_version(state->version);
      reader.set_version(state->version);

      state->server_hello = new Server_Hello(rng, writer,
                                             policy, cert_chain,
                                             *(state->client_hello),
                                             state->version, state->hash);

      state->suite = CipherSuite(state->server_hello->ciphersuite());

      if(state->suite.sig_type() != TLS_ALGO_SIGNER_ANON)
         {
         // FIXME: should choose certs based on sig type
         state->server_certs = new Certificate(writer, cert_chain,
                                               state->hash);
         }

      state->kex_priv = PKCS8::copy_key(*private_key, rng);
      if(state->suite.kex_type() != TLS_ALGO_KEYEXCH_NOKEX)
         {
         if(state->suite.kex_type() == TLS_ALGO_KEYEXCH_RSA)
            {
            state->kex_priv = new RSA_PrivateKey(rng,
                                                 policy.rsa_export_keysize());
            }
         else if(state->suite.kex_type() == TLS_ALGO_KEYEXCH_DH)
            {
            state->kex_priv = new DH_PrivateKey(rng, policy.dh_group());
            }
         else
            throw Internal_Error("TLS_Server: Unknown ciphersuite kex type");

         state->server_kex =
            new Server_Key_Exchange(rng, writer,
                                    state->kex_priv, private_key,
                                    state->client_hello->random(),
                                    state->server_hello->random(),
                                    state->hash);
         }

      if(policy.require_client_auth())
         {
         state->do_client_auth = true;
         throw Internal_Error("Client auth not implemented");
         // FIXME: send client auth request here
         }

      state->server_hello_done = new Server_Hello_Done(writer, state->hash);
      }
   else if(type == CERTIFICATE)
      {
      server_check_state(type, state);
      // FIXME: process this
      }
   else if(type == CLIENT_KEX)
      {
      server_check_state(type, state);

      state->client_kex = new Client_Key_Exchange(contents, state->suite,
                                                  state->version);

      SecureVector<byte> pre_master =
         state->client_kex->pre_master_secret(rng, state->kex_priv,
                                              state->server_hello->version());

      state->keys = SessionKeys(state->suite, state->version, pre_master,
                                state->client_hello->random(),
                                state->server_hello->random());
     }
   else if(type == CERTIFICATE_VERIFY)
      {
      server_check_state(type, state);
      // FIXME: process this
      }
   else if(type == HANDSHAKE_CCS)
      {
      server_check_state(type, state);

      reader.set_keys(state->suite, state->keys, SERVER);
      state->got_client_ccs = true;
      }
   else if(type == FINISHED)
      {
      server_check_state(type, state);

      state->client_finished = new Finished(contents);

      if(!state->client_finished->verify(state->keys.master_secret(),
                                         state->version, state->hash, CLIENT))
         throw TLS_Exception(DECRYPT_ERROR,
                             "Finished message didn't verify");

      state->hash.update(static_cast<byte>(type));

      const size_t record_length = contents.size();
      for(size_t i = 0; i != 3; i++)
         state->hash.update(get_byte<u32bit>(i+1, record_length));

      state->hash.update(contents);

      writer.send(CHANGE_CIPHER_SPEC, 1);
      writer.flush();

      writer.set_keys(state->suite, state->keys, SERVER);

      state->server_finished = new Finished(writer, state->version, SERVER,
                                            state->keys.master_secret(),
                                            state->hash);

      delete state;
      state = 0;
      active = true;
      }
   else
      throw Unexpected_Message("Unknown handshake message received");
   }

/*
* Perform a server-side TLS handshake
*/
void TLS_Server::do_handshake()
   {
   while(true)
      {
      if(active && !state)
         break;

      state_machine();

      if(!active && !state)
         throw TLS_Exception(HANDSHAKE_FAILURE, "TLS_Server: Handshake failed");
      }
   }

}
