/*
* TLS Client
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_client.h>
#include <botan/internal/tls_alerts.h>
#include <botan/internal/tls_state.h>
#include <botan/loadstor.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/dh.h>

namespace Botan {

namespace {

/**
* Verify the state transition is allowed
* FIXME: checks are wrong for session reuse (add a flag for that)
*/
void client_check_state(Handshake_Type new_msg, Handshake_State* state)
   {
   class State_Transition_Error : public Unexpected_Message
      {
      public:
         State_Transition_Error(const std::string& err) :
            Unexpected_Message("State transition error from " + err) {}
      };

   if(new_msg == HELLO_REQUEST)
      {
      if(state->client_hello)
         throw State_Transition_Error("HelloRequest");
      }
   else if(new_msg == SERVER_HELLO)
      {
      if(!state->client_hello || state->server_hello)
         throw State_Transition_Error("ServerHello");
      }
   else if(new_msg == CERTIFICATE)
      {
      if(!state->server_hello || state->server_kex ||
         state->cert_req || state->server_hello_done)
         throw State_Transition_Error("ServerCertificate");
      }
   else if(new_msg == SERVER_KEX)
      {
      if(!state->server_hello || state->server_kex ||
         state->cert_req || state->server_hello_done)
         throw State_Transition_Error("ServerKeyExchange");
      }
   else if(new_msg == CERTIFICATE_REQUEST)
      {
      if(!state->server_certs || state->cert_req || state->server_hello_done)
         throw State_Transition_Error("CertificateRequest");
      }
   else if(new_msg == SERVER_HELLO_DONE)
      {
      if(!state->server_hello || state->server_hello_done)
         throw State_Transition_Error("ServerHelloDone");
      }
   else if(new_msg == HANDSHAKE_CCS)
      {
      if(!state->client_finished || state->server_finished)
         throw State_Transition_Error("ServerChangeCipherSpec");
      }
   else if(new_msg == FINISHED)
      {
      if(!state->got_server_ccs)
         throw State_Transition_Error("ServerFinished");
      }
   else
      throw Unexpected_Message("Unexpected message in handshake");
   }

}

/**
* TLS Client Constructor
*/
TLS_Client::TLS_Client(std::tr1::function<size_t (unsigned char[], size_t)> input_fn,
                       std::tr1::function<void (const unsigned char[], size_t)> output_fn,
                       const TLS_Policy& policy,
                       RandomNumberGenerator& rng) :
   input_fn(input_fn),
   policy(policy),
   rng(rng),
   writer(output_fn)
   {
   initialize();
   }

void TLS_Client::add_client_cert(const X509_Certificate& cert,
                                 Private_Key* cert_key)
   {
   certs.push_back(std::make_pair(cert, cert_key));
   }

/**
* TLS Client Destructor
*/
TLS_Client::~TLS_Client()
   {
   close();
   for(size_t i = 0; i != certs.size(); i++)
      delete certs[i].second;
   delete state;
   }

/**
* Initialize a TLS client connection
*/
void TLS_Client::initialize()
   {
   std::string error_str;
   Alert_Type error_type = NO_ALERT_TYPE;

   try {
      state = 0;
      active = false;
      writer.set_version(policy.pref_version());
      do_handshake();
   }
   catch(TLS_Exception& e)
      {
      error_str = e.what();
      error_type = e.type();
      }
   catch(std::exception& e)
      {
      error_str = e.what();
      error_type = HANDSHAKE_FAILURE;
      }

   if(error_type != NO_ALERT_TYPE)
      {
      if(active)
         {
         active = false;
         reader.reset();

         writer.alert(FATAL, error_type);
         writer.reset();
         }

      if(state)
         {
         delete state;
         state = 0;
         }

      throw Stream_IO_Error("TLS_Client: Handshake failed: " + error_str);
      }
   }

/**
* Return the peer's certificate chain
*/
std::vector<X509_Certificate> TLS_Client::peer_cert_chain() const
   {
   return peer_certs;
   }

/**
* Write to a TLS connection
*/
void TLS_Client::write(const byte buf[], size_t length)
   {
   if(!active)
      throw TLS_Exception(INTERNAL_ERROR,
                          "TLS_Client::write called while closed");

   writer.send(APPLICATION_DATA, buf, length);
   }

/**
* Read from a TLS connection
*/
size_t TLS_Client::read(byte out[], size_t length)
   {
   if(!active)
      return 0;

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

/**
* Close a TLS connection
*/
void TLS_Client::close()
   {
   close(WARNING, CLOSE_NOTIFY);
   }

/**
* Check connection status
*/
bool TLS_Client::is_closed() const
   {
   if(!active)
      return true;
   return false;
   }

/**
* Close a TLS connection
*/
void TLS_Client::close(Alert_Level level, Alert_Type alert_code)
   {
   if(active)
      {
      try {
         writer.alert(level, alert_code);
         writer.flush();
      }
      catch(...) {}

      active = false;
      }
   }

/**
* Iterate the TLS state machine
*/
void TLS_Client::state_machine()
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
         if(state)
            {
            delete state;
            state = 0;
            }
         }
      }
   else
      throw Unexpected_Message("Unknown message type received");
   }

/**
* Split up and process handshake messages
*/
void TLS_Client::read_handshake(byte rec_type,
                                const MemoryRegion<byte>& rec_buf)
   {
   if(rec_type == HANDSHAKE)
      {
      if(!state)
         return;

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

/**
* Process a handshake message
*/
void TLS_Client::process_handshake_msg(Handshake_Type type,
                                       const MemoryRegion<byte>& contents)
   {
   if(type == HELLO_REQUEST)
      return;

   if(state == 0)
      throw Unexpected_Message("Unexpected handshake message");

   if(type != HANDSHAKE_CCS && type != HELLO_REQUEST && type != FINISHED)
      {
      state->hash.update(static_cast<byte>(type));
      const size_t record_length = contents.size();
      for(size_t i = 0; i != 3; i++)
         state->hash.update(get_byte<u32bit>(i+1, record_length));
      state->hash.update(contents);
      }

   if(type == SERVER_HELLO)
      {
      client_check_state(type, state);

      state->server_hello = new Server_Hello(contents);

      if(!state->client_hello->offered_suite(
            state->server_hello->ciphersuite()
            )
         )
         throw TLS_Exception(HANDSHAKE_FAILURE,
                             "TLS_Client: Server replied with bad ciphersuite");

      state->version = state->server_hello->version();

      if(state->version > state->client_hello->version())
         throw TLS_Exception(HANDSHAKE_FAILURE,
                             "TLS_Client: Server replied with bad version");

      if(state->version < policy.min_version())
         throw TLS_Exception(PROTOCOL_VERSION,
                             "TLS_Client: Server is too old for specified policy");

      writer.set_version(state->version);
      reader.set_version(state->version);

      state->suite = CipherSuite(state->server_hello->ciphersuite());
      }
   else if(type == CERTIFICATE)
      {
      client_check_state(type, state);

      if(state->suite.sig_type() == TLS_ALGO_SIGNER_ANON)
         throw Unexpected_Message("Recived certificate from anonymous server");

      state->server_certs = new Certificate(contents);

      peer_certs = state->server_certs->cert_chain();
      if(peer_certs.size() == 0)
         throw TLS_Exception(HANDSHAKE_FAILURE,
                             "TLS_Client: No certificates sent by server");

      if(!policy.check_cert(peer_certs))
         throw TLS_Exception(BAD_CERTIFICATE,
                             "TLS_Client: Server certificate is not valid");

      state->kex_pub = peer_certs[0].subject_public_key();

      bool is_dsa = false, is_rsa = false;

      if(dynamic_cast<DSA_PublicKey*>(state->kex_pub))
         is_dsa = true;
      else if(dynamic_cast<RSA_PublicKey*>(state->kex_pub))
         is_rsa = true;
      else
         throw TLS_Exception(UNSUPPORTED_CERTIFICATE,
                             "Unknown key type received in server kex");

      if((is_dsa && state->suite.sig_type() != TLS_ALGO_SIGNER_DSA) ||
         (is_rsa && state->suite.sig_type() != TLS_ALGO_SIGNER_RSA))
         throw TLS_Exception(ILLEGAL_PARAMETER,
                             "Certificate key type did not match ciphersuite");
      }
   else if(type == SERVER_KEX)
      {
      client_check_state(type, state);

      if(state->suite.kex_type() == TLS_ALGO_KEYEXCH_NOKEX)
         throw Unexpected_Message("Unexpected key exchange from server");

      state->server_kex = new Server_Key_Exchange(contents);

      if(state->kex_pub)
         delete state->kex_pub;

      state->kex_pub = state->server_kex->key();

      bool is_dh = false, is_rsa = false;

      if(dynamic_cast<DH_PublicKey*>(state->kex_pub))
         is_dh = true;
      else if(dynamic_cast<RSA_PublicKey*>(state->kex_pub))
         is_rsa = true;
      else
         throw TLS_Exception(HANDSHAKE_FAILURE,
                             "Unknown key type received in server kex");

      if((is_dh && state->suite.kex_type() != TLS_ALGO_KEYEXCH_DH) ||
         (is_rsa && state->suite.kex_type() != TLS_ALGO_KEYEXCH_RSA))
         throw TLS_Exception(ILLEGAL_PARAMETER,
                             "Certificate key type did not match ciphersuite");

      if(state->suite.sig_type() != TLS_ALGO_SIGNER_ANON)
         {
         if(!state->server_kex->verify(peer_certs[0],
                                       state->client_hello->random(),
                                       state->server_hello->random()))
            throw TLS_Exception(DECRYPT_ERROR,
                            "Bad signature on server key exchange");
         }
      }
   else if(type == CERTIFICATE_REQUEST)
      {
      client_check_state(type, state);

      state->cert_req = new Certificate_Req(contents);
      state->do_client_auth = true;
      }
   else if(type == SERVER_HELLO_DONE)
      {
      client_check_state(type, state);

      state->server_hello_done = new Server_Hello_Done(contents);

      if(state->do_client_auth)
         {
         std::vector<X509_Certificate> send_certs;

         std::vector<Certificate_Type> types =
            state->cert_req->acceptable_types();

         // FIXME: Fill in useful certs here, if any
         state->client_certs = new Certificate(writer, send_certs,
                                               state->hash);
         }

      state->client_kex =
         new Client_Key_Exchange(rng, writer, state->hash,
                                 state->kex_pub, state->version,
                                 state->client_hello->version());

      if(state->do_client_auth)
         {
         Private_Key* key_matching_cert = 0; // FIXME
         state->client_verify = new Certificate_Verify(rng,
                                                       writer, state->hash,
                                                       key_matching_cert);
         }

      state->keys = SessionKeys(state->suite, state->version,
                                state->client_kex->pre_master_secret(),
                                state->client_hello->random(),
                                state->server_hello->random());

      writer.send(CHANGE_CIPHER_SPEC, 1);
      writer.flush();

      writer.set_keys(state->suite, state->keys, CLIENT);

      state->client_finished = new Finished(writer, state->version, CLIENT,
                                            state->keys.master_secret(),
                                            state->hash);
      }
   else if(type == HANDSHAKE_CCS)
      {
      client_check_state(type, state);

      reader.set_keys(state->suite, state->keys, CLIENT);
      state->got_server_ccs = true;
      }
   else if(type == FINISHED)
      {
      client_check_state(type, state);

      state->server_finished = new Finished(contents);

      if(!state->server_finished->verify(state->keys.master_secret(),
                                         state->version, state->hash, SERVER))
         throw TLS_Exception(DECRYPT_ERROR,
                                 "Finished message didn't verify");

      delete state;
      state = 0;
      active = true;
      }
   else
      throw Unexpected_Message("Unknown handshake message received");
   }

/**
* Perform a client-side TLS handshake
*/
void TLS_Client::do_handshake()
   {
   state = new Handshake_State;

   state->client_hello = new Client_Hello(rng, writer, policy, state->hash);

   while(true)
      {
      if(active && !state)
         break;
      if(!active && !state)
         throw TLS_Exception(HANDSHAKE_FAILURE, "TLS_Client: Handshake failed (do_handshake)");

      state_machine();
      }
   }

}
