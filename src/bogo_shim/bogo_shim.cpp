/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

/*
* This is a shim for testing Botan against BoringSSL's test TLS stack (BoGo).
*
* Instructions on use should go here.
*/

#include <botan/tls_client.h>
#include <botan/tls_server.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_algos.h>
#include <botan/data_src.h>
#include <botan/pkcs8.h>
#include <botan/internal/loadstor.h>
#include <botan/oids.h>
#include <botan/chacha_rng.h>
#include <botan/base64.h>
#include <botan/hex.h>
#include <botan/internal/parsing.h>
#include <botan/mem_ops.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <ctime>
#include <unordered_map>

#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)
  #include <sys/socket.h>
  #include <sys/time.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <string.h>
  #include <unistd.h>
  #include <errno.h>
  #include <fcntl.h>
#endif

namespace {

int shim_output(const std::string& s, int rc = 0)
   {
   std::cout << s << "\n";
   return rc;
   }

void shim_log(const std::string& s)
   {
   if(::getenv("BOTAN_BOGO_SHIM_LOG"))
      {
      static FILE* log = std::fopen("/tmp/bogo_shim.log", "w");
      struct timeval tv;
      ::gettimeofday(&tv, nullptr);
      std::fprintf(log, "%lld.%lu: %s\n", static_cast<unsigned long long>(tv.tv_sec), tv.tv_usec, s.c_str());
      std::fflush(log);
      }
   }

[[noreturn]] void shim_exit_with_error(const std::string& s, int rc = 1)
   {
   shim_log("Exiting with " + s);
   std::cerr << s << "\n";
   std::exit(rc);
   }

std::string map_to_bogo_error(const std::string& e)
   {
   shim_log("Original error " + e);

   static const std::unordered_map<std::string, std::string> err_map
      {
         { "Application data before handshake done", ":APPLICATION_DATA_INSTEAD_OF_HANDSHAKE:" },
         { "Bad Hello_Request, has non-zero size", ":BAD_HELLO_REQUEST:" },
         { "Bad code for TLS alert level", ":UNKNOWN_ALERT_TYPE:" },
         { "Bad extension size", ":DECODE_ERROR:" },
         { "Bad length in hello verify request", ":DECODE_ERROR:" },
         { "Bad lengths in DTLS header", ":BAD_HANDSHAKE_RECORD:" },
         { "Bad signature on server key exchange", ":BAD_SIGNATURE:" },
         { "Bad size (1) for TLS alert message", ":BAD_ALERT:" },
         { "Bad size (4) for TLS alert message", ":BAD_ALERT:" },
         { "CERTIFICATE decoding failed with PEM: No PEM header found", ":CANNOT_PARSE_LEAF_CERT:" },
         { "Can't agree on a ciphersuite with client", ":NO_SHARED_CIPHER:" },
         { "Can't interleave application and handshake data", ":UNEXPECTED_RECORD:" },
         { "Certificate chain exceeds policy specified maximum size", ":EXCESSIVE_MESSAGE_SIZE:" },
         { "Certificate key type did not match ciphersuite", ":WRONG_CERTIFICATE_TYPE:" },
         { "Certificate usage constraints do not allow this ciphersuite", ":KEY_USAGE_BIT_INCORRECT:" },
         { "Certificate: Message malformed", ":DECODE_ERROR:" },
         { "Channel_Impl_12::key_material_export cannot export during renegotiation", "failed to export keying material" },
         { "Client cert verify failed", ":BAD_SIGNATURE:" },
         { "Client certificate does not support signing", ":KEY_USAGE_BIT_INCORRECT:" },
         { "Client did not offer NULL compression", ":INVALID_COMPRESSION_LIST:" },
         { "Client offered DTLS version with major version 0xFF",  ":UNSUPPORTED_PROTOCOL:" },
         { "Client offered SSLv3 which is not supported", ":UNSUPPORTED_PROTOCOL:" },
         { "Client offered TLS version with major version under 3", ":UNSUPPORTED_PROTOCOL:" },
         { "Client policy prohibits insecure renegotiation", ":RENEGOTIATION_MISMATCH:" },
         { "Client policy prohibits renegotiation", ":NO_RENEGOTIATION:" },
         { "Client resumed extended ms session without sending extension", ":RESUMED_EMS_SESSION_WITHOUT_EMS_EXTENSION:" },
         { "Client sent HTTP proxy CONNECT request instead of TLS handshake", ":HTTPS_PROXY_REQUEST:" },
         { "Client sent plaintext HTTP request instead of TLS handshake", ":HTTP_REQUEST:" },
         { "Client signalled fallback SCSV, possible attack", ":INAPPROPRIATE_FALLBACK:" },
         { "Client version DTLS v1.0 is unacceptable by policy", ":UNSUPPORTED_PROTOCOL:" },
         { "Client version TLS v1.0 is unacceptable by policy", ":UNSUPPORTED_PROTOCOL:" },
         { "Client version TLS v1.1 is unacceptable by policy", ":UNSUPPORTED_PROTOCOL:" },
         { "Client: No certificates sent by server", ":DECODE_ERROR:" },
         { "Counterparty sent inconsistent key and sig types", ":WRONG_SIGNATURE_TYPE:" },
         { "Downgrade attack detected", ":TLS13_DOWNGRADE:" },
         { "Empty ALPN protocol not allowed", ":PARSE_TLSEXT:" },
         { "Encoding error: Cannot encode PSS string, output length too small", ":NO_COMMON_SIGNATURE_ALGORITHMS:" },
         { "Expected TLS but got a record with DTLS version", ":WRONG_VERSION_NUMBER:" },
         { "Finished message didn't verify", ":DIGEST_CHECK_FAILED:" },
         { "Have data remaining in buffer after ClientHello", ":EXCESS_HANDSHAKE_DATA:" },
         { "Have data remaining in buffer after Finished", ":EXCESS_HANDSHAKE_DATA:" },
         { "Have data remaining in buffer after ServerHelloDone", ":EXCESS_HANDSHAKE_DATA:" },
         { "Inconsistent length in certificate request", ":DECODE_ERROR:" },
         { "Inconsistent values in fragmented DTLS handshake header", ":FRAGMENT_MISMATCH:" },
         { "Invalid CertificateRequest: Length field outside parameters", ":DECODE_ERROR:" },
         { "Invalid CertificateVerify: Extra bytes at end of message", ":DECODE_ERROR:" },
         { "Invalid Certificate_Status: invalid length field", ":DECODE_ERROR:" },
         { "Invalid ChangeCipherSpec", ":BAD_CHANGE_CIPHER_SPEC:" },
         { "Invalid ClientHello: Length field outside parameters", ":DECODE_ERROR:" },
         { "Invalid ClientKeyExchange: Extra bytes at end of message", ":DECODE_ERROR:" },
         { "Invalid ServerKeyExchange: Extra bytes at end of message", ":DECODE_ERROR:" },
         { "Invalid SessionTicket: Extra bytes at end of message", ":DECODE_ERROR:" },
         { "Invalid authentication tag: ChaCha20Poly1305 tag check failed", ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:" },
         { "Invalid authentication tag: GCM tag check failed", ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:" },
         { "Message authentication failure", ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:" },
         { "No shared DTLS version", ":UNSUPPORTED_PROTOCOL:" },
         { "No shared TLS version", ":UNSUPPORTED_PROTOCOL:" },
         { "OS2ECP: Unknown format type 251", ":BAD_ECPOINT:" },
         { "Policy forbids all available DTLS version", ":NO_SUPPORTED_VERSIONS_ENABLED:" },
         { "Policy forbids all available TLS version", ":NO_SUPPORTED_VERSIONS_ENABLED:" },
         { "Policy refuses to accept signing with any hash supported by peer", ":NO_COMMON_SIGNATURE_ALGORITHMS:" },
         { "Policy requires client send a certificate, but it did not", ":PEER_DID_NOT_RETURN_A_CERTIFICATE:" },
         { "Received a record that exceeds maximum size", ":ENCRYPTED_LENGTH_TOO_LONG:" },
         { "Received application data after connection closure", ":APPLICATION_DATA_ON_SHUTDOWN:" },
         { "Received handshake data after connection closure", ":NO_RENEGOTIATION:" },
         { "Received unexpected record version in initial record", ":WRONG_VERSION_NUMBER:" },
         { "Received unexpected record version", ":WRONG_VERSION_NUMBER:" },
         { "Rejecting ALPN request with alert", ":NO_APPLICATION_PROTOCOL:" },
         { "Server attempting to negotiate SSLv3 which is not supported", ":UNSUPPORTED_PROTOCOL:" },
         { "Server certificate changed during renegotiation", ":SERVER_CERT_CHANGED:" },
         { "Server changed its mind about extended master secret", ":RENEGOTIATION_EMS_MISMATCH:" },
         { "Server changed its mind about secure renegotiation", ":RENEGOTIATION_MISMATCH:" },
         { "Server changed version after renegotiation", ":WRONG_SSL_VERSION:" },
         { "Server downgraded version after renegotiation", ":WRONG_SSL_VERSION:" },
         { "Server policy prohibits renegotiation", ":NO_RENEGOTIATION:" },
         { "Server replied using a ciphersuite not allowed in version it offered", ":WRONG_CIPHER_RETURNED:" },
         { "Server replied with DTLS-SRTP alg we did not send", ":BAD_SRTP_PROTECTION_PROFILE_LIST:" },
         { "Server replied with ciphersuite we didn't send", ":WRONG_CIPHER_RETURNED:" },
         { "Server replied with later version than client offered", ":UNSUPPORTED_PROTOCOL:" },
         { "Server replied with non-null compression method", ":UNSUPPORTED_COMPRESSION_ALGORITHM:" },
         { "Server replied with some unknown ciphersuite", ":UNKNOWN_CIPHER_RETURNED:" },
         { "Server replied with unsupported extensions: 0", ":UNEXPECTED_EXTENSION:" },
         { "Server replied with unsupported extensions: 1234", ":UNEXPECTED_EXTENSION:" },
         { "Server replied with unsupported extensions: 16", ":UNEXPECTED_EXTENSION:" },
         { "Server replied with unsupported extensions: 43", ":UNEXPECTED_EXTENSION:" },
         { "Server replied with unsupported extensions: 5", ":UNEXPECTED_EXTENSION:" },
         { "Server resumed session and removed extended master secret", ":RESUMED_EMS_SESSION_WITHOUT_EMS_EXTENSION:" },
         { "Server resumed session but added extended master secret", ":RESUMED_NON_EMS_SESSION_WITH_EMS_EXTENSION:" },
         { "Server resumed session but with wrong version", ":OLD_SESSION_VERSION_NOT_RETURNED:" },
         { "Server sent ECC curve prohibited by policy", ":WRONG_CURVE:" },
         { "Server sent an unsupported extension", ":UNEXPECTED_EXTENSION:" },
         { "Server sent bad values for secure renegotiation", ":RENEGOTIATION_MISMATCH:" },
         { "Server version DTLS v1.0 is unacceptable by policy", ":UNSUPPORTED_PROTOCOL:" },
         { "Server version TLS v1.0 is unacceptable by policy", ":UNSUPPORTED_PROTOCOL:" },
         { "Server version TLS v1.1 is unacceptable by policy", ":UNSUPPORTED_PROTOCOL:" },
         { "Server_Hello_Done: Must be empty, and is not", ":DECODE_ERROR:" },
         { "Simulated OCSP callback failure", ":OCSP_CB_ERROR:" },
         { "Simulating cert verify callback failure", ":CERT_CB_ERROR:" },
         { "Simulating failure from OCSP response callback", ":OCSP_CB_ERROR:" },
         { "TLS plaintext record is larger than allowed maximum", ":DATA_LENGTH_TOO_LONG:" },
         { "TLS record version has unexpected value", ":WRONG_VERSION_NUMBER:" },
         { "TLS signature extension did not allow for RSA/SHA-256 signature", ":WRONG_SIGNATURE_TYPE:", },
         { "Test requires rejecting cert", ":CERTIFICATE_VERIFY_FAILED:" },
         { "Unexpected ALPN protocol", ":INVALID_ALPN_PROTOCOL:" },
         { "Unexpected record type 42 from counterparty", ":UNEXPECTED_RECORD:" },
         { "Unexpected state transition in handshake got a certificate_request expected server_hello_done seen server_hello+server_key_exchange", ":UNEXPECTED_MESSAGE:" },
         { "Unexpected state transition in handshake got a certificate_request expected server_key_exchange|server_hello_done seen server_hello", ":UNEXPECTED_MESSAGE:" },
         { "Unexpected state transition in handshake got a certificate_status expected certificate seen server_hello", ":UNEXPECTED_MESSAGE:" },
         { "Unexpected state transition in handshake got a change_cipher_spec expected certificate_verify seen client_hello+certificate+client_key_exchange", ":UNEXPECTED_RECORD:" },
         { "Unexpected state transition in handshake got a change_cipher_spec expected client_key_exchange seen client_hello", ":UNEXPECTED_RECORD:" },
         { "Unexpected state transition in handshake got a change_cipher_spec expected new_session_ticket seen server_hello+certificate+certificate_status+server_key_exchange+server_hello_done", ":UNEXPECTED_RECORD:" },
         { "Unexpected state transition in handshake got a client_key_exchange expected certificate seen client_hello", ":UNEXPECTED_MESSAGE:" },
         { "Unexpected state transition in handshake got a finished expected change_cipher_spec seen client_hello", ":UNEXPECTED_RECORD:" },
         { "Unexpected state transition in handshake got a finished expected change_cipher_spec seen client_hello+client_key_exchange", ":UNEXPECTED_RECORD:" },
         { "Unexpected state transition in handshake got a finished expected change_cipher_spec seen server_hello", ":UNEXPECTED_RECORD:" },
         { "Unexpected state transition in handshake got a finished expected change_cipher_spec seen server_hello+certificate+certificate_status+server_key_exchange+server_hello_done+new_session_ticket", ":UNEXPECTED_RECORD:" },
         { "Unexpected state transition in handshake got a hello_request expected server_hello", ":UNEXPECTED_MESSAGE:" },
         { "Unexpected state transition in handshake got a server_hello_done expected server_key_exchange seen server_hello+certificate+certificate_status", ":UNEXPECTED_MESSAGE:" },
         { "Unexpected state transition in handshake got a server_key_exchange expected certificate_request|server_hello_done seen server_hello+certificate+certificate_status", ":UNEXPECTED_MESSAGE:" },
         { "Unexpected state transition in handshake got a server_key_exchange not expecting messages", ":BAD_HELLO_REQUEST:" },
         { "Unknown TLS handshake message type 43", ":UNEXPECTED_MESSAGE:" },
         { "Unknown TLS handshake message type 44", ":UNEXPECTED_MESSAGE:" },
         { "Unknown TLS handshake message type 45", ":UNEXPECTED_MESSAGE:" },
         { "Unknown TLS handshake message type 46", ":UNEXPECTED_MESSAGE:" },
         { "Unknown TLS handshake message type 53", ":UNEXPECTED_MESSAGE:" },
         { "Unknown TLS handshake message type 54", ":UNEXPECTED_MESSAGE:" },
         { "Unknown TLS handshake message type 55", ":UNEXPECTED_MESSAGE:" },
         { "Unknown TLS handshake message type 56", ":UNEXPECTED_MESSAGE:" },
         { "Unknown TLS handshake message type 57", ":UNEXPECTED_MESSAGE:" },
         { "Unknown TLS handshake message type 58", ":UNEXPECTED_MESSAGE:" },
         { "Unknown TLS handshake message type 6", ":UNEXPECTED_MESSAGE:" },
         { "Unknown TLS handshake message type 62", ":UNEXPECTED_MESSAGE:" },
         { "Unknown TLS handshake message type 64", ":UNEXPECTED_MESSAGE:" },
         { "signature_algorithm_of_scheme: Unknown signature algorithm enum", ":WRONG_SIGNATURE_TYPE:" },
      };

   auto err_map_i = err_map.find(e);
   if(err_map_i != err_map.end())
      return err_map_i->second;

   return "Unmapped error: '" + e + "'";
   }

class Shim_Exception final : public std::exception
   {
   public:
      Shim_Exception(const std::string& msg, int rc = 1) :
         m_msg(msg), m_rc(rc) {}

      const char* what() const noexcept override { return m_msg.c_str(); }

      int rc() const { return m_rc; }
   private:
      const std::string m_msg;
      int m_rc;
   };

#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)

class Shim_Socket final
   {
   private:
      typedef int socket_type;
      typedef ssize_t socket_op_ret_type;
      static void close_socket(socket_type s) { ::close(s); }
      static std::string get_last_socket_error() { return ::strerror(errno); }

   public:
      Shim_Socket(const std::string& hostname, int port) : m_socket(-1)
         {
         addrinfo hints;
         std::memset(&hints, 0, sizeof(hints));
         hints.ai_family = AF_UNSPEC;
         hints.ai_socktype = SOCK_STREAM;
         hints.ai_flags = AI_NUMERICSERV;
         addrinfo* res;

         const std::string service = std::to_string(port);
         int rc = ::getaddrinfo(hostname.c_str(), service.c_str(), &hints, &res);
         shim_log("Connecting " + hostname + ":" + service);

         if(rc != 0)
            {
            throw Shim_Exception("Name resolution failed for " + hostname);
            }

         for(addrinfo* rp = res; (m_socket == -1) && (rp != nullptr); rp = rp->ai_next)
            {
            if(rp->ai_family != AF_INET && rp->ai_family != AF_INET6)
               continue;

            m_socket = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

            if(m_socket == -1)
               {
               // unsupported socket type?
               continue;
               }

            int err = ::connect(m_socket, rp->ai_addr, rp->ai_addrlen);

            if(err != 0)
               {
               ::close(m_socket);
               m_socket = -1;
               }
            }

         if(m_socket < 0)
            throw Shim_Exception("Failed to connect to host");
         }

      ~Shim_Socket()
         {
         ::close(m_socket);
         m_socket = -1;
         }

      void write(const uint8_t buf[], size_t len)
         {
         if(m_socket < 0)
            throw Shim_Exception("Socket was bad on write");
         size_t sent_so_far = 0;
         while(sent_so_far != len)
            {
            const size_t left = len - sent_so_far;
            socket_op_ret_type sent = ::send(m_socket, Botan::cast_uint8_ptr_to_char(&buf[sent_so_far]), left, MSG_NOSIGNAL);
            if(sent < 0)
               {
               if(errno == EPIPE)
                  return;
               else
                  throw Shim_Exception("Socket write failed", errno);
               }
            else
               sent_so_far += static_cast<size_t>(sent);
            }
         }

      size_t read(uint8_t buf[], size_t len)
         {
         if(m_socket < 0)
            throw Shim_Exception("Socket was bad on read");
         socket_op_ret_type got = ::read(m_socket, Botan::cast_uint8_ptr_to_char(buf), len);

         if(got < 0)
            {
            if(errno == ECONNRESET)
               return 0;
            throw Shim_Exception("Socket read failed: " + std::string(strerror(errno)));
            }

         return static_cast<size_t>(got);
         }

      void read_exactly(uint8_t buf[], size_t len)
         {
         if(m_socket < 0)
            throw Shim_Exception("Socket was bad on read");

         while(len > 0)
            {
            socket_op_ret_type got = ::read(m_socket, Botan::cast_uint8_ptr_to_char(buf), len);

            if(got == 0)
               throw Shim_Exception("Socket read EOF");
            else if(got < 0)
               throw Shim_Exception("Socket read failed: " + std::string(strerror(errno)));

            buf += static_cast<size_t>(got);
            len -= static_cast<size_t>(got);
            }
         }

   private:
      socket_type m_socket;
   };

#endif

std::set<std::string> combine_options(
   const std::set<std::string>& a,
   const std::set<std::string>& b,
   const std::set<std::string>& c,
   const std::set<std::string>& d)
   {
   std::set<std::string> combined;

   for(auto i : a)
      combined.insert(i);
   for(auto i : b)
      combined.insert(i);
   for(auto i : c)
      combined.insert(i);
   for(auto i : d)
      combined.insert(i);

   return combined;
   }

class Shim_Arguments final
   {
   public:
      Shim_Arguments(const std::set<std::string>& flags,
                     const std::set<std::string>& string_opts,
                     const std::set<std::string>& base64_opts,
                     const std::set<std::string>& int_opts,
                     const std::set<std::string>& int_vec_opts) :
         m_flags(flags),
         m_string_opts(string_opts),
         m_base64_opts(base64_opts),
         m_int_opts(int_opts),
         m_int_vec_opts(int_vec_opts),
         m_all_options(combine_options(string_opts, base64_opts, int_opts, int_vec_opts))
         {}

      void parse_args(char* argv[]);

      bool flag_set(const std::string& flag) const
         {
         if(m_flags.count(flag) == 0)
            throw Shim_Exception("Unknown bool flag " + flag);

         return m_parsed_flags.count(flag);
         }

      std::string test_name() const
         {
         return get_string_opt("test-name");
         }

      std::string get_string_opt(const std::string& key) const
         {
         if(m_string_opts.count(key) == 0)
            throw Shim_Exception("Unknown string key " + key);
         return get_opt(key);
         }

      std::string get_string_opt_or_else(const std::string& key, const std::string& def) const
         {
         if(m_string_opts.count(key) == 0)
            throw Shim_Exception("Unknown string key " + key);
         if(!option_used(key))
            return def;
         return get_opt(key);
         }

      std::vector<uint8_t> get_b64_opt(const std::string& key) const
         {
         if(m_base64_opts.count(key) == 0)
            throw Shim_Exception("Unknown base64 key " + key);
         return Botan::unlock(Botan::base64_decode(get_opt(key)));
         }

      size_t get_int_opt(const std::string& key) const
         {
         if(m_int_opts.count(key) == 0)
            throw Shim_Exception("Unknown int key " + key);
         return Botan::to_u32bit(get_opt(key));
         }

      size_t get_int_opt_or_else(const std::string& key, size_t def) const
         {
         if(m_int_opts.count(key) == 0)
            throw Shim_Exception("Unknown int key " + key);
         if(!option_used(key))
            return def;

         return Botan::to_u32bit(get_opt(key));
         }

      std::vector<size_t> get_int_vec_opt(const std::string& key) const
         {
         if(m_int_vec_opts.count(key) == 0)
            throw Shim_Exception("Unknown int vec key " + key);

         auto i = m_parsed_int_vec_opts.find(key);
         if(i == m_parsed_int_vec_opts.end())
            return std::vector<size_t>();
         else
            return i->second;
         }

      std::vector<std::string> get_alpn_string_vec_opt(const std::string& option) const
         {
         // hack used for alpn list (relies on all ALPNs being 3 chars long...)
         char delim = 0x03;

         if(option_used(option))
            return Botan::split_on(get_string_opt(option), delim);
         else
            return std::vector<std::string>();
         }

      bool option_used(const std::string& key) const
         {
         if(m_all_options.count(key) == 0)
            throw Shim_Exception("Invalid option " + key);
         if(m_parsed_opts.find(key) != m_parsed_opts.end())
            return true;
         if(m_parsed_int_vec_opts.find(key) != m_parsed_int_vec_opts.end())
            return true;
         return false;
         }

   private:
      std::string get_opt(const std::string& key) const
         {
         auto i = m_parsed_opts.find(key);
         if(i == m_parsed_opts.end())
            throw Shim_Exception("Option " + key + " was not provided");
         return i->second;
         }

      const std::set<std::string> m_flags;
      const std::set<std::string> m_string_opts;
      const std::set<std::string> m_base64_opts;
      const std::set<std::string> m_int_opts;
      const std::set<std::string> m_int_vec_opts;
      const std::set<std::string> m_all_options;

      std::set<std::string> m_parsed_flags;
      std::map<std::string, std::string> m_parsed_opts;
      std::map<std::string, std::vector<size_t>> m_parsed_int_vec_opts;
   };

void Shim_Arguments::parse_args(char* argv[])
   {
   int i = 1; // skip argv[0]

   while(argv[i] != nullptr)
      {
      const std::string param(argv[i]);

      if(param.find("-") == 0)
         {
         const std::string flag_name = param.substr(1, std::string::npos);

         if(m_flags.count(flag_name))
            {
            shim_log("flag " + flag_name);
            m_parsed_flags.insert(flag_name);
            i += 1;
            }
         else if(m_all_options.count(flag_name))
            {
            if(argv[i+1] == nullptr)
               throw Shim_Exception("Expected argument following " + param);
            std::string val(argv[i+1]);
            shim_log("param " + flag_name + "=" + val);

            if(m_int_vec_opts.count(flag_name))
               {
               const size_t v = Botan::to_u32bit(val);
               m_parsed_int_vec_opts[flag_name].push_back(v);
               }
            else
               {
               m_parsed_opts[flag_name] = val;
               }
            i += 2;
            }
         else
            {
            shim_log("Unknown option " + param);
            throw Shim_Exception("Unknown option " + param, 89);
            }
         }
      else
         {
         shim_log("Unknown option " + param);
         throw Shim_Exception("Unknown option " + param, 89);
         }
      }
   }

std::unique_ptr<Shim_Arguments> parse_options(char* argv[])
   {
   const std::set<std::string> bogo_shim_flags = {
      "allow-false-start-without-alpn",
      "allow-unknown-alpn-protos",
      "async",
      "cbc-record-splitting",
      "check-close-notify",
      "decline-alpn",
      "decline-ocsp-callback",
      "dtls",
      "enable-all-curves",
      "enable-channel-id",
      "enable-early-data",
      "enable-ed25519",
      "enable-grease",
      "enable-ocsp-stapling",
      "enable-signed-cert-timestamps",
      "enforce-rsa-key-usage",
      //"expect-accept-early-data",
      "expect-extended-master-secret",
      "expect-no-offer-early-data",
      "expect-no-secure-renegotiation",
      "expect-no-session",
      "expect-no-session-id",
      //"expect-reject-early-data",
      "expect-secure-renegotiation",
      "expect-session-id",
      "expect-session-miss",
      "expect-sha256-client-cert",
      "expect-ticket-renewal",
      "expect-ticket-supports-early-data",
      //"expect-tls13-downgrade",
      "expect-verify-result",
      "expect-no-hrr",
      //"export-traffic-secrets",
      "fail-cert-callback",
      //"fail-ddos-callback",
      //"fail-early-callback",
      "fail-ocsp-callback",
      "fallback-scsv",
      //"false-start",
      "forbid-renegotiation-after-handshake",
      "handoff",
      "handshake-never-done",
      "handshake-twice",
      "handshaker-resume",
      //"ignore-tls13-downgrade",
      "implicit-handshake",
      "install-cert-compression-algs",
      "install-ddos-callback",
      "is-handshaker-supported",
      //"jdk11-workaround",
      //"key-update",
      "no-op-extra-handshake",
      "no-rsa-pss-rsae-certs",
      "no-ticket",
      "no-tls1",
      "no-tls11",
      "no-tls12",
      "no-tls13", // implict due to 1.3 not being implemented
      "on-resume-no-ticket",
      //"on-resume-verify-fail",
      //"partial-write",
      //"peek-then-read",
      //"read-with-unfinished-write",
      "reject-alpn",
      "renegotiate-freely",
      "renegotiate-ignore",
      "renegotiate-once",
      //"renew-ticket",
      "require-any-client-certificate",
      "retain-only-sha256-client-cert",
      //"reverify-on-resume",
      "select-empty-alpn",
      "send-alert",
      "server",
      "server-preference",
      "set-ocsp-in-callback",
      "shim-shuts-down",
      "shim-writes-first",
      //"tls-unique",
      "use-custom-verify-callback",
      "use-early-callback",
      "use-export-context",
      "use-exporter-between-reads",
      "use-ocsp-callback",
      //"use-old-client-cert-callback",
      //"use-ticket-callback",
      "verify-fail",
      "verify-peer",
      //"verify-peer-if-no-obc",
      "write-different-record-sizes",
   };

   const std::set<std::string> bogo_shim_string_opts = {
      "advertise-alpn",
      //"advertise-npn",
      "cert-file",
      "cipher",
      //"delegated-credential",
      "expect-advertised-alpn",
      "expect-alpn",
      "expect-client-ca-list",
      "expect-late-alpn",
      "expect-msg-callback",
      //"expect-next-proto",
      "expect-peer-cert-file",
      "expect-server-name",
      "export-context",
      "export-label",
      "handshaker-path",
      "host-name",
      "key-file",
      "psk",
      "psk-identity",
      "select-alpn",
      "select-next-proto",
      "srtp-profiles",
      "test-name",
      "use-client-ca-list",
      //"send-channel-id",
      //"write-settings",
   };

   const std::set<std::string> bogo_shim_base64_opts = {
      "expect-certificate-types",
      //"expect-channel-id",
      "expect-ocsp-response",
      //"expect-quic-transport-params",
      //"expect-signed-cert-timestamps",
      "ocsp-response",
      //"quic-transport-params",
      //"signed-cert-timestamps",
      //"ticket-key", /* we use a different ticket format from Boring */
      //"token-binding-params",
   };

   const std::set<std::string> bogo_shim_int_opts {
      "expect-cipher-aes",
      "expect-cipher-no-aes",
      "expect-curve-id",
      "expect-peer-signature-algorithm",
      "expect-ticket-age-skew",
      "expect-token-binding-param",
      "expect-total-renegotiations",
      "expect-version",
      //"export-early-keying-material",
      "export-keying-material",
      "initial-timeout-duration-ms",
      "max-cert-list",
      //"max-send-fragment",
      "max-version",
      "min-version",
      "mtu",
      "port",
      "read-size",
      "resume-count",
      "resumption-delay",
   };

   const std::set<std::string> bogo_shim_int_vec_opts {
      "curves",
      "expect-peer-verify-pref",
      "signing-prefs",
      "verify-prefs",
   };

   std::unique_ptr<Shim_Arguments> args(
      new Shim_Arguments(bogo_shim_flags,
                         bogo_shim_string_opts,
                         bogo_shim_base64_opts,
                         bogo_shim_int_opts,
                         bogo_shim_int_vec_opts));

   // may throw:
   args->parse_args(argv);

   return args;
   }

class Shim_Policy final : public Botan::TLS::Policy
   {
   public:
      Shim_Policy(const Shim_Arguments& args) : m_args(args), m_sessions(0) {}

      void incr_session_established() { m_sessions += 1; }

      std::vector<std::string> allowed_ciphers() const override
         {
         return {
            "AES-256/OCB(12)",
            "AES-128/OCB(12)",
            "ChaCha20Poly1305",
            "AES-256/GCM",
            "AES-128/GCM",
            "AES-256/CCM",
            "AES-128/CCM",
            "AES-256/CCM(8)",
            "AES-128/CCM(8)",
            "Camellia-256/GCM",
            "Camellia-128/GCM",
            "ARIA-256/GCM",
            "ARIA-128/GCM",
            "AES-256",
            "AES-128",
            "Camellia-256",
            "Camellia-128",
            "SEED",
            "3DES",
         };

         }

      std::vector<std::string> allowed_signature_hashes() const override
         {
         if(m_args.option_used("signing-prefs"))
            {
            std::vector<std::string> pref_hash;
            for(size_t pref : m_args.get_int_vec_opt("signing-prefs"))
               {
               const auto scheme = static_cast<Botan::TLS::Signature_Scheme>(pref);
               if(Botan::TLS::signature_scheme_is_known(scheme) == false)
                  continue;
               pref_hash.push_back(Botan::TLS::hash_function_of_scheme(scheme));
               }

            if(m_args.flag_set("server"))
               pref_hash.push_back("SHA-256");
            return pref_hash;
            }
         else
            {
            return { "SHA-512", "SHA-384", "SHA-256", "SHA-1" };
            }
         }

      //std::vector<std::string> allowed_macs() const override;

      std::vector<std::string> allowed_key_exchange_methods() const override
         {
         return {
            "ECDHE_PSK",
            "DHE_PSK",
            "PSK",
            "CECPQ1",
            "ECDH",
            "DH",
            "RSA",
         };
         }

      std::vector<std::string> allowed_signature_methods() const override
         {
         return {
            "ECDSA",
            "RSA",
            "IMPLICIT",
         };

         }

      std::vector<Botan::TLS::Signature_Scheme> acceptable_signature_schemes() const override
         {
         if(m_args.option_used("verify-prefs"))
            {
            std::vector<Botan::TLS::Signature_Scheme> schemes;
            for(size_t pref : m_args.get_int_vec_opt("verify-prefs"))
               {
               schemes.push_back(static_cast<Botan::TLS::Signature_Scheme>(pref));
               }

            return schemes;
            }

         return Botan::TLS::Policy::acceptable_signature_schemes();
         }

      std::vector<Botan::TLS::Signature_Scheme> allowed_signature_schemes() const override
         {
         if(m_args.option_used("signing-prefs"))
            {
            std::vector<Botan::TLS::Signature_Scheme> schemes;
            for(size_t pref : m_args.get_int_vec_opt("signing-prefs"))
               {
               schemes.push_back(static_cast<Botan::TLS::Signature_Scheme>(pref));
               }

            // BoGo gets sad if these are not included in our signature_algorithms extension
            if(!m_args.flag_set("server"))
               {
               schemes.push_back(Botan::TLS::Signature_Scheme::RSA_PKCS1_SHA256);
               schemes.push_back(Botan::TLS::Signature_Scheme::ECDSA_SHA256);
               }

            return schemes;
            }

         return Botan::TLS::Policy::allowed_signature_schemes();
         }

      //size_t minimum_signature_strength() const override;

      //bool require_cert_revocation_info() const override;

      std::vector<Botan::TLS::Group_Params> key_exchange_groups() const override
         {
         if(m_args.option_used("curves"))
            {
            std::vector<Botan::TLS::Group_Params> groups;
            for(size_t pref : m_args.get_int_vec_opt("curves"))
               {
               groups.push_back(static_cast<Botan::TLS::Group_Params>(pref));
               }

            return groups;
            }

         return Botan::TLS::Policy::key_exchange_groups();
         }

      bool use_ecc_point_compression() const override { return false; } // BoGo expects this

      //Botan::TLS::Group_Params choose_key_exchange_group(const std::vector<Botan::TLS::Group_Params>& peer_groups) const override;

      bool require_client_certificate_authentication() const override
         {
         return m_args.flag_set("require-any-client-certificate");
         }

      bool request_client_certificate_authentication() const override
         {
         return m_args.flag_set("verify-peer") ||
            m_args.flag_set("fail-cert-callback") ||
            require_client_certificate_authentication();
         }

      bool allow_insecure_renegotiation() const override
         {
         if(m_args.flag_set("expect-no-secure-renegotiation"))
            return true;
         else
            return false;
         }

      //bool include_time_in_hello_random() const override;

      bool allow_client_initiated_renegotiation() const override
         {
         if(m_args.flag_set("renegotiate-freely"))
            return true;

         if(m_args.flag_set("renegotiate-once") && m_sessions <= 1)
            return true;

         return false;
         }

      bool allow_server_initiated_renegotiation() const override
         {
         return allow_client_initiated_renegotiation(); // same logic
         }

      bool allow_version(Botan::TLS::Protocol_Version version) const
         {
         if(m_args.option_used("min-version"))
            {
            const uint16_t min_version_16 = static_cast<uint16_t>(m_args.get_int_opt("min-version"));
            Botan::TLS::Protocol_Version min_version(min_version_16 >> 8, min_version_16 & 0xFF);
            if(min_version > version)
               return false;
            }

         if(m_args.option_used("max-version"))
            {
            const uint16_t max_version_16 = static_cast<uint16_t>(m_args.get_int_opt("max-version"));
            Botan::TLS::Protocol_Version max_version(max_version_16 >> 8, max_version_16 & 0xFF);
            if(version > max_version)
               return false;
            }

         return version.known_version();
         }

      bool allow_tls12() const override
         {
         return !m_args.flag_set("dtls") && !m_args.flag_set("no-tls12") && allow_version(Botan::TLS::Protocol_Version::TLS_V12);
         }

      bool allow_tls13() const override
         {
         //TODO: No TLS 1.3 allowed until it is implemented
         return false;
         }

      bool allow_dtls12() const override
         {
         return m_args.flag_set("dtls") && !m_args.flag_set("no-tls12") && allow_version(Botan::TLS::Protocol_Version::DTLS_V12);
         }

      //Botan::TLS::Group_Params default_dh_group() const override;

      //size_t minimum_dh_group_size() const override;

      size_t minimum_ecdsa_group_size() const override { return 224; }

      size_t minimum_ecdh_group_size() const override { return 224; }

      //size_t minimum_rsa_bits() const override;

      //size_t minimum_dsa_group_size() const override;

      //void check_peer_key_acceptable(const Botan::Public_Key& public_key) const override;

      //bool hide_unknown_users() const override;

      //uint32_t session_ticket_lifetime() const override;

      std::vector<uint16_t> srtp_profiles() const override
         {
         if(m_args.option_used("srtp-profiles"))
            {
            std::string srtp = m_args.get_string_opt("srtp-profiles");

            if(srtp == "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32")
               return {1,2};
            else if(srtp == "SRTP_AES128_CM_SHA1_80")
               return {1};
            else
               shim_exit_with_error("unknown srtp-profiles");
            }
         else
            return {};
         }

      bool only_resume_with_exact_version() const override
         {
         return false;
         }

      //bool server_uses_own_ciphersuite_preferences() const override;

      //bool negotiate_encrypt_then_mac() const override;

      bool support_cert_status_message() const override
         {
         if(m_args.flag_set("server"))
            {
            if(!m_args.option_used("ocsp-response"))
               return false;
            if(m_args.flag_set("decline-ocsp-callback"))
               return false;
            }
         return true;
         }

      std::vector<uint16_t> ciphersuite_list(Botan::TLS::Protocol_Version version) const override;

      size_t dtls_default_mtu() const override
         {
         return m_args.get_int_opt_or_else("mtu", 1500);
         }

      //size_t dtls_initial_timeout() const override;

      //size_t dtls_maximum_timeout() const override;

      bool allow_resumption_for_renegotiation() const override
         {
         return false; // BoGo expects this
         }

      bool abort_connection_on_undesired_renegotiation() const override
         {
         if(m_args.flag_set("renegotiate-ignore"))
            return false;
         else
            return true;
         }

      size_t maximum_certificate_chain_size() const override
         {
         return m_args.get_int_opt_or_else("max-cert-list", 0);
         }

   private:
      const Shim_Arguments& m_args;
      size_t m_sessions;
   };

std::vector<uint16_t> Shim_Policy::ciphersuite_list(Botan::TLS::Protocol_Version) const
   {
   std::vector<uint16_t> ciphersuite_codes;

   const std::string cipher_limit = m_args.get_string_opt_or_else("cipher", "");
   if(cipher_limit == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:[TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384|TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256|TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA]:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_128_CBC_SHA:[TLS_RSA_WITH_AES_256_GCM_SHA384|TLS_RSA_WITH_AES_256_CBC_SHA]")
      {
      std::vector<std::string> suites = {
         "ECDHE_RSA_WITH_AES_128_GCM_SHA256",
         "ECDHE_RSA_WITH_AES_256_GCM_SHA384",
         "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
         "ECDHE_RSA_WITH_AES_256_CBC_SHA",
         "RSA_WITH_AES_256_GCM_SHA384",
         "RSA_WITH_AES_256_CBC_SHA",
      };

      for(auto suite_name : suites)
         {
         const auto suite = Botan::TLS::Ciphersuite::from_name(suite_name);
         if(suite.valid() == false)
            shim_exit_with_error("Bad ciphersuite name " + suite_name);
         ciphersuite_codes.push_back(suite.ciphersuite_code());
         }
      }
   else
      {
      // Hack: go in reverse order to avoid preferring 3DES
      auto ciphersuites = Botan::TLS::Ciphersuite::all_known_ciphersuites();
      for(auto i = ciphersuites.rbegin(); i != ciphersuites.rend(); ++i)
         {
         const auto suite = *i;

         //TODO: Dummy way of skipping TLS 1.3 cipher suites
         if(suite.kex_method() == Botan::TLS::Kex_Algo::UNDEFINED &&
            suite.auth_method() == Botan::TLS::Auth_Method::UNDEFINED)
            continue;

         // Can we use it?
         if(suite.valid() == false)
            continue;

         if(cipher_limit != "")
            {
            if(cipher_limit == "DEFAULT:!AES")
               {
               const std::string suite_algo = suite.cipher_algo();

               if(suite_algo == "AES-128" || suite_algo == "AES-256" ||
                  suite_algo == "AES-128/GCM" || suite_algo == "AES-256/GCM" ||
                  suite_algo == "AES-128/CCM" || suite_algo == "AES-256/CCM" ||
                  suite_algo == "AES-128/CCM(8)" || suite_algo == "AES-256/CCM(8)" ||
                  suite_algo == "AES-128/OCB(12)" || suite_algo == "AES-256/OCB(12)")
                  {
                  continue;
                  }
               }
            else
               {
               shim_exit_with_error("Unknown cipher " + cipher_limit);
               }
            }

         ciphersuite_codes.push_back(suite.ciphersuite_code());
         }
      }

   return ciphersuite_codes;
   }

class Shim_Credentials final : public Botan::Credentials_Manager
   {
   public:
      Shim_Credentials(const Shim_Arguments& args) : m_args(args)
         {
         m_psk_identity = m_args.get_string_opt_or_else("psk-identity", "");

         const std::string psk_str = m_args.get_string_opt_or_else("psk", "");
         m_psk = Botan::SymmetricKey(reinterpret_cast<const uint8_t*>(psk_str.data()), psk_str.size());

         if(m_args.option_used("key-file") && m_args.option_used("cert-file"))
            {
            Botan::DataSource_Stream key_stream(m_args.get_string_opt("key-file"));
            m_key = Botan::PKCS8::load_key(key_stream);

            Botan::DataSource_Stream cert_stream(m_args.get_string_opt("cert-file"));

            while(!cert_stream.end_of_data())
               {
               try
                  {
                  m_cert_chain.push_back(Botan::X509_Certificate(cert_stream));
                  }
               catch(...) {}
               }
            }
         }

      std::string psk_identity(const std::string& /*type*/,
                               const std::string& /*context*/,
                               const std::string& /*identity_hint*/) override
         {
         return m_psk_identity;
         }

      std::string psk_identity_hint(const std::string& /*type*/,
                                    const std::string& /*context*/) override
         {
         return m_psk_identity;
         }

      Botan::SymmetricKey psk(const std::string& type,
                              const std::string& context,
                              const std::string& identity) override
         {
         if(type == "tls-server" && context == "session-ticket")
            {
            if(!m_args.flag_set("no-ticket") && !m_args.flag_set("on-resume-no-ticket"))
               return Botan::SymmetricKey("ABCDEF0123456789");
            }

         if(type == "tls-server" && context == "dtls-cookie-secret")
            {
            return Botan::SymmetricKey("F00FB00FD00F100F700F");
            }

         if(identity != m_psk_identity)
            throw Shim_Exception("Unexpected PSK identity");
         return m_psk;
         }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::string& /*type*/,
         const std::string& /*context*/) override
         {
         if(m_args.flag_set("fail-cert-callback"))
            throw std::runtime_error("Simulating cert verify callback failure");

         if(m_key != nullptr && m_cert_chain.size() > 0)
            {
            for(std::string t : cert_key_types)
               {
               if(t == m_key->algo_name())
                  return m_cert_chain;
               }
            }

         return {};
         }

      Botan::Private_Key* private_key_for(const Botan::X509_Certificate& /*cert*/,
                                          const std::string& /*type*/,
                                          const std::string& /*context*/) override
         {
         // assumes cert == m_cert
         return m_key.get();
         }

   private:
      const Shim_Arguments& m_args;
      Botan::SymmetricKey m_psk;
      std::string m_psk_identity;
      std::unique_ptr<Botan::Private_Key> m_key;
      std::vector<Botan::X509_Certificate> m_cert_chain;
   };

class Shim_Callbacks final : public Botan::TLS::Callbacks
   {
   public:
      Shim_Callbacks(const Shim_Arguments& args, Shim_Socket& socket, Shim_Policy& policy) :
         m_channel(nullptr),
         m_args(args),
         m_policy(policy),
         m_socket(socket),
         m_is_datagram(args.flag_set("dtls")),
         m_warning_alerts(0),
         m_empty_records(0),
         m_sessions_established(0),
         m_got_close(false)
         {}

      size_t sessions_established() const { return m_sessions_established; }

      void set_channel(Botan::TLS::Channel* channel)
         {
         m_channel = channel;
         }

      bool saw_close_notify() const { return m_got_close; }

      void tls_emit_data(const uint8_t data[], size_t size) override
         {
         shim_log("sending record of len " + std::to_string(size));

         if(m_is_datagram)
            {
            std::vector<uint8_t> packet(size + 5);

            packet[0] = 'P';
            for(size_t i = 0; i != 4; ++i)
               packet[i+1] = static_cast<uint8_t>((size >> (24-8*i)) & 0xFF);
            std::memcpy(packet.data() + 5, data, size);

            m_socket.write(packet.data(), packet.size());
            }
         else
            {
            m_socket.write(data, size);
            }
         }

      std::vector<uint8_t> tls_provide_cert_status(const std::vector<Botan::X509_Certificate>&,
                                                   const Botan::TLS::Certificate_Status_Request&) override
          {
          if(m_args.flag_set("use-ocsp-callback") && m_args.flag_set("fail-ocsp-callback"))
             throw std::runtime_error("Simulating failure from OCSP response callback");

          if(m_args.flag_set("decline-ocsp-callback"))
             return {};

          if(m_args.option_used("ocsp-response"))
             {
             return m_args.get_b64_opt("ocsp-response");
             }

          return {};
          }

      void tls_record_received(uint64_t /*seq_no*/, const uint8_t data[], size_t size) override
         {
         if(size == 0)
            {
            m_empty_records += 1;
            if(m_empty_records > 32)
               shim_exit_with_error(":TOO_MANY_EMPTY_FRAGMENTS:");
            }
         else
            {
            m_empty_records = 0;
            }

         shim_log("Reflecting application_data len " + std::to_string(size));

         std::vector<uint8_t> buf(data, data + size);
         for(size_t i = 0; i != size; ++i)
            buf[i] ^= 0xFF;

         m_channel->send(buf);
         }

      bool tls_verify_message(const Botan::Public_Key& key,
                              const std::string& emsa,
                              Botan::Signature_Format format,
                              const std::vector<uint8_t>& msg,
                              const std::vector<uint8_t>& sig) override
         {
         if(m_args.option_used("expect-peer-signature-algorithm"))
            {
            const auto scheme = static_cast<Botan::TLS::Signature_Scheme>(m_args.get_int_opt("expect-peer-signature-algorithm"));
            if(scheme != Botan::TLS::Signature_Scheme::NONE)
               {
               const std::string exp_emsa = Botan::TLS::padding_string_for_scheme(scheme);
               if(emsa != exp_emsa)
                  shim_exit_with_error("Unexpected signature scheme got " + emsa + " expected " + exp_emsa);
               }
            }
         return Botan::TLS::Callbacks::tls_verify_message(key, emsa, format, msg, sig);
         }

      void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& /*cert_chain*/,
                                 const std::vector<std::optional<Botan::OCSP::Response>>& /*ocsp_responses*/,
                                 const std::vector<Botan::Certificate_Store*>& /*trusted_roots*/,
                                 Botan::Usage_Type /*usage*/,
                                 const std::string& /*hostname*/,
                                 const Botan::TLS::Policy& /*policy*/) override
         {
         if(m_args.flag_set("enable-ocsp-stapling") &&
            m_args.flag_set("use-ocsp-callback") &&
            m_args.flag_set("fail-ocsp-callback"))
            {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::BAD_CERTIFICATE_STATUS_RESPONSE,
                                            "Simulated OCSP callback failure");
            }

         if(m_args.flag_set("verify-fail"))
            {
            auto alert = Botan::TLS::Alert::HANDSHAKE_FAILURE;
            if(m_args.flag_set("use-custom-verify-callback"))
               alert = Botan::TLS::Alert::CERTIFICATE_UNKNOWN;

            throw Botan::TLS::TLS_Exception(alert, "Test requires rejecting cert");
            }
         }

      std::string tls_server_choose_app_protocol(const std::vector<std::string>& client_protos) override
         {
         if(client_protos.empty())
            return ""; // shouldn't happen?

         if(m_args.flag_set("reject-alpn"))
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::NO_APPLICATION_PROTOCOL,
                                            "Rejecting ALPN request with alert");

         if(m_args.flag_set("decline-alpn"))
            return "";

         if(m_args.option_used("expect-advertised-alpn"))
            {
            const std::vector<std::string> expected = m_args.get_alpn_string_vec_opt("expect-advertised-alpn");

            if(client_protos != expected)
               shim_exit_with_error("Bad ALPN from client");
            }

         if(m_args.option_used("select-alpn"))
            return m_args.get_string_opt("select-alpn");

         return client_protos[0]; // if not configured just pick something
         }

      void tls_alert(Botan::TLS::Alert alert) override
         {
         if(alert.is_fatal())
            shim_log("Got a fatal alert " + alert.type_string());
         else
            shim_log("Got a warning alert " + alert.type_string());

         if(alert.type() == Botan::TLS::Alert::RECORD_OVERFLOW)
            {
            shim_exit_with_error(":TLSV1_ALERT_RECORD_OVERFLOW:");
            }

         if(alert.type() == Botan::TLS::Alert::DECOMPRESSION_FAILURE)
            {
            shim_exit_with_error(":SSLV3_ALERT_DECOMPRESSION_FAILURE:");
            }

         if(!alert.is_fatal())
            {
            m_warning_alerts++;
            if(m_warning_alerts > 5)
               shim_exit_with_error(":TOO_MANY_WARNING_ALERTS:");
            }

         if(alert.type() == Botan::TLS::Alert::CLOSE_NOTIFY)
            {
            if(m_got_close == false && !m_args.flag_set("shim-shuts-down"))
               {
               shim_log("Sending return close notify");
               m_channel->send_alert(alert);
               }
            m_got_close = true;
            }
         else if(alert.is_fatal())
            {
            shim_exit_with_error("Unexpected fatal alert " + alert.type_string());
            }
         }

      bool tls_session_established(const Botan::TLS::Session& session) override
         {
         shim_log("Session established: " + Botan::hex_encode(session.session_id()) +
                  " version " + session.version().to_string() +
                  " cipher " + session.ciphersuite().to_string() +
                  " EMS " + std::to_string(session.supports_extended_master_secret()));
         // probably need tests here?

         m_policy.incr_session_established();
         m_sessions_established++;

         if(m_args.flag_set("expect-no-session-id"))
            {
            // BoGo expects that ticket issuance implies no stateful session...
            if(!m_args.flag_set("server") && session.session_id().size() > 0)
               shim_exit_with_error("Unexpectedly got a session ID");
            }
         else if(m_args.flag_set("expect-session-id"))
            {
            if(session.session_id().empty())
               shim_exit_with_error("Unexpectedly got no session ID");
            }

         if(m_args.option_used("expect-version"))
            {
            if(session.version().version_code() != m_args.get_int_opt("expect-version"))
               shim_exit_with_error("Unexpected version");
            }

         if(m_args.flag_set("expect-secure-renegotiation"))
            {
            if(m_channel->secure_renegotiation_supported() == false)
               shim_exit_with_error("Expected secure renegotiation");
            }
         else if(m_args.flag_set("expect-no-secure-renegotiation"))
            {
            if(m_channel->secure_renegotiation_supported() == true)
               shim_exit_with_error("Expected no secure renegotation");
            }

         if(m_args.flag_set("expect-extended-master-secret"))
            {
            if(session.supports_extended_master_secret() == false)
               shim_exit_with_error("Expected extended maseter secret");
            }

         return true;
         }

      void tls_session_activated() override
         {
         if(m_args.flag_set("send-alert"))
            {
            m_channel->send_fatal_alert(Botan::TLS::Alert::DECOMPRESSION_FAILURE);
            return;
            }

         if(size_t length = m_args.get_int_opt_or_else("export-keying-material", 0))
            {
            const std::string label = m_args.get_string_opt("export-label");
            const std::string context = m_args.get_string_opt("export-context");
            const auto exported = m_channel->key_material_export(label, context, length);
            shim_log("Sending " + std::to_string(length) + " bytes of key material");
            m_channel->send(exported.bits_of());
            }

         const std::string alpn = m_channel->application_protocol();

         if(m_args.option_used("expect-alpn"))
            {
            if(alpn != m_args.get_string_opt("expect-alpn"))
               shim_exit_with_error("Got unexpected ALPN");
            }

         if(alpn == "baz" && !m_args.flag_set("allow-unknown-alpn-protos"))
            {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::ILLEGAL_PARAMETER,
                                            "Unexpected ALPN protocol");
            }

         if(m_args.flag_set("shim-shuts-down"))
            {
            shim_log("Shim shutting down");
            m_channel->close();
            }

         if(m_args.flag_set("write-different-record-sizes"))
            {
            static const size_t record_sizes[] = {
               0, 1, 255, 256, 257, 16383, 16384, 16385, 32767, 32768, 32769
            };

            std::vector<uint8_t> buf(32769, 0x42);

            for(size_t sz : record_sizes)
               {
               m_channel->send(buf.data(), sz);
               }

            m_channel->close();
            }
         }

   private:
      Botan::TLS::Channel* m_channel;
      const Shim_Arguments& m_args;
      Shim_Policy& m_policy;
      Shim_Socket& m_socket;
      const bool m_is_datagram;
      size_t m_warning_alerts;
      size_t m_empty_records;
      size_t m_sessions_established;
      bool m_got_close;
   };

}

int main(int /*argc*/, char* argv[])
   {
   try
      {
      std::unique_ptr<Shim_Arguments> args = parse_options(argv);

      if(args->flag_set("is-handshaker-supported"))
         {
         return shim_output("No\n");
         }

      const uint16_t port = static_cast<uint16_t>(args->get_int_opt("port"));
      const size_t resume_count = args->get_int_opt_or_else("resume-count", 0);
      const bool is_server = args->flag_set("server");
      const bool is_datagram = args->flag_set("dtls");

      const size_t buf_size = args->get_int_opt_or_else("read-size", 18*1024);

      Botan::ChaCha_RNG rng(Botan::secure_vector<uint8_t>(64));
      Botan::TLS::Session_Manager_In_Memory session_manager(rng, 1024);
      Shim_Credentials creds(*args);

      for(size_t i = 0; i != resume_count+1; ++i)
         {

         auto execute_test = [&](const std::string& hostname) {
         Shim_Socket socket(hostname, port);

         shim_log("Connection " + std::to_string(i+1) + "/" + std::to_string(resume_count+1));

         Shim_Policy policy(*args);
         Shim_Callbacks callbacks(*args, socket, policy);

         std::unique_ptr<Botan::TLS::Channel> chan;

         if(is_server)
            {
            chan.reset(new Botan::TLS::Server(callbacks, session_manager, creds, policy, rng, is_datagram));
            }
         else
            {
            Botan::TLS::Protocol_Version offer_version = policy.latest_supported_version(is_datagram);
            shim_log("Offering " + offer_version.to_string());

            std::string host_name = args->get_string_opt_or_else("host-name", hostname);
            if(args->test_name().find("UnsolicitedServerNameAck") == 0)
               host_name = ""; // avoid sending SNI for this test

            Botan::TLS::Server_Information server_info(host_name, port);
            const std::vector<std::string> next_protocols = args->get_alpn_string_vec_opt("advertise-alpn");
            chan.reset(new Botan::TLS::Client(callbacks, session_manager, creds, policy, rng,
                                              server_info, offer_version, next_protocols));
            }

         callbacks.set_channel(chan.get());

         std::vector<uint8_t> buf(buf_size);

         for(;;)
            {
            if(is_datagram)
               {
               uint8_t opcode;
               size_t got = socket.read(&opcode, 1);
               if(got == 0)
                  {
                  shim_log("EOF on socket");
                  break;
                  }

               if(opcode == 'P')
                  {
                  uint8_t len_bytes[4];
                  socket.read_exactly(len_bytes, sizeof(len_bytes));

                  size_t packet_len = Botan::load_be<uint32_t>(len_bytes, 0);

                  if(buf.size() < packet_len)
                     buf.resize(packet_len);
                  socket.read_exactly(buf.data(), packet_len);

                  chan->received_data(buf.data(), packet_len);
                  }
               else if(opcode == 'T')
                  {
                  uint8_t timeout_ack = 't';

                  uint8_t timeout_bytes[8];
                  socket.read_exactly(timeout_bytes, sizeof(timeout_bytes));

                  const uint64_t nsec = Botan::load_be<uint64_t>(timeout_bytes, 0);

                  shim_log("Timeout nsec " + std::to_string(nsec));

                  // FIXME handle this!

                  socket.write(&timeout_ack, 1); // ack it anyway
                  }
               else
                  shim_exit_with_error("Unknown opcode " + std::to_string(opcode));
               }
            else
               {
               size_t got = socket.read(buf.data(), buf.size());
               if(got == 0)
                  {
                  shim_log("EOF on socket");
                  break;
                  }

               shim_log("Got packet of " + std::to_string(got));

               if(args->flag_set("use-exporter-between-reads") && chan->is_active())
                  {
                  chan->key_material_export("some label", "some context", 42);
                  }
               const size_t needed = chan->received_data(buf.data(), got);

               if(needed)
                  shim_log("Short read still need " + std::to_string(needed));
               }
            }

         if(args->flag_set("check-close-notify"))
            {
            if(!callbacks.saw_close_notify())
               throw Shim_Exception("Unexpected SSL_shutdown result: -1 != 1");
            }

         if(args->option_used("expect-total-renegotiations"))
            {
            const size_t exp = args->get_int_opt("expect-total-renegotiations");

            if(exp != callbacks.sessions_established() - 1)
               throw Shim_Exception("Unexpected number of renegotiations: saw " +
                                    std::to_string(callbacks.sessions_established() - 1) +
                                    " exp " + std::to_string(exp));
            }
         shim_log("End of resume loop");
         };
         try
            {
            execute_test("localhost");
            }
         catch (const Shim_Exception& e)
            {
            if (std::string(e.what()) == "Failed to connect to host")
               {
               execute_test("::1");
               }
            else
               {
               throw e;
               }
            }
         }
      }
   catch(Shim_Exception& e)
      {
      shim_exit_with_error(e.what(), e.rc());
      }
   catch(std::exception& e)
      {
      shim_exit_with_error(map_to_bogo_error(e.what()));
      }
   catch(...)
      {
      shim_exit_with_error("Unknown exception", 3);
      }
   return 0;
   }
