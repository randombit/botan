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

#include <botan/base64.h>
#include <botan/chacha_rng.h>
#include <botan/data_src.h>
#include <botan/hex.h>
#include <botan/mem_ops.h>
#include <botan/ocsp.h>
#include <botan/pkcs8.h>
#include <botan/tls_algos.h>
#include <botan/tls_client.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_messages.h>
#include <botan/tls_server.h>
#include <botan/tls_session_manager_hybrid.h>
#include <botan/tls_session_manager_memory.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/parsing.h>
#include <botan/internal/stl_util.h>

#include <ctime>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)
   #include <errno.h>
   #include <fcntl.h>
   #include <netdb.h>
   #include <netinet/in.h>
   #include <string.h>
   #include <sys/socket.h>
   #include <sys/time.h>
   #include <unistd.h>
#endif

namespace {

int shim_output(const std::string& s, int rc = 0) {
   std::cout << s << "\n";
   return rc;
}

void shim_log(const std::string& s) {
   if(::getenv("BOTAN_BOGO_SHIM_LOG")) {
      /*
      FIXMEs:
       - Rewrite this to use a std::ostream instead
       - Allow using the env variable to point to where the log is written
       - Avoid rechecking the env variable with each call (!)
      */

      // NOLINTNEXTLINE(*-avoid-non-const-global-variables)
      static FILE* g_log = std::fopen("/tmp/bogo_shim.log", "w");
      struct timeval tv;
      ::gettimeofday(&tv, nullptr);
      static_cast<void>(std::fprintf(g_log,
                                     "%lld.%lu: %s\n",
                                     static_cast<unsigned long long>(tv.tv_sec),
                                     static_cast<unsigned long>(tv.tv_usec),
                                     s.c_str()));
      static_cast<void>(std::fflush(g_log));
   }
}

[[noreturn]] void shim_exit_with_error(const std::string& s, int rc = 1) {
   shim_log("Exiting with " + s);
   std::cerr << s << "\n";
   std::exit(rc);
}

std::string map_to_bogo_error(const std::string& e) {
   shim_log("Original error " + e);

   static const std::unordered_map<std::string, std::string> err_map{
      {"Application data before handshake done", ":APPLICATION_DATA_INSTEAD_OF_HANDSHAKE:"},
      {"Bad Hello_Request, has non-zero size", ":BAD_HELLO_REQUEST:"},
      {"Bad code for TLS alert level", ":UNKNOWN_ALERT_TYPE:"},
      {"Bad encoding on signature algorithms extension", ":DECODE_ERROR:"},
      {"Bad extension size", ":DECODE_ERROR:"},
      {"Bad length in hello verify request", ":DECODE_ERROR:"},
      {"Bad lengths in DTLS header", ":BAD_HANDSHAKE_RECORD:"},
      {"Bad signature on server key exchange", ":BAD_SIGNATURE:"},
      {"Server certificate verification failed", ":BAD_SIGNATURE:"},
      {"compression is not supported in TLS 1.3", ":DECODE_ERROR:"},
      {"Cookie length must be at least 1 byte", ":DECODE_ERROR:"},
      {"Bad size (1) for TLS alert message", ":BAD_ALERT:"},
      {"Bad size (4) for TLS alert message", ":BAD_ALERT:"},
      {"CERTIFICATE decoding failed with PEM: No PEM header found", ":CANNOT_PARSE_LEAF_CERT:"},
      {"Certificate usage constraints do not allow signing", ":KEY_USAGE_BIT_INCORRECT:"},
      {"Can't agree on a ciphersuite with client", ":NO_SHARED_CIPHER:"},
      {"Can't interleave application and handshake data", ":UNEXPECTED_RECORD:"},
      {"Certificate chain exceeds policy specified maximum size", ":EXCESSIVE_MESSAGE_SIZE:"},
      {"Certificate key type did not match ciphersuite", ":WRONG_CERTIFICATE_TYPE:"},
      {"Certificate usage constraints do not allow this ciphersuite", ":KEY_USAGE_BIT_INCORRECT:"},
      {"Certificate: Message malformed", ":DECODE_ERROR:"},
      {"Certificate_Request context must be empty in the main handshake", ":DECODE_ERROR:"},
      {"Certificate_Request message did not provide a signature_algorithms extension", ":DECODE_ERROR:"},
      {"Channel_Impl_12::key_material_export cannot export during renegotiation", "failed to export keying material"},
      {"Client cert verify failed", ":BAD_SIGNATURE:"},
      {"Client certificate does not support signing", ":KEY_USAGE_BIT_INCORRECT:"},
      {"Client certificate verification failed", ":BAD_SIGNATURE:"},
      {"Client did not comply with the requested key exchange group", ":WRONG_CURVE:"},
      {"Client did not offer NULL compression", ":INVALID_COMPRESSION_LIST:"},
      {"Client did not comply with the requested key exchange group", ":WRONG_CURVE:"},
      {"Client Hello must either contain both key_share and supported_groups extensions or neither",
       ":MISSING_KEY_SHARE:"},
      {"Client Hello offered a PSK without a psk_key_exchange_modes extension", ":MISSING_EXTENSION:"},
      {"Client offered DTLS version with major version 0xFF", ":UNSUPPORTED_PROTOCOL:"},
      {"Client offered SSLv3 which is not supported", ":UNSUPPORTED_PROTOCOL:"},
      {"Client offered TLS version with major version under 3", ":UNSUPPORTED_PROTOCOL:"},
      {"Expected server hello of (D)TLS 1.2 or lower", ":UNSUPPORTED_PROTOCOL:"},
      {"Protocol version was not offered", ":UNSUPPORTED_PROTOCOL:"},
      {"Client policy prohibits insecure renegotiation", ":RENEGOTIATION_MISMATCH:"},
      {"Client policy prohibits renegotiation", ":NO_RENEGOTIATION:"},
      {"Client resumed extended ms session without sending extension", ":RESUMED_EMS_SESSION_WITHOUT_EMS_EXTENSION:"},
      {"Client sent plaintext HTTP proxy CONNECT request instead of TLS handshake", ":HTTPS_PROXY_REQUEST:"},
      {"Client sent plaintext HTTP request instead of TLS handshake", ":HTTP_REQUEST:"},
      {"Client signalled fallback SCSV, possible attack", ":INAPPROPRIATE_FALLBACK:"},
      {"Client version TLS v1.1 is unacceptable by policy", ":UNSUPPORTED_PROTOCOL:"},
      {"Concatenated public values have an unexpected length", ":BAD_ECPOINT:"},
      {"No shared TLS version based on supported versions extension", ":UNSUPPORTED_PROTOCOL:"},
      {"Client: No certificates sent by server", ":DECODE_ERROR:"},
      {"Decoded polynomial coefficients out of range", ":BAD_ECPOINT:"},
      {"Non-PSK Client Hello did not contain supported_groups and signature_algorithms extensions",
       ":NO_SHARED_GROUP:"},
      {"No certificates sent by server", ":PEER_DID_NOT_RETURN_A_CERTIFICATE:"},
      {"Not enough data to read another KeyShareEntry", ":DECODE_ERROR:"},
      {"Not enough PSK binders", ":PSK_IDENTITY_BINDER_COUNT_MISMATCH:"},
      {"Counterparty sent inconsistent key and sig types", ":WRONG_SIGNATURE_TYPE:"},
      {"Downgrade attack detected", ":TLS13_DOWNGRADE:"},
      {"Empty ALPN protocol not allowed", ":PARSE_TLSEXT:"},
      {"Empty PSK binders list", ":DECODE_ERROR: "},
      {"Encoding error: Cannot encode PSS string, output length too small", ":NO_COMMON_SIGNATURE_ALGORITHMS:"},
      {"Expected TLS but got a record with DTLS version", ":WRONG_VERSION_NUMBER:"},
      {"Extension removed in updated Client Hello", ":INCONSISTENT_CLIENT_HELLO:"},
      {"Failed to agree on a signature algorithm", ":NO_COMMON_SIGNATURE_ALGORITHMS:"},
      {"Failed to agree on any signature algorithm", ":NO_COMMON_SIGNATURE_ALGORITHMS:"},
      {"Failed to deserialize elliptic curve point", ":BAD_ECPOINT:"},
      {"Failed to negotiate a common signature algorithm for client authentication",
       ":NO_COMMON_SIGNATURE_ALGORITHMS:"},
      {"PSK extension was not at the very end of the Client Hello", ":PRE_SHARED_KEY_MUST_BE_LAST:"},
      {"Finished message didn't verify", ":DIGEST_CHECK_FAILED:"},
      {"Have data remaining in buffer after ClientHello", ":EXCESS_HANDSHAKE_DATA:"},
      {"Have data remaining in buffer after Finished", ":EXCESS_HANDSHAKE_DATA:"},
      {"Have data remaining in buffer after ServerHelloDone", ":EXCESS_HANDSHAKE_DATA:"},
      {"Hello Retry Request does not request any changes to Client Hello", ":EMPTY_HELLO_RETRY_REQUEST:"},
      {"Unexpected additional handshake message data found in record", ":EXCESS_HANDSHAKE_DATA:"},
      {"Inconsistent length in certificate request", ":DECODE_ERROR:"},
      {"unexpected key_update parameter", ":DECODE_ERROR:"},
      {"Inconsistent values in fragmented DTLS handshake header", ":FRAGMENT_MISMATCH:"},
      {"Invalid CertificateRequest: Length field outside parameters", ":DECODE_ERROR:"},
      {"Invalid ServerHello: Length field outside parameters", ":DECODE_ERROR:"},
      {"Invalid CertificateVerify: Extra bytes at end of message", ":DECODE_ERROR:"},
      {"Invalid Certificate_Status: invalid length field", ":DECODE_ERROR:"},
      {"Invalid ChangeCipherSpec", ":BAD_CHANGE_CIPHER_SPEC:"},
      {"Invalid ClientHello: Length field outside parameters", ":DECODE_ERROR:"},
      {"Invalid ClientKeyExchange: Extra bytes at end of message", ":DECODE_ERROR:"},
      {"Invalid ServerKeyExchange: Extra bytes at end of message", ":DECODE_ERROR:"},
      {"Invalid SessionTicket: Extra bytes at end of message", ":DECODE_ERROR:"},
      {"Invalid authentication tag: ChaCha20Poly1305 tag check failed", ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:"},
      {"Invalid authentication tag: GCM tag check failed", ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:"},
      {"Invalid encapsulated key length", ":BAD_ECPOINT:"},
      {"Invalid hybrid KEM ciphertext", ":BAD_ECPOINT:"},
      {"Invalid size 31 for X25519 public key", ":BAD_ECPOINT:"},
      {"Invalid size 33 for X25519 public key", ":BAD_ECPOINT:"},
      {"Message authentication failure", ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:"},
      {"No content type found in encrypted record", ":DECRYPTION_FAILED_OR_BAD_RECORD_MAC:"},
      {"No shared DTLS version", ":UNSUPPORTED_PROTOCOL:"},
      {"No shared TLS version", ":UNSUPPORTED_PROTOCOL:"},
      {"OS2ECP: Unknown format type 251", ":BAD_ECPOINT:"},
      {"Peer sent signature algorithm that is not suitable for TLS 1.3", ":WRONG_SIGNATURE_TYPE:"},
      {"Policy forbids all available DTLS version", ":NO_SUPPORTED_VERSIONS_ENABLED:"},
      {"Policy forbids all available TLS version", ":NO_SUPPORTED_VERSIONS_ENABLED:"},
      {"Policy refuses to accept signing with any hash supported by peer", ":NO_COMMON_SIGNATURE_ALGORITHMS:"},
      {"Policy requires client send a certificate, but it did not", ":PEER_DID_NOT_RETURN_A_CERTIFICATE:"},
      {"PSK binder does not check out", ":DIGEST_CHECK_FAILED:"},
      {"PSK identity selected by server is out of bounds", ":PSK_IDENTITY_NOT_FOUND:"},
      {"PSK and ciphersuite selected by server are not compatible", ":OLD_SESSION_PRF_HASH_MISMATCH:"},
      {"Received a record that exceeds maximum size", ":ENCRYPTED_LENGTH_TOO_LONG:"},
      {"Received an encrypted record that exceeds maximum size", ":ENCRYPTED_LENGTH_TOO_LONG:"},
      {"received an illegal handshake message", ":UNEXPECTED_MESSAGE:"},
      {"Received a legacy Client Hello", ":UNSUPPORTED_PROTOCOL:"},
      {"Received an unexpected legacy Server Hello", ":UNSUPPORTED_PROTOCOL:"},
      {"Received application data after connection closure", ":APPLICATION_DATA_ON_SHUTDOWN:"},
      {"Received handshake data after connection closure", ":NO_RENEGOTIATION:"},
      {"Received multiple key share entries for the same group", ":DUPLICATE_KEY_SHARE:"},
      {"Received unexpected record version in initial record", ":WRONG_VERSION_NUMBER:"},
      {"Received unexpected record version", ":WRONG_VERSION_NUMBER:"},
      {"Rejecting ALPN request with alert", ":NO_APPLICATION_PROTOCOL:"},
      {"RSA signatures must use an RSASSA-PSS algorithm", ":WRONG_SIGNATURE_TYPE:"},
      {"Server attempting to negotiate SSLv3 which is not supported", ":UNSUPPORTED_PROTOCOL:"},
      {"Server certificate changed during renegotiation", ":SERVER_CERT_CHANGED:"},
      {"Server changed its mind about extended master secret", ":RENEGOTIATION_EMS_MISMATCH:"},
      {"Server changed its mind about secure renegotiation", ":RENEGOTIATION_MISMATCH:"},
      {"Server changed version after renegotiation", ":WRONG_SSL_VERSION:"},
      {"Server policy prohibits renegotiation", ":NO_RENEGOTIATION:"},
      {"Server replied using a ciphersuite not allowed in version it offered", ":WRONG_CIPHER_RETURNED:"},
      {"Server replied with an invalid version", ":UNSUPPORTED_PROTOCOL:"},
      {"server changed its chosen ciphersuite", ":WRONG_CIPHER_RETURNED:"},
      {"Server replied with DTLS-SRTP alg we did not send", ":BAD_SRTP_PROTECTION_PROFILE_LIST:"},
      {"Server replied with ciphersuite we didn't send", ":WRONG_CIPHER_RETURNED:"},
      {"Server replied with an invalid version", ":UNSUPPORTED_PROTOCOL:"},  // bogus version from "ServerBogusVersion"
      {"Server version SSL v3 is unacceptable by policy", ":UNSUPPORTED_PROTOCOL:"},  // "NoSSL3-Client-Unsolicited"
      {"legacy_version 'TLS v1.4' is not allowed", ":DECODE_ERROR:"},
      {"legacy_version 'Unknown 18.52' is not allowed", ":UNSUPPORTED_PROTOCOL:"},
      {"Server replied with non-null compression method", ":UNSUPPORTED_COMPRESSION_ALGORITHM:"},
      {"Server replied with some unknown ciphersuite", ":UNKNOWN_CIPHER_RETURNED:"},
      {"Server replied with unsupported extensions: 0", ":UNEXPECTED_EXTENSION:"},
      {"Server replied with unsupported extensions: 1234", ":UNEXPECTED_EXTENSION:"},
      {"Server replied with unsupported extensions: 16", ":UNEXPECTED_EXTENSION:"},
      {"Server replied with unsupported extensions: 43", ":UNEXPECTED_EXTENSION:"},
      {"Server replied with unsupported extensions: 5", ":UNEXPECTED_EXTENSION:"},
      {"Server resumed session and removed extended master secret", ":RESUMED_EMS_SESSION_WITHOUT_EMS_EXTENSION:"},
      {"Server resumed session but added extended master secret", ":RESUMED_NON_EMS_SESSION_WITH_EMS_EXTENSION:"},
      {"Server resumed session but with wrong version", ":OLD_SESSION_VERSION_NOT_RETURNED:"},
      {"Server selected a group that is not compatible with the negotiated ciphersuite", ":WRONG_CURVE:"},
      {"Server sent ECC curve prohibited by policy", ":WRONG_CURVE:"},
      {"group was not advertised as supported", ":WRONG_CURVE:"},
      {"group was already offered", ":WRONG_CURVE:"},
      {"Server selected a key exchange group we didn't offer.", ":WRONG_CURVE:"},
      {"TLS 1.3 Server Hello selected a different version", ":SECOND_SERVERHELLO_VERSION_MISMATCH:"},
      {"Version downgrade received after Hello Retry", ":SECOND_SERVERHELLO_VERSION_MISMATCH:"},
      {"protected change cipher spec received", ":UNEXPECTED_RECORD:"},
      {"Server sent an unsupported extension", ":UNEXPECTED_EXTENSION:"},
      {"Unsupported extension found in Server Hello", ":UNEXPECTED_EXTENSION:"},
      {"Unexpected extension received", ":UNEXPECTED_EXTENSION:"},
      {"server hello must contain key exchange information", ":MISSING_KEY_SHARE:"},
      {"Peer sent duplicated extensions", ":DUPLICATE_EXTENSION:"},
      {"Policy does not accept any hash function supported by client", ":NO_SHARED_CIPHER:"},
      {"Server sent bad values for secure renegotiation", ":RENEGOTIATION_MISMATCH:"},
      {"Server version DTLS v1.0 is unacceptable by policy", ":UNSUPPORTED_PROTOCOL:"},
      {"Server version TLS v1.0 is unacceptable by policy", ":UNSUPPORTED_PROTOCOL:"},
      {"Server version TLS v1.1 is unacceptable by policy", ":UNSUPPORTED_PROTOCOL:"},
      {"Server_Hello_Done: Must be empty, and is not", ":DECODE_ERROR:"},
      {"Simulated OCSP callback failure", ":OCSP_CB_ERROR:"},
      {"Simulating cert verify callback failure", ":CERT_CB_ERROR:"},
      {"Simulating failure from OCSP response callback", ":OCSP_CB_ERROR:"},
      {"TLS plaintext record is larger than allowed maximum", ":DATA_LENGTH_TOO_LONG:"},
      {"Received an encrypted record that exceeds maximum plaintext size", ":DATA_LENGTH_TOO_LONG:"},
      {"TLS record type had unexpected value", ":UNEXPECTED_RECORD:"},
      {"TLS record version had unexpected value", ":WRONG_VERSION_NUMBER:"},
      {"Test requires rejecting cert", ":CERTIFICATE_VERIFY_FAILED:"},
      {"Too many PSK binders", ":PSK_IDENTITY_BINDER_COUNT_MISMATCH:"},
      {"Unexpected ALPN protocol", ":INVALID_ALPN_PROTOCOL:"},
      {"Unexpected record type 42 from counterparty", ":UNEXPECTED_RECORD:"},
      {"Unexpected state transition in handshake got a certificate_request expected server_hello_done seen server_hello+server_key_exchange",
       ":UNEXPECTED_MESSAGE:"},
      {"Unexpected state transition in handshake got a certificate_request expected server_key_exchange|server_hello_done seen server_hello",
       ":UNEXPECTED_MESSAGE:"},
      {"Unexpected state transition in handshake got a certificate_status expected certificate seen server_hello",
       ":UNEXPECTED_MESSAGE:"},
      {"Unexpected state transition in handshake got a change_cipher_spec expected certificate_verify seen client_hello+certificate+client_key_exchange",
       ":UNEXPECTED_RECORD:"},
      {"Unexpected state transition in handshake got a change_cipher_spec expected client_key_exchange seen client_hello",
       ":UNEXPECTED_RECORD:"},
      {"Unexpected state transition in handshake got a change_cipher_spec expected new_session_ticket seen server_hello+certificate+server_key_exchange+server_hello_done",
       ":UNEXPECTED_RECORD:"},
      {"Unexpected state transition in handshake got a client_key_exchange expected certificate seen client_hello",
       ":UNEXPECTED_MESSAGE:"},
      {"Unexpected state transition in handshake got a finished expected certificate_verify seen client_hello+certificate",
       ":UNEXPECTED_MESSAGE:"},
      {"Unexpected state transition in handshake got a finished expected certificate seen client_hello",
       ":UNEXPECTED_MESSAGE:"},
      {"Unexpected state transition in handshake got a finished expected change_cipher_spec seen client_hello",
       ":UNEXPECTED_RECORD:"},
      {"Unexpected state transition in handshake got a finished expected change_cipher_spec seen client_hello+client_key_exchange",
       ":UNEXPECTED_RECORD:"},
      {"Unexpected state transition in handshake got a finished expected change_cipher_spec seen server_hello",
       ":UNEXPECTED_RECORD:"},
      {"Unexpected state transition in handshake got a finished expected change_cipher_spec seen server_hello+certificate+server_key_exchange+server_hello_done+new_session_ticket",
       ":UNEXPECTED_RECORD:"},
      {"Unexpected state transition in handshake got a hello_request expected server_hello", ":UNEXPECTED_MESSAGE:"},
      {"Unexpected state transition in handshake got a server_hello_done expected server_key_exchange seen server_hello+certificate+certificate_status",
       ":UNEXPECTED_MESSAGE:"},
      {"Unexpected state transition in handshake got a server_key_exchange expected certificate_request|server_hello_done seen server_hello+certificate+certificate_status",
       ":UNEXPECTED_MESSAGE:"},
      {"Unexpected state transition in handshake got a server_hello_done expected server_key_exchange seen server_hello+certificate",
       ":UNEXPECTED_MESSAGE:"},
      {"Unexpected state transition in handshake got a server_key_exchange expected certificate seen server_hello",
       ":UNEXPECTED_MESSAGE:"},
      {"Unexpected state transition in handshake got a server_key_exchange expected certificate_request|server_hello_done seen server_hello+certificate",
       ":UNEXPECTED_MESSAGE:"},
      {"Unexpected state transition in handshake got a hello_retry_request expected server_hello",
       ":UNEXPECTED_MESSAGE:"},
      {"Unexpected state transition in handshake got a server_key_exchange not expecting messages",
       ":BAD_HELLO_REQUEST:"},
      {"Unexpected state transition in handshake got a finished expected certificate_verify seen server_hello+certificate+encrypted_extensions",
       ":BAD_HELLO_REQUEST:"},
      {"Unknown TLS handshake message type 43", ":UNEXPECTED_MESSAGE:"},
      {"Unknown TLS handshake message type 44", ":UNEXPECTED_MESSAGE:"},
      {"Unknown TLS handshake message type 45", ":UNEXPECTED_MESSAGE:"},
      {"Unknown TLS handshake message type 46", ":UNEXPECTED_MESSAGE:"},
      {"Unknown TLS handshake message type 53", ":UNEXPECTED_MESSAGE:"},
      {"Unknown TLS handshake message type 54", ":UNEXPECTED_MESSAGE:"},
      {"Unknown TLS handshake message type 55", ":UNEXPECTED_MESSAGE:"},
      {"Unknown TLS handshake message type 56", ":UNEXPECTED_MESSAGE:"},
      {"Unknown TLS handshake message type 57", ":UNEXPECTED_MESSAGE:"},
      {"Unknown TLS handshake message type 58", ":UNEXPECTED_MESSAGE:"},
      {"Unknown TLS handshake message type 6", ":UNEXPECTED_MESSAGE:"},
      {"Unknown TLS handshake message type 62", ":UNEXPECTED_MESSAGE:"},
      {"Unknown TLS handshake message type 64", ":UNEXPECTED_MESSAGE:"},
      {"Unknown handshake message received", ":UNEXPECTED_MESSAGE:"},
      {"Unknown post-handshake message received", ":UNEXPECTED_MESSAGE:"},
      {"signature_algorithm_of_scheme: Unknown signature algorithm enum", ":WRONG_SIGNATURE_TYPE:"},
      {"Unexpected session ID during downgrade", ":SERVER_ECHOED_INVALID_SESSION_ID:"},
      {"Encrypted Extensions contained an extension that is not allowed", ":ERROR_PARSING_EXTENSION:"},
      {"Encrypted Extensions contained an extension that was not offered", ":UNEXPECTED_EXTENSION:"},
      {"Certificate Entry contained an extension that is not allowed", ":UNEXPECTED_EXTENSION:"},
      {"Certificate Entry contained an extension that was not offered", ":UNEXPECTED_EXTENSION:"},
      {"Server Hello contained an extension that is not allowed", ":UNEXPECTED_EXTENSION:"},
      {"Hello Retry Request contained an extension that is not allowed", ":UNEXPECTED_EXTENSION:"},
      {"Signature algorithm does not match certificate's public key", ":WRONG_SIGNATURE_TYPE:"},
      {"unprotected record received where protected traffic was expected", ":INVALID_OUTER_RECORD_TYPE:"},
      {"Error alert not marked fatal", ":BAD_ALERT:"},
      {"Peer sent unknown signature scheme", ":WRONG_SIGNATURE_TYPE:"},
      {"We did not offer the usage of RSA_PSS_SHA256 as a signature scheme", ":WRONG_SIGNATURE_TYPE:"},
      {"X25519 public point appears to be of low order", ":BAD_ECPOINT:"},
   };

   auto err_map_i = err_map.find(e);
   if(err_map_i != err_map.end()) {
      return err_map_i->second;
   }

   return "Unmapped error: '" + e + "'";
}

class Shim_Exception final : public std::exception {
   public:
      Shim_Exception(std::string_view msg, int rc = 1) : m_msg(msg), m_rc(rc) {}

      const char* what() const noexcept override { return m_msg.c_str(); }

      int rc() const { return m_rc; }

   private:
      const std::string m_msg;
      int m_rc;
};

#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)

class Shim_Socket final {
   private:
      typedef int socket_type;
      typedef ssize_t socket_op_ret_type;

      static void close_socket(socket_type s) { ::close(s); }

      static std::string get_last_socket_error() { return ::strerror(errno); }

      using unique_addrinfo_t = std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)>;

   public:
      Shim_Socket(const std::string& hostname, int port, const bool ipv6) : m_socket(-1) {
         addrinfo hints;
         std::memset(&hints, 0, sizeof(hints));
         hints.ai_family = AF_UNSPEC;
         hints.ai_socktype = SOCK_STREAM;
         hints.ai_flags = AI_NUMERICSERV;

         const std::string service = std::to_string(port);

         // TODO: C++23 will introduce std::out_ptr() that should replace the
         //       temporary variable for the call to ::getaddrinfo() and
         //       std::unique_ptr<>::reset().
         unique_addrinfo_t::pointer res_tmp;
         int rc = ::getaddrinfo(hostname.c_str(), service.c_str(), &hints, &res_tmp);
         unique_addrinfo_t res(res_tmp, &::freeaddrinfo);

         shim_log("Connecting " + hostname + ":" + service);

         if(rc != 0) {
            throw Shim_Exception("Name resolution failed for " + hostname);
         }

         for(addrinfo* rp = res.get(); (m_socket == -1) && (rp != nullptr); rp = rp->ai_next) {
            if((!ipv6 && rp->ai_family != AF_INET) || (ipv6 && rp->ai_family != AF_INET6)) {
               continue;
            }

            m_socket = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

            if(m_socket == -1) {
               // unsupported socket type?
               continue;
            }

            int err = ::connect(m_socket, rp->ai_addr, rp->ai_addrlen);

            if(err != 0) {
               ::close(m_socket);
               m_socket = -1;
            }
         }

         if(m_socket < 0) {
            throw Shim_Exception("Failed to connect to host");
         }
      }

      Shim_Socket(const Shim_Socket&) = delete;
      Shim_Socket& operator=(const Shim_Socket&) = delete;

      Shim_Socket(Shim_Socket&&) = delete;
      Shim_Socket& operator=(Shim_Socket&&) = delete;

      ~Shim_Socket() {
         ::close(m_socket);
         m_socket = -1;
      }

      void write(const uint8_t buf[], size_t len) const {
         if(m_socket < 0) {
            throw Shim_Exception("Socket was bad on write");
         }
         size_t sent_so_far = 0;
         while(sent_so_far != len) {
            const size_t left = len - sent_so_far;
            socket_op_ret_type sent =
               ::send(m_socket, Botan::cast_uint8_ptr_to_char(&buf[sent_so_far]), left, MSG_NOSIGNAL);
            if(sent < 0) {
               if(errno == EPIPE) {
                  return;
               } else {
                  throw Shim_Exception("Socket write failed", errno);
               }
            } else {
               sent_so_far += static_cast<size_t>(sent);
            }
         }
      }

      size_t read(uint8_t buf[], size_t len) const {
         if(m_socket < 0) {
            throw Shim_Exception("Socket was bad on read");
         }
         socket_op_ret_type got = ::read(m_socket, Botan::cast_uint8_ptr_to_char(buf), len);

         if(got < 0) {
            if(errno == ECONNRESET) {
               return 0;
            }
            throw Shim_Exception("Socket read failed: " + std::string(strerror(errno)));
         }

         return static_cast<size_t>(got);
      }

      void read_exactly(uint8_t buf[], size_t len) const {
         if(m_socket < 0) {
            throw Shim_Exception("Socket was bad on read");
         }

         while(len > 0) {
            socket_op_ret_type got = ::read(m_socket, Botan::cast_uint8_ptr_to_char(buf), len);

            if(got == 0) {
               throw Shim_Exception("Socket read EOF");
            } else if(got < 0) {
               throw Shim_Exception("Socket read failed: " + std::string(strerror(errno)));
            }

            buf += static_cast<size_t>(got);
            len -= static_cast<size_t>(got);
         }
      }

   private:
      socket_type m_socket;
};

#endif

std::set<std::string> combine_options(const std::set<std::string>& a,
                                      const std::set<std::string>& b,
                                      const std::set<std::string>& c,
                                      const std::set<std::string>& d) {
   std::set<std::string> combined;

   for(const auto& i : a) {
      combined.insert(i);
   }
   for(const auto& i : b) {
      combined.insert(i);
   }
   for(const auto& i : c) {
      combined.insert(i);
   }
   for(const auto& i : d) {
      combined.insert(i);
   }

   return combined;
}

class Shim_Arguments final {
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
            m_all_options(combine_options(string_opts, base64_opts, int_opts, int_vec_opts)) {}

      void parse_args(char* argv[]);

      bool flag_set(const std::string& flag) const {
         if(!m_flags.contains(flag)) {
            throw Shim_Exception("Unknown bool flag " + flag);
         }

         return m_parsed_flags.contains(flag);
      }

      std::string test_name() const { return get_string_opt("test-name"); }

      std::string get_string_opt(const std::string& key) const {
         if(!m_string_opts.contains(key)) {
            throw Shim_Exception("Unknown string key " + key);
         }
         return get_opt(key);
      }

      std::string get_string_opt_or_else(const std::string& key, const std::string& def) const {
         if(!m_string_opts.contains(key)) {
            throw Shim_Exception("Unknown string key " + key);
         }
         if(!option_used(key)) {
            return def;
         }
         return get_opt(key);
      }

      std::vector<uint8_t> get_b64_opt(const std::string& key) const {
         if(!m_base64_opts.contains(key)) {
            throw Shim_Exception("Unknown base64 key " + key);
         }
         return Botan::unlock(Botan::base64_decode(get_opt(key)));
      }

      size_t get_int_opt(const std::string& key) const {
         if(!m_int_opts.contains(key)) {
            throw Shim_Exception("Unknown int key " + key);
         }
         return Botan::to_u32bit(get_opt(key));
      }

      size_t get_int_opt_or_else(const std::string& key, size_t def) const {
         if(!m_int_opts.contains(key)) {
            throw Shim_Exception("Unknown int key " + key);
         }
         if(!option_used(key)) {
            return def;
         }

         return Botan::to_u32bit(get_opt(key));
      }

      std::vector<size_t> get_int_vec_opt(const std::string& key) const {
         if(!m_int_vec_opts.contains(key)) {
            throw Shim_Exception("Unknown int vec key " + key);
         }

         auto i = m_parsed_int_vec_opts.find(key);
         if(i == m_parsed_int_vec_opts.end()) {
            return std::vector<size_t>();
         } else {
            return i->second;
         }
      }

      std::vector<std::string> get_alpn_string_vec_opt(const std::string& option) const {
         // hack used for alpn list (relies on all ALPNs being 3 chars long...)
         char delim = 0x03;

         if(option_used(option)) {
            return Botan::split_on(get_string_opt(option), delim);
         } else {
            return std::vector<std::string>();
         }
      }

      bool option_used(const std::string& key) const {
         if(!m_all_options.contains(key)) {
            throw Shim_Exception("Invalid option " + key);
         }
         if(m_parsed_opts.find(key) != m_parsed_opts.end()) {
            return true;
         }
         if(m_parsed_int_vec_opts.find(key) != m_parsed_int_vec_opts.end()) {
            return true;
         }
         return false;
      }

   private:
      std::string get_opt(const std::string& key) const {
         auto i = m_parsed_opts.find(key);
         if(i == m_parsed_opts.end()) {
            throw Shim_Exception("Option " + key + " was not provided");
         }
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

void Shim_Arguments::parse_args(char* argv[]) {
   int i = 1;  // skip argv[0]

   while(argv[i] != nullptr) {
      const std::string param(argv[i]);

      if(param.starts_with("-")) {
         const std::string flag_name = param.substr(1, std::string::npos);

         if(m_flags.contains(flag_name)) {
            shim_log("flag " + flag_name);
            m_parsed_flags.insert(flag_name);
            i += 1;
         } else if(m_all_options.contains(flag_name)) {
            if(argv[i + 1] == nullptr) {
               throw Shim_Exception("Expected argument following " + param);
            }
            std::string val(argv[i + 1]);
            shim_log(Botan::fmt("param {}={}", flag_name, val));

            if(m_int_vec_opts.contains(flag_name)) {
               const size_t v = Botan::to_u32bit(val);
               m_parsed_int_vec_opts[flag_name].push_back(v);
            } else {
               m_parsed_opts[flag_name] = val;
            }
            i += 2;
         } else {
            shim_log("Unknown option " + param);
            throw Shim_Exception("Unknown option " + param, 89);
         }
      } else {
         shim_log("Unknown option " + param);
         throw Shim_Exception("Unknown option " + param, 89);
      }
   }
}

std::unique_ptr<Shim_Arguments> parse_options(char* argv[]) {
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
      "expect-hrr",
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
      "ipv6",
      "is-handshaker-supported",
      //"jdk11-workaround",
      "key-update",
      "no-check-client-certificate-type",
      "no-check-ecdsa-curve",
      "no-op-extra-handshake",
      "no-rsa-pss-rsae-certs",
      "no-ticket",
      "no-tls1",
      "no-tls11",
      "no-tls12",
      "no-tls13",
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
      "wait-for-debugger",
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
      "expect-early-data-reason",
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
      "trust-cert",
      "use-client-ca-list",
      //"send-channel-id",
      "write-settings",
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

   const std::set<std::string> bogo_shim_int_opts{
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
      "on-initial-expect-curve-id",
      "on-resume-expect-curve-id",
      "port",
      "read-size",
      "resume-count",
      "resumption-delay",
      "shim-id",
   };

   const std::set<std::string> bogo_shim_int_vec_opts{
      "curves",
      "expect-peer-verify-pref",
      "signing-prefs",
      "verify-prefs",
   };

   std::unique_ptr<Shim_Arguments> args(new Shim_Arguments(
      bogo_shim_flags, bogo_shim_string_opts, bogo_shim_base64_opts, bogo_shim_int_opts, bogo_shim_int_vec_opts));

   // may throw:
   args->parse_args(argv);

   return args;
}

class Shim_Policy final : public Botan::TLS::Policy {
   public:
      Shim_Policy(const Shim_Arguments& args) : m_args(args), m_sessions(0) {}

      void incr_session_established() { m_sessions += 1; }

      std::vector<std::string> allowed_ciphers() const override {
         std::vector<std::string> allowed_without_aes = {
            "ChaCha20Poly1305",
            "Camellia-256/GCM",
            "Camellia-128/GCM",
            "ARIA-256/GCM",
            "ARIA-128/GCM",
            "Camellia-256",
            "Camellia-128",
            "SEED",
         };

         std::vector<std::string> allowed_just_aes = {
            "AES-256/OCB(12)",
            "AES-128/OCB(12)",
            "AES-256/GCM",
            "AES-128/GCM",
            "AES-256/CCM",
            "AES-128/CCM",
            "AES-256/CCM(8)",
            "AES-128/CCM(8)",
            "AES-256",
            "AES-128",
         };

         // 3DES is not supported by default anymore, only if the test runner
         // explicitly enables it via -cipher=
         const std::string cipher_limit = m_args.get_string_opt_or_else("cipher", "");
         if(cipher_limit == "3DES") {
            return {"3DES"};
         } else if(cipher_limit == "DEFAULT:!AES") {
            return allowed_without_aes;
         } else {
            // ignore this very specific config (handled in the overload of ciphersuite_list)
            if(!cipher_limit.empty() &&
               cipher_limit !=
                  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:[TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384|TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256|TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA]:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_128_CBC_SHA:[TLS_RSA_WITH_AES_256_GCM_SHA384|TLS_RSA_WITH_AES_256_CBC_SHA]") {
               shim_exit_with_error("Unknown cipher limit " + cipher_limit);
            }
         }

         return Botan::concat(allowed_without_aes, allowed_just_aes);
      }

      std::vector<std::string> allowed_signature_hashes() const override {
         if(m_args.option_used("signing-prefs")) {
            std::vector<std::string> pref_hash;
            for(size_t pref : m_args.get_int_vec_opt("signing-prefs")) {
               const Botan::TLS::Signature_Scheme scheme(pref);
               if(!scheme.is_available()) {
                  shim_log("skipping inavailable but preferred signature scheme: " + std::to_string(pref));
                  continue;
               }
               pref_hash.push_back(scheme.hash_function_name());
            }

            if(m_args.flag_set("server")) {
               pref_hash.push_back("SHA-256");
            }
            return pref_hash;
         } else {
            return {"SHA-512", "SHA-384", "SHA-256", "SHA-1"};
         }
      }

      //std::vector<std::string> allowed_macs() const override;

      std::vector<std::string> allowed_signature_methods() const override {
         return {
            "ECDSA",
            "RSA",
            "IMPLICIT",
         };
      }

      std::vector<Botan::TLS::Signature_Scheme> acceptable_signature_schemes() const override {
         if(m_args.option_used("verify-prefs")) {
            std::vector<Botan::TLS::Signature_Scheme> schemes;
            for(size_t pref : m_args.get_int_vec_opt("verify-prefs")) {
               schemes.emplace_back(static_cast<uint16_t>(pref));
            }

            return schemes;
         }

         return Botan::TLS::Policy::acceptable_signature_schemes();
      }

      std::vector<Botan::TLS::Signature_Scheme> allowed_signature_schemes() const override {
         if(m_args.option_used("signing-prefs")) {
            std::vector<Botan::TLS::Signature_Scheme> schemes;
            for(size_t pref : m_args.get_int_vec_opt("signing-prefs")) {
               schemes.emplace_back(static_cast<uint16_t>(pref));
            }

            // The relevant tests (*-Sign-Negotiate-*) want to configure a preference
            // for the scheme of our signing operation (-signing-prefs). However, this
            // policy method (`allowed_signature_schemes`) also restricts the peer's
            // signing operation. If we weren't to add a few 'common' algorithms, initial
            // security parameter negotiation would fail.
            // By placing the BoGo-configured scheme first we make sure our implementation
            // meets BoGo's expectation when it is our turn to sign.
            if(!m_args.flag_set("server")) {
               schemes.emplace_back(Botan::TLS::Signature_Scheme::RSA_PKCS1_SHA256);
               schemes.emplace_back(Botan::TLS::Signature_Scheme::RSA_PSS_SHA256);
               schemes.emplace_back(Botan::TLS::Signature_Scheme::ECDSA_SHA256);
            }

            return schemes;
         }

         return Botan::TLS::Policy::allowed_signature_schemes();
      }

      //size_t minimum_signature_strength() const override;

      bool require_cert_revocation_info() const override { return false; }

      std::vector<Botan::TLS::Group_Params> key_exchange_groups() const override {
         if(m_args.option_used("curves")) {
            std::vector<Botan::TLS::Group_Params> groups;

            // upcall to base class to find the groups actually supported by
            // this Botan build
            const auto supported_groups = Botan::TLS::Policy::key_exchange_groups();

            for(size_t pref : m_args.get_int_vec_opt("curves")) {
               const auto group = static_cast<Botan::TLS::Group_Params>(pref);
               if(std::find(supported_groups.cbegin(), supported_groups.cend(), group) != supported_groups.end()) {
                  groups.push_back(group);
               }
            }

            return groups;
         }

         return Botan::TLS::Policy::key_exchange_groups();
      }

      bool use_ecc_point_compression() const override { return false; }  // BoGo expects this

      Botan::TLS::Group_Params choose_key_exchange_group(
         const std::vector<Botan::TLS::Group_Params>& supported_by_peer,
         const std::vector<Botan::TLS::Group_Params>& offered_by_peer) const override {
         BOTAN_UNUSED(offered_by_peer);

         // always insist on our most preferred group regardless of the peer's
         // pre-offers (BoGo expects it like that)
         const auto our_groups = key_exchange_groups();
         for(auto g : our_groups) {
            if(Botan::value_exists(supported_by_peer, g)) {
               return g;
            }
         }

         return Botan::TLS::Group_Params::NONE;
      }

      bool require_client_certificate_authentication() const override {
         return m_args.flag_set("require-any-client-certificate");
      }

      bool request_client_certificate_authentication() const override {
         return m_args.flag_set("verify-peer") || m_args.flag_set("fail-cert-callback") ||
                require_client_certificate_authentication();
      }

      bool allow_insecure_renegotiation() const override {
         if(m_args.flag_set("expect-no-secure-renegotiation")) {
            return true;
         } else {
            return false;
         }
      }

      //bool include_time_in_hello_random() const override;

      bool allow_client_initiated_renegotiation() const override {
         if(m_args.flag_set("renegotiate-freely")) {
            return true;
         }

         if(m_args.flag_set("renegotiate-once") && m_sessions <= 1) {
            return true;
         }

         return false;
      }

      bool allow_server_initiated_renegotiation() const override {
         return allow_client_initiated_renegotiation();  // same logic
      }

      bool allow_version(Botan::TLS::Protocol_Version version) const {
         if(m_args.option_used("min-version")) {
            const uint16_t min_version_16 = static_cast<uint16_t>(m_args.get_int_opt("min-version"));
            Botan::TLS::Protocol_Version min_version(min_version_16 >> 8, min_version_16 & 0xFF);
            if(min_version > version) {
               return false;
            }
         }

         if(m_args.option_used("max-version")) {
            const uint16_t max_version_16 = static_cast<uint16_t>(m_args.get_int_opt("max-version"));
            Botan::TLS::Protocol_Version max_version(max_version_16 >> 8, max_version_16 & 0xFF);
            if(version > max_version) {
               return false;
            }
         }

         return version.known_version();
      }

      bool allow_tls12() const override {
         return !m_args.flag_set("dtls") && !m_args.flag_set("no-tls12") &&
                allow_version(Botan::TLS::Protocol_Version::TLS_V12);
      }

      bool allow_tls13() const override {
         return !m_args.flag_set("dtls") && !m_args.flag_set("no-tls13") &&
                allow_version(Botan::TLS::Protocol_Version::TLS_V13);
      }

      bool allow_dtls12() const override {
         return m_args.flag_set("dtls") && !m_args.flag_set("no-tls12") &&
                allow_version(Botan::TLS::Protocol_Version::DTLS_V12);
      }

      //Botan::TLS::Group_Params default_dh_group() const override;

      //size_t minimum_dh_group_size() const override;

      size_t minimum_ecdsa_group_size() const override { return 224; }

      size_t minimum_ecdh_group_size() const override { return 224; }

      //size_t minimum_rsa_bits() const override;

      //size_t minimum_dsa_group_size() const override;

      //void check_peer_key_acceptable(const Botan::Public_Key& public_key) const override;

      //bool hide_unknown_users() const override;

      //std::chrono::seconds session_ticket_lifetime() const override;

      size_t new_session_tickets_upon_handshake_success() const override {
         return m_args.flag_set("no-ticket") ? 0 : 1;
      }

      std::vector<uint16_t> srtp_profiles() const override {
         if(m_args.option_used("srtp-profiles")) {
            std::string srtp = m_args.get_string_opt("srtp-profiles");

            if(srtp == "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32") {
               return {1, 2};
            } else if(srtp == "SRTP_AES128_CM_SHA1_80") {
               return {1};
            } else {
               shim_exit_with_error("unknown srtp-profiles");
            }
         } else {
            return {};
         }
      }

      bool only_resume_with_exact_version() const override { return false; }

      //bool server_uses_own_ciphersuite_preferences() const override;

      //bool negotiate_encrypt_then_mac() const override;

      bool support_cert_status_message() const override {
         if(m_args.flag_set("server")) {
            if(!m_args.option_used("ocsp-response")) {
               return false;
            }
            if(m_args.flag_set("decline-ocsp-callback")) {
               return false;
            }
         } else if(!m_args.flag_set("enable-ocsp-stapling")) {
            return false;
         }

         return true;
      }

      std::vector<uint16_t> ciphersuite_list(Botan::TLS::Protocol_Version version) const override;

      size_t dtls_default_mtu() const override { return m_args.get_int_opt_or_else("mtu", 1500); }

      //size_t dtls_initial_timeout() const override;

      //size_t dtls_maximum_timeout() const override;

      bool abort_connection_on_undesired_renegotiation() const override {
         if(m_args.flag_set("renegotiate-ignore")) {
            return false;
         } else {
            return true;
         }
      }

      size_t maximum_certificate_chain_size() const override { return m_args.get_int_opt_or_else("max-cert-list", 0); }

      bool tls_13_middlebox_compatibility_mode() const override {
         // These tests expect the client to send an alert in return of a malformed TLS 1.2 server hello.
         // However, our TLS 1.3 implementation produces an alert without downgrading to TLS 1.2 first.
         // In compatibility mode this prepends a CCS, which BoGo does not expect to read.
         const std::vector<std::string> alert_after_server_hello = {
            "DuplicateExtensionClient-TLS-TLS12",
            "WrongMessageType-ServerHello-TLS",
            "SendServerHelloAsHelloRetryRequest",
            "TrailingMessageData-ServerHello-TLS",
            "NoSSL3-Client-Unsolicited",
            "Client-TooLongSessionID",
            "MinimumVersion-Client-TLS13-TLS12-TLS",
            "MinimumVersion-Client2-TLS13-TLS12-TLS",
         };
         if(Botan::value_exists(alert_after_server_hello, m_args.test_name())) {
            return false;
         }

         return true;
      }

   private:
      const Shim_Arguments& m_args;
      size_t m_sessions;
};

std::vector<uint16_t> Shim_Policy::ciphersuite_list(Botan::TLS::Protocol_Version version) const {
   std::vector<uint16_t> ciphersuite_codes;

   const std::string cipher_limit = m_args.get_string_opt_or_else("cipher", "");
   if(cipher_limit ==
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:[TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384|TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256|TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA]:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_128_CBC_SHA:[TLS_RSA_WITH_AES_256_GCM_SHA384|TLS_RSA_WITH_AES_256_CBC_SHA]") {
      std::vector<std::string> suites = {
         "ECDHE_RSA_WITH_AES_128_GCM_SHA256",
         "ECDHE_RSA_WITH_AES_256_GCM_SHA384",
         "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
         "ECDHE_RSA_WITH_AES_256_CBC_SHA",
         "RSA_WITH_AES_256_GCM_SHA384",
         "RSA_WITH_AES_256_CBC_SHA",
      };

      for(const auto& suite_name : suites) {
         const auto suite = Botan::TLS::Ciphersuite::from_name(suite_name);
         if(!suite || !suite->valid()) {
            shim_exit_with_error("Bad ciphersuite name " + suite_name);
         }
         ciphersuite_codes.push_back(suite->ciphersuite_code());
      }
   } else {
      // Hack: go in reverse order to avoid preferring 3DES
      auto ciphersuites = Botan::TLS::Ciphersuite::all_known_ciphersuites();
      for(auto i = ciphersuites.rbegin(); i != ciphersuites.rend(); ++i) {
         const auto suite = *i;

         // Can we use it?
         if(suite.valid() == false || !suite.usable_in_version(version) ||
            !Botan::value_exists(allowed_ciphers(), suite.cipher_algo())) {
            continue;
         }

         ciphersuite_codes.push_back(suite.ciphersuite_code());
      }
   }

   return ciphersuite_codes;
}

class Shim_Credentials final : public Botan::Credentials_Manager {
   public:
      Shim_Credentials(const Shim_Arguments& args) : m_args(args) {
         const auto psk_identity = m_args.get_string_opt_or_else("psk-identity", "");
         const auto psk_str = m_args.get_string_opt_or_else("psk", "");

         if(!psk_identity.empty() || !psk_str.empty()) {
            // If the shim received a -psk param but no -psk-identity param,
            // we have to initialize the identity as "empty string".
            m_psk_identity = psk_identity;
         }

         if(!psk_str.empty()) {
            m_psk = Botan::SymmetricKey(reinterpret_cast<const uint8_t*>(psk_str.data()), psk_str.size());
         }

         if(m_args.option_used("key-file") && m_args.option_used("cert-file")) {
            Botan::DataSource_Stream key_stream(m_args.get_string_opt("key-file"));
            m_key.reset(Botan::PKCS8::load_key(key_stream).release());

            Botan::DataSource_Stream cert_stream(m_args.get_string_opt("cert-file"));

            while(!cert_stream.end_of_data()) {
               try {
                  m_cert_chain.push_back(Botan::X509_Certificate(cert_stream));
               } catch(...) {}
            }
         }

         if(m_args.option_used("trust-cert") && !m_args.get_string_opt("trust-cert").empty()) {
            Botan::DataSource_Stream cert_stream(m_args.get_string_opt("trust-cert"));
            try {
               m_trust_roots.add_certificate(Botan::X509_Certificate(cert_stream));
            } catch(const std::exception& ex) {
               throw Shim_Exception("Failed to load trusted root certificate: " + std::string(ex.what()));
            }
         }
      }

      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string& type,
                                                                             const std::string& context) override {
         if(m_args.flag_set("server") && type != "tls-server") {
            throw Shim_Exception("TLS server implementation asked for unexpected trusted CA type: " + type);
         }
         if(!m_args.flag_set("server") && type != "tls-client") {
            throw Shim_Exception("TLS client implementation asked for unexpected trusted CA type: " + type);
         }

         const auto expected_hostname = m_args.get_string_opt_or_else("host-name", "none");
         if(expected_hostname != "none" && expected_hostname != context) {
            throw Shim_Exception("Unexpected host name in trusted CA request: " + context);
         }

         return {&m_trust_roots};
      }

      std::string psk_identity(const std::string& /*type*/,
                               const std::string& /*context*/,
                               const std::string& /*identity_hint*/) override {
         return m_psk_identity.value_or("");
      }

      std::string psk_identity_hint(const std::string& /*type*/, const std::string& /*context*/) override {
         return m_psk_identity.value_or("");
      }

      Botan::secure_vector<uint8_t> session_ticket_key() override {
         return Botan::hex_decode_locked("ABCDEF0123456789");
      }

      Botan::secure_vector<uint8_t> dtls_cookie_secret() override {
         return Botan::hex_decode_locked("F00FB00FD00F100F700F");
      }

      std::vector<Botan::TLS::ExternalPSK> find_preshared_keys(
         std::string_view host,
         Botan::TLS::Connection_Side whoami,
         const std::vector<std::string>& identities = {},
         const std::optional<std::string>& prf = std::nullopt) override {
         if(!m_psk_identity.has_value()) {
            return Botan::Credentials_Manager::find_preshared_keys(host, whoami, identities, prf);
         }

         auto id_matches =
            identities.empty() || std::find(identities.begin(), identities.end(), m_psk_identity) != identities.end();

         if(!id_matches) {
            throw Shim_Exception("Unexpected PSK identity");
         }

         if(!m_psk.has_value()) {
            throw Shim_Exception("PSK identified but not set");
         }

         std::vector<Botan::TLS::ExternalPSK> psks;

         // Currently, BoGo tests PSK with TLS 1.2 only. In TLS 1.2 the PRF does not
         // need to be specified for PSKs.
         //
         // TODO: Once BoGo has tests for TLS 1.3 with externally provided PSKs, this
         //       will need to be handled somehow.
         const std::string psk_prf = "SHA-256";
         psks.emplace_back(m_psk_identity.value(), psk_prf, m_psk->bits_of());
         return psks;
      }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::vector<Botan::AlgorithmIdentifier>& /*cert_signature_schemes*/,
         const std::string& /*type*/,
         const std::string& /*context*/) override {
         if(m_args.flag_set("fail-cert-callback")) {
            throw std::runtime_error("Simulating cert verify callback failure");
         }

         if(m_key != nullptr && !m_cert_chain.empty()) {
            for(const std::string& t : cert_key_types) {
               if(t == m_key->algo_name()) {
                  return m_cert_chain;
               }
            }
         }

         return {};
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate& /*cert*/,
                                                          const std::string& /*type*/,
                                                          const std::string& /*context*/) override {
         // assumes cert == m_cert
         return m_key;
      }

   private:
      const Shim_Arguments& m_args;
      std::optional<Botan::SymmetricKey> m_psk;
      std::optional<std::string> m_psk_identity;
      std::shared_ptr<Botan::Private_Key> m_key;
      std::vector<Botan::X509_Certificate> m_cert_chain;
      Botan::Certificate_Store_In_Memory m_trust_roots;
};

class Shim_Callbacks final : public Botan::TLS::Callbacks {
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
            m_got_close(false),
            m_hello_retry_request(false),
            m_clock_skew(0) {}

      size_t sessions_established() const { return m_sessions_established; }

      void set_channel(Botan::TLS::Channel* channel) { m_channel = channel; }

      void set_clock_skew(std::chrono::seconds clock_skew) { m_clock_skew = clock_skew; }

      bool saw_close_notify() const { return m_got_close; }

      void tls_emit_data(std::span<const uint8_t> data) override {
         shim_log("sending record of len " + std::to_string(data.size()));

         if(m_args.option_used("write-settings")) {
            // TODO: the transcript option should probably be used differently
            std::cout << ">>>" << std::endl << Botan::hex_encode(data) << std::endl << ">>>" << std::endl;
         }

         if(m_is_datagram) {
            std::vector<uint8_t> packet(data.size() + 5);

            packet[0] = 'P';
            for(size_t i = 0; i != 4; ++i) {
               packet[i + 1] = static_cast<uint8_t>((data.size() >> (24 - 8 * i)) & 0xFF);
            }
            std::memcpy(packet.data() + 5, data.data(), data.size());

            m_socket.write(packet.data(), packet.size());
         } else {
            m_socket.write(data.data(), data.size());
         }
      }

      std::vector<uint8_t> tls_provide_cert_status(const std::vector<Botan::X509_Certificate>&,
                                                   const Botan::TLS::Certificate_Status_Request&) override {
         if(m_args.flag_set("use-ocsp-callback") && m_args.flag_set("fail-ocsp-callback")) {
            throw std::runtime_error("Simulating failure from OCSP response callback");
         }

         if(m_args.flag_set("decline-ocsp-callback")) {
            return {};
         }

         if(m_args.option_used("ocsp-response")) {
            return m_args.get_b64_opt("ocsp-response");
         }

         return {};
      }

      void tls_record_received(uint64_t /*seq_no*/, std::span<const uint8_t> data) override {
         if(data.empty()) {
            m_empty_records += 1;
            if(m_empty_records > 32) {
               shim_exit_with_error(":TOO_MANY_EMPTY_FRAGMENTS:");
            }
         } else {
            m_empty_records = 0;
         }

         shim_log("Reflecting application_data len " + std::to_string(data.size()));

         std::vector<uint8_t> buf(data.begin(), data.end());
         for(auto& b : buf) {
            b ^= 0xFF;
         }

         m_channel->send(buf);
      }

      bool tls_verify_message(const Botan::Public_Key& key,
                              std::string_view padding,
                              Botan::Signature_Format format,
                              const std::vector<uint8_t>& msg,
                              const std::vector<uint8_t>& sig) override {
         if(m_args.option_used("expect-peer-signature-algorithm")) {
            const Botan::TLS::Signature_Scheme scheme(
               static_cast<uint16_t>(m_args.get_int_opt("expect-peer-signature-algorithm")));

            if(!scheme.is_available()) {
               shim_exit_with_error(std::string("Unsupported signature scheme provided by BoGo: ") +
                                    scheme.to_string());
            }

            const std::string exp_padding = scheme.padding_string();
            if(padding != exp_padding) {
               shim_exit_with_error(Botan::fmt("Unexpected signature scheme got {} expected {}", padding, exp_padding));
            }
         }

         return Botan::TLS::Callbacks::tls_verify_message(key, padding, format, msg, sig);
      }

      void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& cert_chain,
                                 const std::vector<std::optional<Botan::OCSP::Response>>& ocsp_responses,
                                 const std::vector<Botan::Certificate_Store*>& trusted_roots,
                                 Botan::Usage_Type usage,
                                 std::string_view /* hostname */,
                                 const Botan::TLS::Policy& policy) override {
         if(m_args.flag_set("enable-ocsp-stapling") && m_args.flag_set("use-ocsp-callback") &&
            m_args.flag_set("fail-ocsp-callback")) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::BadCertificateStatusResponse,
                                            "Simulated OCSP callback failure");
         }

         if(m_args.flag_set("verify-fail")) {
            auto alert = Botan::TLS::Alert::HandshakeFailure;
            if(m_args.flag_set("use-custom-verify-callback")) {
               alert = Botan::TLS::Alert::CertificateUnknown;
            }

            throw Botan::TLS::TLS_Exception(alert, "Test requires rejecting cert");
         }

         if(!cert_chain.empty() && cert_chain.front().is_self_signed()) {
            for(const auto roots : trusted_roots) {
               if(roots->certificate_known(cert_chain.front())) {
                  shim_log("Trusting self-signed certificate");
                  return;
               }
            }
         }

         shim_log("Establishing trust from a certificate chain");

         Botan::TLS::Callbacks::tls_verify_cert_chain(
            cert_chain, ocsp_responses, trusted_roots, usage, "" /* hostname */, policy);
      }

      std::optional<Botan::OCSP::Response> tls_parse_ocsp_response(const std::vector<uint8_t>& raw_response) override {
         if(m_args.option_used("expect-ocsp-response") && m_args.get_b64_opt("expect-ocsp-response") != raw_response) {
            shim_exit_with_error("unexpected OCSP response");
         }

         // Bogo uses invalid dummy OCSP responses. Don't even bother trying to
         // decode them.
         return std::nullopt;
      }

      void tls_modify_extensions(Botan::TLS::Extensions& exts,
                                 Botan::TLS::Connection_Side /* side */,
                                 Botan::TLS::Handshake_Type msg_type) override {
         if(msg_type == Botan::TLS::Handshake_Type::CertificateRequest) {
            if(m_args.option_used("use-client-ca-list")) {
               // The CertificateAuthorities extension is filled with the CA
               // list provided by the credentials manager. The same list is
               // used to later verify the client certificate chain.
               //
               // Hence, we have to use this low-level callback to fulfill the
               // BoGo requirement of sending specific configurations of the CA
               // list in the CertificateRequest message.
               if(m_args.get_string_opt("use-client-ca-list") == "<EMPTY>" ||
                  m_args.get_string_opt("use-client-ca-list") == "<NULL>") {
                  exts.remove_extension(Botan::TLS::Extension_Code::CertificateAuthorities);
               } else {
                  // TODO: -use-client-ca-list might also provide the encoded
                  //       list of DNs. We could render this here, if needed.
               }
            }
         }
      }

      std::string tls_server_choose_app_protocol(const std::vector<std::string>& client_protos) override {
         if(client_protos.empty()) {
            return "";  // shouldn't happen?
         }

         if(m_args.flag_set("reject-alpn")) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::NoApplicationProtocol,
                                            "Rejecting ALPN request with alert");
         }

         if(m_args.flag_set("decline-alpn")) {
            return "";
         }

         if(m_args.option_used("expect-advertised-alpn")) {
            const std::vector<std::string> expected = m_args.get_alpn_string_vec_opt("expect-advertised-alpn");

            if(client_protos != expected) {
               shim_exit_with_error("Bad ALPN from client");
            }
         }

         if(m_args.option_used("select-alpn")) {
            return m_args.get_string_opt("select-alpn");
         }

         return client_protos[0];  // if not configured just pick something
      }

      void tls_alert(Botan::TLS::Alert alert) override {
         if(alert.is_fatal()) {
            shim_log("Got a fatal alert " + alert.type_string());
         } else {
            shim_log("Got a warning alert " + alert.type_string());
         }

         if(alert.type() == Botan::TLS::Alert::RecordOverflow) {
            shim_exit_with_error(":TLSV1_ALERT_RECORD_OVERFLOW:");
         }

         if(alert.type() == Botan::TLS::Alert::DecompressionFailure) {
            shim_exit_with_error(":SSLV3_ALERT_DECOMPRESSION_FAILURE:");
         }

         if(!alert.is_fatal()) {
            m_warning_alerts++;
            if(m_warning_alerts > 5) {
               shim_exit_with_error(":TOO_MANY_WARNING_ALERTS:");
            }
         }

         if(alert.type() == Botan::TLS::Alert::CloseNotify) {
            if(m_got_close == false && !m_args.flag_set("shim-shuts-down")) {
               shim_log("Sending return close notify");
               m_channel->send_alert(alert);
            }
            m_got_close = true;
         } else if(alert.is_fatal()) {
            shim_exit_with_error("Unexpected fatal alert " + alert.type_string());
         }
      }

      void tls_session_established(const Botan::TLS::Session_Summary& session) override {
         shim_log("Session established: " + Botan::hex_encode(session.session_id().get()) + " version " +
                  session.version().to_string() + " cipher " + session.ciphersuite().to_string() + " EMS " +
                  std::to_string(session.supports_extended_master_secret()));
         // probably need tests here?

         m_policy.incr_session_established();
         m_sessions_established++;

         if(m_args.flag_set("expect-no-session-id")) {
            // BoGo expects that ticket issuance implies no stateful session...
            if(!m_args.flag_set("server") && !session.session_id().empty()) {
               shim_exit_with_error("Unexpectedly got a session ID");
            }
         } else if(m_args.flag_set("expect-session-id") && session.session_id().empty()) {
            shim_exit_with_error("Unexpectedly got no session ID");
         }

         if(m_args.option_used("expect-version")) {
            if(session.version().version_code() != m_args.get_int_opt("expect-version")) {
               shim_exit_with_error("Unexpected version");
            }
         }

         if(m_args.flag_set("expect-secure-renegotiation")) {
            if(m_channel->secure_renegotiation_supported() == false) {
               shim_exit_with_error("Expected secure renegotiation");
            }
         } else if(m_args.flag_set("expect-no-secure-renegotiation")) {
            if(m_channel->secure_renegotiation_supported() == true) {
               shim_exit_with_error("Expected no secure renegotation");
            }
         }

         if(m_args.flag_set("expect-extended-master-secret")) {
            if(session.supports_extended_master_secret() == false) {
               shim_exit_with_error("Expected extended maseter secret");
            }
         }
      }

      void tls_session_activated() override {
         if(m_args.flag_set("send-alert")) {
            m_channel->send_fatal_alert(Botan::TLS::Alert::DecompressionFailure);
            return;
         }

         if(size_t length = m_args.get_int_opt_or_else("export-keying-material", 0)) {
            const std::string label = m_args.get_string_opt("export-label");
            const std::string context = m_args.get_string_opt("export-context");
            const auto exported = m_channel->key_material_export(label, context, length);
            shim_log("Sending " + std::to_string(length) + " bytes of key material");
            m_channel->send(exported.bits_of());
         }

         const std::string alpn = m_channel->application_protocol();

         if(m_args.option_used("expect-alpn")) {
            if(alpn != m_args.get_string_opt("expect-alpn")) {
               shim_exit_with_error("Got unexpected ALPN");
            }
         }

         if(alpn == "baz" && !m_args.flag_set("allow-unknown-alpn-protos")) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::IllegalParameter, "Unexpected ALPN protocol");
         }

         if(m_args.flag_set("shim-shuts-down")) {
            shim_log("Shim shutting down");
            m_channel->close();
         }

         if(m_args.flag_set("write-different-record-sizes")) {
            static const size_t record_sizes[] = {0, 1, 255, 256, 257, 16383, 16384, 16385, 32767, 32768, 32769};

            std::vector<uint8_t> buf(32769, 0x42);

            for(size_t sz : record_sizes) {
               m_channel->send(buf.data(), sz);
            }

            m_channel->close();
         }

         if(m_args.flag_set("expect-hrr") && !m_hello_retry_request) {
            throw Shim_Exception("Expected Hello Retry Request but didn't see one");
         }

         if(m_args.flag_set("expect-no-hrr") && m_hello_retry_request) {
            throw Shim_Exception("Hello Retry Request seen but didn't expect one");
         }

         if(m_args.flag_set("key-update")) {
            shim_log("Updating traffic keys without asking for reciprocation");
            m_channel->update_traffic_keys(false /* don't request reciprocal update */);
         }
      }

      std::chrono::system_clock::time_point tls_current_timestamp() override {
         // Some tests require precise timings. Hence, the TLS 'now' timestamp
         // is frozen on first access and rounded to the last full second. E.g.
         // storage of sessions does store the timestamp with second-resolution.
         using sec = std::chrono::seconds;
         static auto g_now = std::chrono::floor<sec>(std::chrono::system_clock::now());
         return g_now + m_clock_skew;
      }

      void tls_inspect_handshake_msg(const Botan::TLS::Handshake_Message& msg) override {
         if(msg.type() == Botan::TLS::Handshake_Type::HelloRetryRequest) {
            m_hello_retry_request = true;
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
      bool m_hello_retry_request;
      std::chrono::seconds m_clock_skew;
};

}  // namespace

int main(int /*argc*/, char* argv[]) {
   try {
      std::unique_ptr<Shim_Arguments> args = parse_options(argv);

      if(args->flag_set("is-handshaker-supported")) {
         return shim_output("No\n");
      }

      const uint16_t port = static_cast<uint16_t>(args->get_int_opt("port"));
      const size_t resume_count = args->get_int_opt_or_else("resume-count", 0);
      const bool is_server = args->flag_set("server");
      const bool is_datagram = args->flag_set("dtls");
      const size_t buf_size = args->get_int_opt_or_else("read-size", 18 * 1024);

      auto rng = std::make_shared<Botan::ChaCha_RNG>(Botan::secure_vector<uint8_t>(64));
      auto creds = std::make_shared<Shim_Credentials>(*args);
      auto session_manager = [&]() -> std::shared_ptr<Botan::TLS::Session_Manager> {
         if(args->flag_set("no-ticket") || args->flag_set("on-resume-no-ticket")) {
            // The in-memory session manager stores sessions in volatile memory and
            // hands out Session_IDs (i.e. does not utilize session tickets)
            return std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng, 1024);
         } else {
            // The hybrid session manager prefers stateless tickets (when used in
            // servers) but can also fall back to stateful management when tickets
            // are not an option.
            return std::make_shared<Botan::TLS::Session_Manager_Hybrid>(
               std::make_unique<Botan::TLS::Session_Manager_In_Memory>(rng, 1024), creds, rng);
         }
      }();

      if(args->flag_set("wait-for-debugger")) {
         sleep(20);
      }

      for(size_t i = 0; i != resume_count + 1; ++i) {
         auto execute_test = [&](const std::string& hostname) {
            Shim_Socket socket(hostname, port, args->flag_set("ipv6"));

            shim_log("Connection " + std::to_string(i + 1) + "/" + std::to_string(resume_count + 1));

            // The ShimID must be written on the socket as a 64-bit little-endian integer
            // *before* any test data is transferred
            // See: https://github.com/google/boringssl/commit/50ee09552cde1c2019bef24520848d041920cfd4
            shim_log("Sending ShimID: " + std::to_string(args->get_int_opt("shim-id")));
            std::array<uint8_t, 8> shim_id;
            Botan::store_le(static_cast<uint64_t>(args->get_int_opt("shim-id")), shim_id.data());
            socket.write(shim_id.data(), shim_id.size());

            auto policy = std::make_shared<Shim_Policy>(*args);
            auto callbacks = std::make_shared<Shim_Callbacks>(*args, socket, *policy);

            if(args->option_used("resumption-delay") && i > 0) {
               shim_log("skewing the clock by " + std::to_string(args->get_int_opt("resumption-delay")) + " seconds");
               callbacks->set_clock_skew(std::chrono::seconds(args->get_int_opt("resumption-delay")));
            }

            std::unique_ptr<Botan::TLS::Channel> chan;

            if(is_server) {
               chan = std::make_unique<Botan::TLS::Server>(callbacks, session_manager, creds, policy, rng, is_datagram);
            } else {
               Botan::TLS::Protocol_Version offer_version = policy->latest_supported_version(is_datagram);
               shim_log("Offering " + offer_version.to_string());

               std::string host_name = args->get_string_opt_or_else("host-name", hostname);
               if(args->test_name().starts_with("UnsolicitedServerNameAck")) {
                  host_name = "";  // avoid sending SNI for this test
               }

               Botan::TLS::Server_Information server_info(host_name, port);
               const std::vector<std::string> next_protocols = args->get_alpn_string_vec_opt("advertise-alpn");
               chan = std::make_unique<Botan::TLS::Client>(
                  callbacks, session_manager, creds, policy, rng, server_info, offer_version, next_protocols);
            }

            callbacks->set_channel(chan.get());

            std::vector<uint8_t> buf(buf_size);

            for(;;) {
               if(is_datagram) {
                  uint8_t opcode;
                  size_t got = socket.read(&opcode, 1);
                  if(got == 0) {
                     shim_log("EOF on socket");
                     break;
                  }

                  if(opcode == 'P') {
                     uint8_t len_bytes[4];
                     socket.read_exactly(len_bytes, sizeof(len_bytes));

                     size_t packet_len = Botan::load_be<uint32_t>(len_bytes, 0);

                     if(buf.size() < packet_len) {
                        buf.resize(packet_len);
                     }
                     socket.read_exactly(buf.data(), packet_len);

                     chan->received_data(buf.data(), packet_len);
                  } else if(opcode == 'T') {
                     uint8_t timeout_ack = 't';

                     uint8_t timeout_bytes[8];
                     socket.read_exactly(timeout_bytes, sizeof(timeout_bytes));

                     const uint64_t nsec = Botan::load_be<uint64_t>(timeout_bytes, 0);

                     shim_log("Timeout nsec " + std::to_string(nsec));

                     // FIXME handle this!

                     socket.write(&timeout_ack, 1);  // ack it anyway
                  } else {
                     shim_exit_with_error("Unknown opcode " + std::to_string(opcode));
                  }
               } else {
                  size_t got = socket.read(buf.data(), buf.size());
                  if(got == 0) {
                     shim_log("EOF on socket");
                     break;
                  }

                  shim_log("Got packet of " + std::to_string(got));

                  if(args->option_used("write-settings")) {
                     // TODO: the transcript option should probably be used differently
                     std::cout << "<<<" << std::endl
                               << Botan::hex_encode(buf.data(), got) << std::endl
                               << "<<<" << std::endl;
                  }

                  if(args->flag_set("use-exporter-between-reads") && chan->is_active()) {
                     chan->key_material_export("some label", "some context", 42);
                  }
                  const size_t needed = chan->received_data(buf.data(), got);

                  if(needed) {
                     shim_log("Short read still need " + std::to_string(needed));
                  }
               }
            }

            if(args->flag_set("check-close-notify")) {
               if(!callbacks->saw_close_notify()) {
                  throw Shim_Exception("Unexpected SSL_shutdown result: -1 != 1");
               }
            }

            if(args->option_used("expect-total-renegotiations")) {
               const size_t exp = args->get_int_opt("expect-total-renegotiations");

               if(exp != callbacks->sessions_established() - 1) {
                  throw Shim_Exception("Unexpected number of renegotiations: saw " +
                                       std::to_string(callbacks->sessions_established() - 1) + " exp " +
                                       std::to_string(exp));
               }
            }
            shim_log("End of resume loop");
         };
         try {
            execute_test("localhost");
         } catch(const Shim_Exception& e) {
            if(std::string(e.what()) == "Failed to connect to host") {
               execute_test("::1");
            } else {
               // NOLINTNEXTLINE(cert-err60-cpp)
               throw e;
            }
         }
      }
   } catch(Shim_Exception& e) {
      shim_exit_with_error(e.what(), e.rc());
   } catch(std::exception& e) {
      shim_exit_with_error(map_to_bogo_error(e.what()));
   } catch(...) {
      shim_exit_with_error("Unknown exception", 3);
   }
   return 0;
}
