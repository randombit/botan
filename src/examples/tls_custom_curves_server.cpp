#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_policy.h>
#include <botan/tls_server.h>
#include <botan/tls_session_manager_memory.h>
#include <botan/ec_group.h>
#include <botan/oids.h>

#include <memory>

/**
 * @brief Callbacks invoked by TLS::Channel.
 *
 * Botan::TLS::Callbacks is an abstract class.
 * For improved readability, only the functions that are mandatory
 * to implement are listed here. See src/lib/tls/tls_callbacks.h.
 */
class Callbacks : public Botan::TLS::Callbacks {
public:
  void tls_emit_data(const uint8_t data[], size_t size) override {
    // send data to tls client, e.g., using BSD sockets or boost asio
  }

  void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override {
    // process full TLS record received by tls client, e.g.,
    // by passing it to the application
  }

  void tls_alert(Botan::TLS::Alert alert) override {
    // handle a tls alert received from the tls server
  }

  bool tls_session_established(const Botan::TLS::Session_with_Handle &session) override {
    // the session with the tls client was established
    // return false to prevent the session from being cached, true to
    // cache the session in the configured session manager
    return false;
  }

  std::string tls_decode_group_param(Botan::TLS::Group_Params group_param) override {
    // handle TLS group identifier decoding and return name as string
    // return empty string to indicate decoding failure

    switch (static_cast<uint16_t>(group_param)) {
    case 0xFE00:
      return "testcurve1102";
    default:
      // decode non-custom groups
      return Botan::TLS::Callbacks::tls_decode_group_param(group_param);
    }
  }
};

/**
 * @brief Credentials storage for the tls server.
 *
 * It returns a certificate and the associated private key to
 * authenticate the tls server to the client.
 * TLS client authentication is not requested.
 * See src/lib/tls/credentials_manager.h.
 */
class Server_Credentials : public Botan::Credentials_Manager {
public:
  Server_Credentials() {
    Botan::DataSource_Stream in("botan.randombit.net.key");
    m_key.reset(Botan::PKCS8::load_key(in).release());
  }

  std::vector<Botan::Certificate_Store *>
  trusted_certificate_authorities(const std::string &type, const std::string &context) override {
    // if client authentication is required, this function
    // shall return a list of certificates of CAs we trust
    // for tls client certificates, otherwise return an empty list
    return {};
  }

  std::vector<Botan::X509_Certificate>
  cert_chain(const std::vector<std::string> &cert_key_types,
             const std::vector<Botan::AlgorithmIdentifier> &cert_signature_schemes,
             const std::string &type, const std::string &context) override {
    Botan::X509_Certificate server_cert("botan.randombit.net.crt");

    // make sure that the server asked for your certificate's key type
    // before handing it out to the implementation
    const auto key_type = server_cert.subject_public_key_algo().oid().to_formatted_string();
    const auto itr = std::find(cert_key_types.begin(), cert_key_types.end(), key_type);
    if (itr == cert_key_types.end()) {
      return {};
    }

    // return the certificate chain being sent to the tls server
    // e.g., the certificate file "botan.randombit.net.crt"
    return {server_cert};
  }

  std::shared_ptr<Botan::Private_Key>
  private_key_for(const Botan::X509_Certificate &cert, const std::string &type,
                  const std::string &context) override {
    // return the private key associated with the leaf certificate,
    // in this case the one associated with "botan.randombit.net.crt"
    return m_key;
  }

private:
  std::shared_ptr<Botan::Private_Key> m_key;
};

class Server_Policy : public Botan::TLS::Strict_Policy {
public:
  std::vector<Botan::TLS::Group_Params> key_exchange_groups() const override {
    // modified strict policy to allow our custom curves
    return {static_cast<Botan::TLS::Group_Params>(0xFE00)};
  }
};

int main() {

  // prepare rng
  Botan::AutoSeeded_RNG rng;

  // prepare custom curve

  // prepare curve parameters
  const Botan::BigInt p(
      "0x92309a3e88b94312f36891a2055725bb35ab51af96b3a651d39321b7bbb8c51575a76768c9b6b323");
  const Botan::BigInt a(
      "0x4f30b8e311f6b2dce62078d70b35dacb96aa84b758ab5a8dff0c9f7a2a1ff466c19988aa0acdde69");
  const Botan::BigInt b(
      "0x9045A513CFFF9AE1F1CC84039D852D240344A1D5C9DB203C844089F855C387823EB6FCDDF49C909C");

  const Botan::BigInt x(
      "0x9120f3779a31296cefcb5a5a08831f1a6d438ad5a3f2ce60585ac19c74eebdc65cadb96bb92622c7");
  const Botan::BigInt y(
      "0x836db8251c152dfee071b72c6b06c5387d82f1b5c30c5a5b65ee9429aa2687e8426d5d61276a4ede");
  const Botan::BigInt order(
      "0x248c268fa22e50c4bcda24688155c96ecd6ad46be5c82d7a6be6e7068cb5d1ca72b2e07e8b90d853");

  const Botan::BigInt cofactor(4);

  const Botan::OID oid("1.2.3.1");

  // create EC_Group object to register the curve
  Botan::EC_Group testcurve1102(p, a, b, x, y, order, cofactor, oid);

  if (!testcurve1102.verify_group(rng)) {
    // Warning: if verify_group returns false the curve parameters are insecure
  }

  // register name to specified oid
  Botan::OIDS::add_oid(oid, "testcurve1102");

  // prepare all the parameters
  Callbacks callbacks;
  Botan::TLS::Session_Manager_In_Memory session_mgr(rng);
  Server_Credentials creds;
  Server_Policy policy;

  // accept tls connection from client
  Botan::TLS::Server server(callbacks, session_mgr, creds, policy, rng);

  // read data received from the tls client, e.g., using BSD sockets or boost asio
  // and pass it to server.received_data().
  // ...

  // send data to the tls client using server.send()
  // ...

  return 0;
}
