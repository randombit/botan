/*
* Credentials Manager
* (C) 2011,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/credentials_manager.h>

#include <botan/pkix_types.h>
#include <botan/internal/fmt.h>

namespace Botan {

std::string Credentials_Manager::psk_identity_hint(const std::string& /*unused*/, const std::string& /*unused*/) {
   return "";
}

std::string Credentials_Manager::psk_identity(const std::string& /*unused*/,
                                              const std::string& /*unused*/,
                                              const std::string& /*unused*/) {
   return "";
}

SymmetricKey Credentials_Manager::psk(const std::string& type,
                                      const std::string& context,
                                      const std::string& identity) {
   auto side = [&] {
      if(type == "tls-client") {
         return TLS::Connection_Side::Client;
      } else if(type == "tls-server") {
         return TLS::Connection_Side::Server;
      } else {
         throw Internal_Error(fmt("No PSK set for type {}", type));
      }
   }();

   // New applications should use the appropriate credentials methods. This is a
   // retrofit of the behaviour before Botan 3.2.0 and will be removed in a
   // future major release.
   //
   // TODO: deprecate `psk("...", "session-ticket" | "dtls-cookie-secret")`
   if(side == TLS::Connection_Side::Server && context == "session-ticket") {
      if(auto key = session_ticket_key(); !key.empty()) {
         return SymmetricKey(std::move(key));
      }
   } else if(side == TLS::Connection_Side::Server && context == "dtls-cookie-secret") {
      if(auto key = dtls_cookie_secret(); !key.empty()) {
         return SymmetricKey(std::move(key));
      }
   } else /* context is a host name */ {
      // Assuming that find_preshared_keys returns _exactly_ one or no keys when
      // searching for a single specific identity.
      if(auto psks = find_preshared_keys(context, side, {identity}); psks.size() == 1) {
         return SymmetricKey(psks.front().extract_master_secret());
      }
   }

   throw Internal_Error(fmt("No PSK set for identity {}", identity));
}

std::vector<TLS::ExternalPSK> Credentials_Manager::find_preshared_keys(std::string_view /* host */,
                                                                       TLS::Connection_Side /* whoami */,
                                                                       const std::vector<std::string>& /* identities */,
                                                                       const std::optional<std::string>& /* prf */) {
   return {};
}

std::optional<TLS::ExternalPSK> Credentials_Manager::choose_preshared_key(std::string_view host,
                                                                          TLS::Connection_Side whoami,
                                                                          const std::vector<std::string>& identities,
                                                                          const std::optional<std::string>& prf) {
   auto psks = find_preshared_keys(host, whoami, identities, prf);
   if(psks.empty()) {
      return std::nullopt;
   } else {
      return std::move(psks.front());
   }
}

std::vector<X509_Certificate> Credentials_Manager::find_cert_chain(
   const std::vector<std::string>& key_types,
   const std::vector<AlgorithmIdentifier>& cert_signature_schemes,
   const std::vector<X509_DN>& /*unused*/,
   const std::string& type,
   const std::string& context) {
   return cert_chain(key_types, cert_signature_schemes, type, context);
}

std::shared_ptr<Public_Key> Credentials_Manager::find_raw_public_key(const std::vector<std::string>& /* key_types */,
                                                                     const std::string& /* type */,
                                                                     const std::string& /* context */) {
   return nullptr;
}

std::vector<X509_Certificate> Credentials_Manager::cert_chain(const std::vector<std::string>& /*unused*/,
                                                              const std::vector<AlgorithmIdentifier>& /*unused*/,
                                                              const std::string& /*unused*/,
                                                              const std::string& /*unused*/) {
   return std::vector<X509_Certificate>();
}

std::vector<X509_Certificate> Credentials_Manager::cert_chain_single_type(
   const std::string& cert_key_type,
   const std::vector<AlgorithmIdentifier>& cert_signature_schemes,
   const std::string& type,
   const std::string& context) {
   return find_cert_chain({cert_key_type}, cert_signature_schemes, std::vector<X509_DN>(), type, context);
}

std::shared_ptr<Private_Key> Credentials_Manager::private_key_for(const X509_Certificate& /*unused*/,
                                                                  const std::string& /*unused*/,
                                                                  const std::string& /*unused*/) {
   return nullptr;
}

std::shared_ptr<Private_Key> Credentials_Manager::private_key_for(const Public_Key& /* raw_public_key */,
                                                                  const std::string& /* type */,
                                                                  const std::string& /* context */) {
   return nullptr;
}

secure_vector<uint8_t> Credentials_Manager::session_ticket_key() {
   return {};
}

secure_vector<uint8_t> Credentials_Manager::dtls_cookie_secret() {
   return {};
}

std::vector<Certificate_Store*> Credentials_Manager::trusted_certificate_authorities(const std::string& /*unused*/,
                                                                                     const std::string& /*unused*/) {
   return std::vector<Certificate_Store*>();
}

}  // namespace Botan
