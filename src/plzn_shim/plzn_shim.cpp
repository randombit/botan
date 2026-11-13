/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

/*
* This is a shim for testing Botan against plzn (https://github.com/randombit/plzn)
*
* It wraps Botan's TLS/DTLS client and server as a unit-under-test driven by a
* single JSON config file written by the plzn runner. The shim dials the runner,
* runs a normal handshake with the configured policy/credentials, answers
* application-data requests (or applies the configured app-data behaviour),
* self-checks the configured expectations, and exits non-zero on mismatch.
*
* Build it with ./configure.py --build-targets=...,plzn_shim --with-plzn-dir=DIR
* where DIR is a plzn checkout; the shim helper library in DIR/shims/common is
* compiled along with this file. Run the suite with src/scripts/run_plzn_tests.py;
* local xfails and skips go in src/plzn_shim/expectations.json
*/

#include "plzn_shim.h"

#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/certstor_system.h>
#include <botan/chacha_rng.h>
#include <botan/credentials_manager.h>
#include <botan/data_src.h>
#include <botan/ec_group.h>
#include <botan/ecc_key.h>
#include <botan/exceptn.h>
#include <botan/hex.h>
#include <botan/pkcs8.h>
#include <botan/tls_alert.h>
#include <botan/tls_algos.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_ciphersuite.h>
#include <botan/tls_client.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_external_psk.h>
#include <botan/tls_policy.h>
#include <botan/tls_server.h>
#include <botan/tls_session_manager_hybrid.h>
#include <botan/tls_session_manager_memory.h>
#include <botan/tls_session_manager_noop.h>
#include <botan/tls_session_manager_stateless.h>
#include <botan/tls_signature_scheme.h>
#include <botan/x509cert.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace plzn;

namespace {

std::string g_fail_reason;

// Records the first fatal condition and lets the flow unwind. The shim then
// reports pass/fail once at the end.
void note_failure(const std::string& reason) {
   if(g_fail_reason.empty()) {
      g_fail_reason = reason;
   }
}

// -------------------------------------------------------------------------
// Policy
// -------------------------------------------------------------------------

class Shim_Policy final : public Botan::TLS::Policy {
   public:
      explicit Shim_Policy(const ShimConfig& cfg) : m_cfg(cfg) {}

      std::vector<std::string> allowed_ciphers() const override {
         // Broad set; concrete negotiation is pinned by ciphersuite_list when
         // the config gives explicit cipher-suite IDs.
         return {
            "ChaCha20Poly1305",
            "AES-256/GCM",
            "AES-128/GCM",
            "AES-256/CCM",
            "AES-128/CCM",
            "AES-256",
            "AES-128",
         };
      }

      std::vector<uint16_t> ciphersuite_list(Botan::TLS::Protocol_Version version) const override {
         if(m_cfg.cipher_suites.empty()) {
            // Expose everything the library implements (project principle: the
            // shim presents the library's capability, not its default posture).
            // The policy's own preference order comes first, so a peer offering
            // the usual suites still gets the usual choice; every other suite
            // the build supports for this version (ARIA, Camellia, CCM, 3DES,
            // NULL, PSK...) is appended as lower preference.
            auto out = Botan::TLS::Policy::ciphersuite_list(version);
            for(const auto& suite : Botan::TLS::Ciphersuite::all_known_ciphersuites()) {
               if(suite.valid() && suite.usable_in_version(version) &&
                  std::find(out.begin(), out.end(), suite.ciphersuite_code()) == out.end()) {
                  out.push_back(suite.ciphersuite_code());
               }
            }
            return out;
         }
         // `uut { cipher_suites }`: exactly the configured suites the library
         // can run in this version, in the configured order. (Intersecting
         // with the policy default, as before, silently dropped suites outside
         // the default posture.)
         std::vector<uint16_t> out;
         for(const uint16_t want : m_cfg.cipher_suites) {
            const auto suite = Botan::TLS::Ciphersuite::by_id(want);
            if(suite.has_value() && suite->valid() && suite->usable_in_version(version)) {
               out.push_back(want);
            }
         }
         return out;
      }

      std::vector<Botan::TLS::Group_Params> key_exchange_groups() const override {
         if(m_cfg.curves.empty()) {
            // Botan's default policy stopped offering finite-field DH (commit
            // 52007ebf58, "Disable finite field DH key exchange in the default
            // TLS policy"), but the RFC 7919 groups remain fully supported. The
            // shim exposes the library's capability, not its default posture, so
            // append them after the default curves; a test that wants the exact
            // default posture pins `uut { curves }` explicitly.
            // The same goes for the pure ML-KEM groups (draft-connolly): the
            // default policy offers only the ECDH hybrids, the library has all
            // three parameter sets.
            auto groups = Botan::TLS::Policy::key_exchange_groups();
            for(const auto extra : {Botan::TLS::Group_Params_Code::FFDHE_2048,
                                    Botan::TLS::Group_Params_Code::FFDHE_3072,
                                    Botan::TLS::Group_Params_Code::FFDHE_4096,
                                    Botan::TLS::Group_Params_Code::FFDHE_6144,
                                    Botan::TLS::Group_Params_Code::FFDHE_8192,
                                    Botan::TLS::Group_Params_Code::ML_KEM_512,
                                    Botan::TLS::Group_Params_Code::ML_KEM_768,
                                    Botan::TLS::Group_Params_Code::ML_KEM_1024}) {
               const Botan::TLS::Group_Params g(extra);
               if(g.is_available() && std::find(groups.begin(), groups.end(), g) == groups.end()) {
                  groups.push_back(g);
               }
            }
            return groups;
         }
         std::vector<Botan::TLS::Group_Params> groups;
         for(const uint16_t id : m_cfg.curves) {
            const auto g = static_cast<Botan::TLS::Group_Params>(id);
            if(g.to_string().has_value() && g.is_available()) {
               groups.push_back(g);
            }
         }
         return groups;
      }

      std::vector<Botan::TLS::Signature_Scheme> allowed_signature_schemes() const override {
         if(m_cfg.signing_prefs.empty()) {
            return Botan::TLS::Policy::allowed_signature_schemes();
         }
         std::vector<Botan::TLS::Signature_Scheme> schemes;
         for(const uint16_t id : m_cfg.signing_prefs) {
            schemes.emplace_back(id);
         }
         return schemes;
      }

      std::vector<Botan::TLS::Signature_Scheme> acceptable_signature_schemes() const override {
         if(m_cfg.verify_prefs.empty()) {
            return Botan::TLS::Policy::acceptable_signature_schemes();
         }
         std::vector<Botan::TLS::Signature_Scheme> schemes;
         for(const uint16_t id : m_cfg.verify_prefs) {
            schemes.emplace_back(id);
         }
         return schemes;
      }

      std::vector<uint16_t> srtp_profiles() const override { return m_cfg.srtp_profiles; }

      // No EdDSA: Botan's TLS stack leaves EDDSA_25519 out of
      // Signature_Scheme::all_available_schemes() (tls_signature_scheme.cpp,
      // "not supported as a signature scheme for certificate authentication"),
      // so listing "Ed25519" here would change nothing; the Ed25519 corpus
      // directory skips Botan for that reason.
      std::vector<std::string> allowed_signature_methods() const override { return {"ECDSA", "RSA", "IMPLICIT"}; }

      std::vector<std::string> allowed_macs() const override { return {"AEAD", "SHA-256", "SHA-384", "SHA-1"}; }

      std::vector<std::string> allowed_key_exchange_methods() const override {
         // Enable PSK key exchange when the config carries a PSK, so PSK
         // ciphersuites (TLS 1.2 / DTLS 1.2) can be negotiated. "RSA" enables
         // static-RSA key exchange (deprecated, but a real test target -- e.g.
         // Bleichenbacher/ROBOT); forward-secret suites are still preferred, so
         // ECDHE handshakes are unaffected.
         if(m_cfg.psk.present) {
            // Botan implements PSK and ECDHE_PSK (no DHE_PSK); the certificate
            // exchanges stay available so a mixed offer still negotiates.
            return {"PSK", "ECDHE_PSK", "ECDH", "DH", "RSA"};
         }
         return {"ECDH", "DH", "RSA"};
      }

      bool require_cert_revocation_info() const override { return false; }

      // The runner controls exactly what the ClientHello carries, so the shim's
      // policy must not impose extensions the test did not ask for. Requiring EMS
      // or secure-renegotiation here would reject minimal/adversarial hellos the
      // runner legitimately sends.
      bool require_extended_master_secret() const override {
         // `uut { extended_master_secret: require }`; "off" is refused at startup
         // (Botan always offers EMS), "allow" is the default.
         return m_cfg.extended_master_secret.value_or("allow") == "require";
      }

      bool allow_insecure_renegotiation() const override { return true; }

      bool require_client_certificate_authentication() const override {
         return m_cfg.verify.require_client_cert || reneg_client_cert.load();
      }

      std::atomic<bool> reneg_client_cert{false};

      bool request_client_certificate_authentication() const override {
         return m_cfg.verify.require_client_cert || m_cfg.verify.request_client_cert || reneg_client_cert.load();
      }

      // RFC 7250: present a raw public key (RawPublicKey) instead of X.509 when configured.
      std::vector<Botan::TLS::Certificate_Type> accepted_server_certificate_types() const override {
         if(!m_cfg.server_certificate_types.empty()) {
            std::vector<Botan::TLS::Certificate_Type> out;
            for(const auto type : m_cfg.server_certificate_types) {
               out.push_back(type == 2 ? Botan::TLS::Certificate_Type::RawPublicKey
                                       : Botan::TLS::Certificate_Type::X509);
            }
            return out;
         }
         return {Botan::TLS::Certificate_Type::X509};
      }

      // RFC 7250 client direction: as a client, offer client_certificate_type=RawPublicKey so
      // client authentication presents a bare public key (via find_raw_public_key) instead of X.509.
      std::vector<Botan::TLS::Certificate_Type> accepted_client_certificate_types() const override {
         if(!m_cfg.client_certificate_types.empty()) {
            std::vector<Botan::TLS::Certificate_Type> out;
            for(const auto type : m_cfg.client_certificate_types) {
               out.push_back(type == 2 ? Botan::TLS::Certificate_Type::RawPublicKey
                                       : Botan::TLS::Certificate_Type::X509);
            }
            return out;
         }
         return {Botan::TLS::Certificate_Type::X509};
      }

      bool allow_tls12() const override {
         return !m_cfg.is_dtls() && version_in_range(Botan::TLS::Protocol_Version::TLS_V12);
      }

      bool allow_tls13() const override {
         return !m_cfg.is_dtls() && version_in_range(Botan::TLS::Protocol_Version::TLS_V13);
      }

      bool allow_dtls12() const override {
         return m_cfg.is_dtls() && version_in_range(Botan::TLS::Protocol_Version::DTLS_V12);
      }

      // Accept peer-initiated renegotiation when the runner asks for it (these
      // are the real Botan policy virtuals; the library defaults are false). A
      // server honours a client's renegotiation ClientHello; a client honours a
      // server HelloRequest.
      bool allow_client_initiated_renegotiation() const override { return reneg_allows("client"); }

      bool allow_server_initiated_renegotiation() const override { return reneg_allows("server"); }

      // `uut { server_preference }`: Botan's own knob covers cipher suites; its
      // default group choice walks the PEER's offered shares in the peer's order,
      // so cover groups here too by walking our list first.
      bool server_uses_own_ciphersuite_preferences() const override {
         return m_cfg.server_preference.value_or(Botan::TLS::Policy::server_uses_own_ciphersuite_preferences());
      }

      Botan::TLS::Group_Params choose_key_exchange_group(
         const std::vector<Botan::TLS::Group_Params>& supported_by_peer,
         const std::vector<Botan::TLS::Group_Params>& offered_by_peer) const override {
         if(!m_cfg.server_preference.value_or(false)) {
            return Botan::TLS::Policy::choose_key_exchange_group(supported_by_peer, offered_by_peer);
         }
         const auto ours = key_exchange_groups();
         for(const auto g : ours) {
            if(std::find(offered_by_peer.begin(), offered_by_peer.end(), g) != offered_by_peer.end()) {
               return g;
            }
         }
         for(const auto g : ours) {
            if(std::find(supported_by_peer.begin(), supported_by_peer.end(), g) != supported_by_peer.end()) {
               return g;
            }
         }
         return Botan::TLS::Group_Params::NONE;
      }

      bool negotiate_encrypt_then_mac() const override {
         return m_cfg.encrypt_then_mac.value_or(Botan::TLS::Policy::negotiate_encrypt_then_mac());
      }

      bool tls_13_middlebox_compatibility_mode() const override {
         return m_cfg.middlebox_compat.value_or(Botan::TLS::Policy::tls_13_middlebox_compatibility_mode());
      }

      // `uut { records_per_traffic_key: N }`: Botan rekeys its write side with an
      // automatic KeyUpdate (update_requested) after N records; 0 disables.
      uint64_t records_per_traffic_key() const override {
         return m_cfg.records_per_traffic_key.value_or(Botan::TLS::Policy::records_per_traffic_key());
      }

      size_t maximum_certificate_chain_size() const override {
         return m_cfg.max_cert_list.value_or(Botan::TLS::Policy::maximum_certificate_chain_size());
      }

      std::optional<uint16_t> record_size_limit() const override {
         if(m_cfg.record_size_limit.has_value()) {
            return static_cast<uint16_t>(*m_cfg.record_size_limit);
         }
         return Botan::TLS::Policy::record_size_limit();
      }

      // `uut { min_key_update_interval_ms: N }`: a peer KeyUpdate arriving sooner
      // than N ms after the previous one is rejected with unexpected_message
      // (a solicited reciprocation is exempt); 0 disables the rate limit.
      uint64_t minimum_key_update_interval_ms() const override {
         return m_cfg.min_key_update_interval_ms.value_or(Botan::TLS::Policy::minimum_key_update_interval_ms());
      }

      size_t new_session_tickets_upon_handshake_success() const override {
         return m_cfg.session_tickets.value_or(Botan::TLS::Policy::new_session_tickets_upon_handshake_success());
      }

      size_t dtls_default_mtu() const override { return m_cfg.mtu; }

      size_t dtls_initial_timeout() const override { return m_cfg.initial_timeout_ms; }

      size_t dtls_maximum_timeout() const override {
         return m_cfg.dtls_max_timeout_ms.value_or(Botan::TLS::Policy::dtls_maximum_timeout());
      }

      std::optional<size_t> dtls_maximum_retransmissions() const override {
         if(m_cfg.dtls_max_retransmissions.has_value()) {
            return static_cast<size_t>(*m_cfg.dtls_max_retransmissions);
         }
         return Botan::TLS::Policy::dtls_maximum_retransmissions();
      }

      std::optional<size_t> dtls_maximum_hello_verify_requests() const override {
         if(m_cfg.dtls_max_hello_verify_requests.has_value()) {
            return static_cast<size_t>(*m_cfg.dtls_max_hello_verify_requests);
         }
         return Botan::TLS::Policy::dtls_maximum_hello_verify_requests();
      }

      bool dtls_server_require_cookie_exchange() const override {
         return m_cfg.dtls_require_cookie.value_or(Botan::TLS::Policy::dtls_server_require_cookie_exchange());
      }

      bool allow_dtls_epoch0_restart() const override {
         return m_cfg.dtls_epoch0_restart.value_or(Botan::TLS::Policy::allow_dtls_epoch0_restart());
      }

   private:
      // `uut { renegotiation }` wins over the legacy renegotiate_freely flag a
      // `renegotiate` step sets; both default to the library's "deny".
      bool reneg_allows(const char* side) const {
         if(m_cfg.renegotiation.has_value()) {
            const std::string& r = *m_cfg.renegotiation;
            return r == "both" || r == side;
         }
         return m_cfg.renegotiate_freely;
      }

      bool version_in_range(Botan::TLS::Protocol_Version v) const {
         const uint16_t code = v.version_code();
         if(m_cfg.min_version.has_value() && !less_or_equal(*m_cfg.min_version, code, m_cfg.is_dtls())) {
            return false;
         }
         if(m_cfg.max_version.has_value() && !less_or_equal(code, *m_cfg.max_version, m_cfg.is_dtls())) {
            return false;
         }
         return true;
      }

      // DTLS version codes count downward (DTLS 1.2 = 0xFEFD < DTLS 1.0 =
      // 0xFEFF), so "newer" is numerically smaller. Normalise the comparison.
      static bool less_or_equal(uint16_t a, uint16_t b, bool dtls) { return dtls ? (a >= b) : (a <= b); }

      const ShimConfig& m_cfg;
};

// -------------------------------------------------------------------------
// Credentials
// -------------------------------------------------------------------------

class Shim_Credentials final : public Botan::Credentials_Manager {
   public:
      // One loaded chain: the certificates, the leaf's private key and the
      // runner's key-type name (derived from the key when the config has none).
      struct LoadedChain {
            std::vector<Botan::X509_Certificate> certs;
            std::shared_ptr<Botan::Private_Key> key;
            std::string key_type;  // rsa_2048 | rsa_pss | ecdsa_p256 | ecdsa_p384 | ecdsa_p521 | ed25519
      };

      static std::vector<Botan::X509_Certificate> read_chain(const std::string& path) {
         std::vector<Botan::X509_Certificate> certs;
         Botan::DataSource_Stream cert_stream(path);
         while(!cert_stream.end_of_data()) {
            try {
               certs.emplace_back(cert_stream);
            } catch(...) {
               break;
            }
         }
         return certs;
      }

      // The runner's key-type name for a loaded chain, from the leaf.
      static std::string key_type_of(const std::vector<Botan::X509_Certificate>& certs, const Botan::Private_Key* key) {
         if(!certs.empty() && certs[0].subject_public_key_algo().oid() == Botan::OID("1.2.840.113549.1.1.10")) {
            return "rsa_pss";
         }
         if(key == nullptr) {
            return "";
         }
         const std::string algo = key->algo_name();
         if(algo == "RSA") {
            return "rsa_2048";
         }
         if(algo == "Ed25519") {
            return "ed25519";
         }
         if(algo == "ECDSA") {
            if(const auto* ec = dynamic_cast<const Botan::EC_PublicKey*>(key)) {
               const std::string curve = ec->domain().get_curve_oid().to_formatted_string();
               if(curve == "secp256r1") {
                  return "ecdsa_p256";
               }
               if(curve == "secp384r1") {
                  return "ecdsa_p384";
               }
               if(curve == "secp521r1") {
                  return "ecdsa_p521";
               }
               return "ecdsa_" + curve;
            }
            return "ecdsa";
         }
         return algo;
      }

      static std::vector<LoadedChain> load_chains(const std::vector<Chain>& chains) {
         std::vector<LoadedChain> out;
         for(const auto& ch : chains) {
            LoadedChain lc;
            if(!ch.key_file.empty()) {
               Botan::DataSource_Stream key_stream(ch.key_file);
               lc.key = Botan::PKCS8::load_key(key_stream);
            }
            if(!ch.cert_file.empty()) {
               lc.certs = read_chain(ch.cert_file);
            }
            lc.key_type = ch.key_type.empty() ? key_type_of(lc.certs, lc.key.get()) : ch.key_type;
            out.push_back(std::move(lc));
         }
         return out;
      }

      explicit Shim_Credentials(const ShimConfig& cfg) : m_cfg(cfg) {
         // Every chain the shim may serve (server role) or present (client
         // role); the shared config derives both lists from the legacy
         // cert_file / key_file pair when the runner sends no `chains`.
         m_server_chains = load_chains(cfg.credentials.chains);
         m_client_chains = load_chains(cfg.credentials.client_chains);
         // Botan has no rsa_pss_pss_* signature schemes: an id-RSASSA-PSS chain
         // can never be signed with correctly, so it is never selected (the
         // startup check refuses the case when nothing else is available).
         auto drop_pss = [](std::vector<LoadedChain>& v) {
            v.erase(std::remove_if(v.begin(), v.end(), [](const LoadedChain& c) { return c.key_type == "rsa_pss"; }),
                    v.end());
         };
         drop_pss(m_server_chains);
         drop_pss(m_client_chains);
         if(!cfg.credentials.trust_file.empty()) {
            Botan::DataSource_Stream trust_stream(cfg.credentials.trust_file);
            while(!trust_stream.end_of_data()) {
               try {
                  m_trust.add_certificate(Botan::X509_Certificate(trust_stream));
               } catch(...) {
                  break;
               }
            }
         }
         if(cfg.psk.present) {
            m_psk_identity = cfg.psk.identity;
            const auto raw = Botan::hex_decode(cfg.psk.secret_hex);
            m_psk = Botan::SymmetricKey(raw.data(), raw.size());
         }
      }

      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(const std::string& /*type*/,
                                                                             const std::string& /*context*/) override {
         return {&m_trust};
      }

      // Does the peer's signature scheme (as Botan hands it over: the
      // SIGNATURE algorithm identifier, e.g. ECDSA/SHA-384, no curve) fit a
      // chain's key? `strict` also binds ECDSA curves to the TLS 1.3 hash
      // pairing (P-256/SHA-256, P-384/SHA-384, P-521/SHA-512), so among
      // several ECDSA chains the one the peer can verify wins; the relaxed
      // pass keeps TLS 1.2's any-curve-any-hash rule for a lone chain.
      static bool scheme_fits(const Botan::AlgorithmIdentifier& ai, const std::string& key_type, bool strict) {
         const std::string name = ai.oid().to_formatted_string();
         auto starts = [&](const char* prefix) { return name.rfind(prefix, 0) == 0; };
         if(key_type == "rsa_2048") {
            return starts("RSA");
         }
         if(key_type == "ed25519") {
            return name == "Ed25519";
         }
         if(key_type.rfind("ecdsa", 0) == 0) {
            if(!starts("ECDSA")) {
               return false;
            }
            if(!strict) {
               return true;
            }
            if(name == "ECDSA/SHA-256") {
               return key_type == "ecdsa_p256" || key_type == "ecdsa_brainpool256r1";
            }
            if(name == "ECDSA/SHA-384") {
               return key_type == "ecdsa_p384" || key_type == "ecdsa_brainpool384r1";
            }
            if(name == "ECDSA/SHA-512") {
               return key_type == "ecdsa_p521" || key_type == "ecdsa_brainpool512r1";
            }
            return true;  // SHA-1 / SHA-224: TLS 1.2 only, any curve
         }
         return false;
      }

      // Prefer a chain the peer can use (key type from its signature_algorithms,
      // then the scheme list, curve-bound first); when nothing fits, present
      // the FIRST chain and let Botan judge it, exactly as a single-chain
      // server or client would (unknown scheme numbers, an rsa_sign-only
      // CertificateRequest answered with an ECDSA chain, ...). Empty only
      // when there is no chain at all.
      static const std::vector<Botan::X509_Certificate>* select(
         const std::vector<LoadedChain>& chains,
         const std::vector<std::string>& cert_key_types,
         const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
         bool tls13) {
         enum class Pass { Strict, Relaxed, KeyTypeOnly };
         const std::array<Pass, 2> passes =
            tls13 ? std::array{Pass::Strict, Pass::KeyTypeOnly} : std::array{Pass::Relaxed, Pass::KeyTypeOnly};
         for(const Pass pass : passes) {
            for(const auto& c : chains) {
               if(c.certs.empty()) {
                  continue;
               }
               if(!cert_key_types.empty()) {
                  const std::string algo = c.certs[0].subject_public_key()->algo_name();
                  if(std::find(cert_key_types.begin(), cert_key_types.end(), algo) == cert_key_types.end()) {
                     continue;
                  }
               }
               if(pass != Pass::KeyTypeOnly && !cert_signature_schemes.empty()) {
                  bool any = false;
                  for(const auto& ai : cert_signature_schemes) {
                     if(scheme_fits(ai, c.key_type, pass == Pass::Strict)) {
                        any = true;
                        break;
                     }
                  }
                  if(!any) {
                     continue;
                  }
               }
               return &c.certs;
            }
         }
         for(const auto& c : chains) {
            if(!c.certs.empty()) {
               return &c.certs;
            }
         }
         return nullptr;
      }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
         const std::string& type,
         const std::string& /*context*/) override {
         // Multi-chain: the first chain (in the runner's order) whose leaf key
         // the peer accepts, else the first chain (see `select`); no chain at
         // all -> an empty list (a PSK-only server, or `client_cert: none`).
         const auto& chains = (type == "tls-client") ? m_client_chains : m_server_chains;
         const bool tls13 = m_cfg.is_dtls() ? m_cfg.requests_dtls13() : m_cfg.min_version.value_or(0x0303) >= 0x0304;
         if(const auto* c = select(chains, cert_key_types, cert_signature_schemes, tls13)) {
            return *c;
         }
         return {};
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate& cert,
                                                          const std::string& /*type*/,
                                                          const std::string& /*context*/) override {
         for(const auto* list : {&m_server_chains, &m_client_chains}) {
            for(const auto& c : *list) {
               if(!c.certs.empty() && c.certs[0] == cert) {
                  return c.key;
               }
            }
         }
         return first_key();
      }

      std::shared_ptr<Botan::Private_Key> first_key() const {
         for(const auto* list : {&m_server_chains, &m_client_chains}) {
            for(const auto& c : *list) {
               if(c.key) {
                  return c.key;
               }
            }
         }
         return nullptr;
      }

      // RFC 7250: hand out the leaf's public key as a bare SubjectPublicKeyInfo when the
      // peer negotiates RawPublicKey. The matching private key is returned below.
      std::shared_ptr<Botan::Public_Key> find_raw_public_key(const std::vector<std::string>& /*key_types*/,
                                                             const std::string& /*type*/,
                                                             const std::string& /*context*/) override {
         auto key = first_key();
         if(!key) {
            return nullptr;
         }
         return key->public_key();
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::Public_Key& /*raw_public_key*/,
                                                          const std::string& /*type*/,
                                                          const std::string& /*context*/) override {
         return first_key();
      }

      // TLS 1.2 / DTLS 1.2 PSK ciphersuites fetch the key through this callback
      // (TLS 1.3 external PSK uses find_preshared_keys instead).
      Botan::SymmetricKey psk(const std::string& type,
                              const std::string& context,
                              const std::string& identity) override {
         // Session_Manager_Stateless draws its ticket-encryption key from
         // psk("tls-server", "session-ticket"). Return a FIXED key so a fresh shim
         // process on a resumed connection can decrypt a ticket issued by an
         // earlier process (self-contained/stateless tickets, TLS 1.2 and 1.3).
         if(type == "tls-server" && (context == "session-ticket" || identity == "session-ticket")) {
            static const uint8_t k[32] = {0x70, 0x6c, 0x7a, 0x6e, 0x2d, 0x73, 0x74, 0x6b, 0x2d, 0x6b, 0x65,
                                          0x79, 0x2d, 0x30, 0x30, 0x30, 0x31, 0x02, 0x03, 0x04, 0x05, 0x06,
                                          0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
            return Botan::SymmetricKey(k, sizeof(k));
         }
         // The shim holds exactly one PSK, for the identity plzn configured. A
         // TLS 1.2 / DTLS server asked for any other identity has no key for it:
         // an empty key makes Botan send unknown_psk_identity (RFC 4279 2),
         // which the unknown-identity negatives probe.
         if(type == "tls-server" && m_psk_identity.has_value() && !identity.empty() && identity != *m_psk_identity) {
            return Botan::SymmetricKey();
         }
         if(m_psk.length() > 0) {
            return m_psk;
         }
         return Botan::Credentials_Manager::psk(type, context, identity);
      }

      // TLS 1.3 external PSK: return the configured PSK as an ExternalPSK when
      // its identity matches (or none was requested).
      std::vector<Botan::TLS::ExternalPSK> find_preshared_keys(
         std::string_view /*host*/,
         Botan::TLS::Connection_Side /*whoami*/,
         const std::vector<std::string>& identities = {},
         const std::optional<std::string>& prf = std::nullopt) override {
         std::vector<Botan::TLS::ExternalPSK> psks;
         if(m_psk.length() == 0) {
            return psks;
         }
         const std::string id = m_psk_identity.value_or("");
         if(!identities.empty() && std::find(identities.begin(), identities.end(), id) == identities.end()) {
            return psks;
         }
         const std::string prf_algo = prf.value_or("SHA-256");
         psks.emplace_back(id, prf_algo, Botan::secure_vector<uint8_t>(m_psk.begin(), m_psk.end()));
         return psks;
      }

      std::string psk_identity(const std::string&, const std::string&, const std::string&) override {
         return m_psk_identity.value_or("");
      }

      std::string psk_identity_hint(const std::string&, const std::string&) override {
         return m_psk_identity.value_or("");
      }

      Botan::secure_vector<uint8_t> session_ticket_key() override {
         return Botan::hex_decode_locked("ABCDEF0123456789ABCDEF0123456789");
      }

      // The cookie secret is read on every ClientHello (Botan reloads it to
      // allow refreshing the key), so a rotation takes effect on the next
      // hello: a cookie issued under the old generation no longer verifies
      // and the client is re-challenged (RFC 6347 4.2.1).
      Botan::secure_vector<uint8_t> dtls_cookie_secret() override {
         auto secret = Botan::hex_decode_locked("F00FB00FD00F100F700F");
         secret.push_back(static_cast<uint8_t>(m_cookie_generation));
         return secret;
      }

      // The runner's `rotate_cookie_secret` step ('C' control frame).
      void rotate_cookie_secret() { ++m_cookie_generation; }

   private:
      const ShimConfig& m_cfg;
      std::vector<LoadedChain> m_server_chains;
      std::vector<LoadedChain> m_client_chains;
      Botan::Certificate_Store_In_Memory m_trust;
      std::optional<std::string> m_psk_identity;
      Botan::SymmetricKey m_psk;
      uint32_t m_cookie_generation = 0;
};

// -------------------------------------------------------------------------
// Callbacks
// -------------------------------------------------------------------------

class Shim_Callbacks final : public Botan::TLS::Callbacks {
   public:
      Shim_Callbacks(const ShimConfig& cfg, ShimSocket& socket) : m_cfg(cfg), m_socket(socket) {
         // T6: `uut { ocsp_stapling }`: the DER OCSP response the runner wrote
         // for our certificate, stapled on request (RFC 6066 8 / RFC 8446
         // 4.4.2.1).
         if(!cfg.credentials.ocsp_file.empty()) {
            std::ifstream in(cfg.credentials.ocsp_file, std::ios::binary);
            m_ocsp.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
         }
      }

      std::vector<uint8_t> tls_provide_cert_status(const std::vector<Botan::X509_Certificate>& /*chain*/,
                                                   const Botan::TLS::Certificate_Status_Request& /*csr*/) override {
         return m_ocsp;
      }

      void set_channel(Botan::TLS::Channel* c) { m_channel = c; }

      std::vector<uint8_t> m_ocsp;

      bool handshake_complete() const { return m_handshake_complete; }

      size_t app_bytes_received() const { return m_app_bytes_received; }

      bool got_close() const { return m_got_close; }

      std::optional<Botan::TLS::Alert> got_fatal_alert() const { return m_got_fatal_alert; }

      void send_key_material(uint32_t connection_index) {
         if(m_key_material_sent || !m_handshake_complete || m_channel == nullptr || !m_channel->is_active()) {
            return;
         }
         for(const auto& request : m_cfg.key_material) {
            if(request.connection != connection_index)
               continue;
            if(request.kind != "exporter" || !request.context.has_value()) {
               throw std::runtime_error("unsupported key_material request reached Botan connection");
            }
            const auto material = m_channel->key_material_export(request.label, *request.context, request.length);
            m_channel->send(material.begin(), material.size());
         }
         m_key_material_sent = true;
      }

      // --- data path ---

      void tls_emit_data(std::span<const uint8_t> data) override {
         if(m_cfg.is_dtls()) {
            m_socket.write_dtls_packet(data.data(), data.size());
         } else {
            m_socket.write(data.data(), data.size());
         }
      }

      void tls_record_received(uint64_t /*seq*/, std::span<const uint8_t> data) override {
         // Default app-data behaviour: answer plzn's framed random-data
         // request. For ShimWrites/ShutdownOnly the main loop drives sending.
         if(m_cfg.app_data.mode == AppDataMode::Echo && m_channel != nullptr && m_channel->is_active()) {
            for(const auto& reply : m_app_responder.receive(data.data(), data.size())) {
               m_channel->send(reply.data(), reply.size());
            }
         }
         m_app_bytes_received += data.size();
      }

      void tls_alert(Botan::TLS::Alert alert) override {
         // In TLS 1.3 user_canceled is a closure alert, whatever its level
         const bool tls13_user_canceled =
            alert.type() == Botan::TLS::Alert::UserCanceled && m_negotiated_version == 0x0304;
         if(alert.type() == Botan::TLS::Alert::CloseNotify) {
            m_got_close = true;
         } else if(alert.is_fatal() && !tls13_user_canceled) {
            m_got_fatal_alert = alert;
         }
      }

      // --- handshake / verification ---

      void tls_session_established(const Botan::TLS::Session_Summary& session) override {
         m_negotiated_version = session.version().version_code();
         m_negotiated_cipher = session.ciphersuite_code();
         // On the server, server_info().hostname() carries the client's SNI.
         m_negotiated_sni = session.server_info().hostname();
         m_was_resumption = session.was_resumption();
         m_negotiated_srtp_profile = session.dtls_srtp_profile();
      }

      void tls_session_activated() override {
         m_handshake_complete = true;
         run_expectations();
      }

      void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& cert_chain,
                                 const std::vector<std::optional<Botan::OCSP::Response>>& ocsp,
                                 const std::vector<Botan::Certificate_Store*>& trusted_roots,
                                 Botan::Usage_Type usage,
                                 std::string_view hostname,
                                 const Botan::TLS::Policy& policy) override {
         if(m_cfg.verify.fail) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::CertificateUnknown, "verification forced to fail");
         }
         // A server that asked for a client certificate verifies the chain it
         // gets (OpenSSL's SSL_VERIFY_PEER and rustls's WebPkiClientVerifier do
         // the same), so `require_client_cert` / `request_client_cert` imply
         // verification against the client trust root; `verify_peer` is the
         // client-side switch (and still forces verification on a server).
         const bool server_asked =
            m_cfg.is_server() && (m_cfg.verify.require_client_cert || m_cfg.verify.request_client_cert);
         if(!m_cfg.verify.verify_peer && !server_asked) {
            return;  // accept without checking
         }
         Botan::TLS::Callbacks::tls_verify_cert_chain(cert_chain, ocsp, trusted_roots, usage, hostname, policy);
      }

      void tls_verify_raw_public_key(const Botan::Public_Key& /*raw_public_key*/,
                                     Botan::Usage_Type /*usage*/,
                                     std::string_view /*hostname*/,
                                     const Botan::TLS::Policy& /*policy*/) override {
         if(m_cfg.verify.fail) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::CertificateUnknown,
                                            "raw-public-key verification forced to fail");
         }
         // The shim is an interop endpoint, so the configured key is the
         // out-of-band trust assertion RFC 7250 requires.
      }

      std::string tls_server_choose_app_protocol(const std::vector<std::string>& client_protos) override {
         if(m_cfg.alpn.decline) {
            return "";
         }
         std::vector<std::string> supported = m_cfg.alpn.select_from;
         if(!m_cfg.alpn.select.empty()) {
            supported.insert(supported.begin(), m_cfg.alpn.select);
         }
         if(!supported.empty()) {
            // Only select a protocol the client actually offered. If the
            // configured protocol was not advertised there is no common protocol
            // (RFC 7301) -- signal the fatal alert, matching OpenSSL, rather than
            // forcing an unoffered protocol onto the peer.
            for(const auto& want : supported) {
               for(const auto& p : client_protos) {
                  if(p == want) {
                     return want;
                  }
               }
            }
            throw Botan::TLS::TLS_Exception(Botan::TLS::AlertType::NoApplicationProtocol,
                                            "no advertised ALPN protocol is acceptable");
         }
         return client_protos.empty() ? std::string() : client_protos.front();
      }

      std::chrono::system_clock::time_point tls_current_timestamp() override {
         using sec = std::chrono::seconds;
         static auto g_now = std::chrono::floor<sec>(std::chrono::system_clock::now());
         return g_now;
      }

      // DTLS runs on the virtual clock the flow advances. TLS has no such
      // steps, so it reads a real monotonic clock: Botan's KeyUpdate rate limit
      // (`minimum_key_update_interval_ms`) treats a zero "last update" time as
      // "never", so the clock must never read 0 for it to count at all.
      uint64_t tls_current_monotonic_clock_ms() const {
         if(m_cfg.is_dtls()) {
            return m_dtls_timer_ns / 1'000'000;
         }
         static const auto start = std::chrono::steady_clock::now();
         const auto elapsed = std::chrono::steady_clock::now() - start;
         return 1 + static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
      }

      uint64_t tls_current_monotonic_clock_ms() override {
         return static_cast<const Shim_Callbacks&>(*this).tls_current_monotonic_clock_ms();
      }

      void advance_dtls_timer_ns(uint64_t ns) { m_dtls_timer_ns += ns; }

      // Botan arms its DTLS retransmission timer here. The operation is only
      // queued; it runs from run_deferred_operations() once the flow advances
      // the virtual clock, never from this callback.
      void tls_register_deferred_operation(uint64_t monotonic_delay_ms, std::function<void()> op) override {
         m_deferred_operations.push_back({tls_current_monotonic_clock_ms() + monotonic_delay_ms, std::move(op)});
      }

      // Runs every queued operation, due or not. One that fires early re-arms
      // itself for the remaining time (and the library applies its own early
      // firing fudge), so afterwards the queue holds exactly the library's
      // current timer and nothing stale.
      void run_deferred_operations() {
         std::vector<Deferred_Operation> ops;
         ops.swap(m_deferred_operations);
         for(auto& deferred : ops) {
            deferred.op();
         }
      }

      // Remaining time until the armed retransmission timer fires, if any
      std::optional<uint64_t> next_timeout_ms() const {
         std::optional<uint64_t> next;
         const uint64_t now = tls_current_monotonic_clock_ms();
         for(const auto& deferred : m_deferred_operations) {
            const uint64_t remaining = deferred.deadline_ms > now ? deferred.deadline_ms - now : 0;
            next = std::min(next.value_or(remaining), remaining);
         }
         return next;
      }

      std::string tls_peer_network_identity() override { return "plzn-shim-peer"; }

   private:
      void run_expectations() {
         const auto& e = m_cfg.expect;
         if(e.version.has_value() && m_negotiated_version != *e.version) {
            note_failure("version mismatch: got " + std::to_string(m_negotiated_version) + " expected " +
                         std::to_string(*e.version));
         }
         if(e.cipher.has_value() && m_negotiated_cipher != *e.cipher) {
            note_failure("cipher mismatch: got " + std::to_string(m_negotiated_cipher) + " expected " +
                         std::to_string(*e.cipher));
         }
         if(m_cfg.alpn.expect.has_value()) {
            const std::string alpn = m_channel != nullptr ? m_channel->application_protocol() : "";
            if(alpn != *m_cfg.alpn.expect) {
               note_failure("alpn mismatch: got '" + alpn + "' expected '" + *m_cfg.alpn.expect + "'");
            }
         }
         if(m_cfg.expect_srtp_profile.has_value() && m_negotiated_srtp_profile != *m_cfg.expect_srtp_profile) {
            note_failure("SRTP profile mismatch: got " + std::to_string(m_negotiated_srtp_profile) + " expected " +
                         std::to_string(*m_cfg.expect_srtp_profile));
         }
         if(m_cfg.expect_server_name.has_value() && m_negotiated_sni != *m_cfg.expect_server_name) {
            note_failure("sni mismatch: got '" + m_negotiated_sni + "' expected '" + *m_cfg.expect_server_name + "'");
         }
         if(m_cfg.expect.resumed.has_value() && m_was_resumption != *m_cfg.expect.resumed) {
            note_failure(std::string("resumed mismatch: got ") + (m_was_resumption ? "true" : "false"));
         }
      }

      const ShimConfig& m_cfg;
      ShimSocket& m_socket;
      AppDataResponder m_app_responder;
      Botan::TLS::Channel* m_channel = nullptr;
      bool m_handshake_complete = false;
      bool m_got_close = false;
      std::optional<Botan::TLS::Alert> m_got_fatal_alert;
      uint16_t m_negotiated_version = 0;
      uint16_t m_negotiated_cipher = 0;
      uint16_t m_negotiated_srtp_profile = 0;
      std::string m_negotiated_sni;
      bool m_was_resumption = false;
      size_t m_app_bytes_received = 0;
      bool m_key_material_sent = false;
      uint64_t m_dtls_timer_ns = 0;

      struct Deferred_Operation {
            uint64_t deadline_ms;
            std::function<void()> op;
      };

      std::vector<Deferred_Operation> m_deferred_operations;
};

// -------------------------------------------------------------------------
// Connection driver
// -------------------------------------------------------------------------

void run_tls_connection(const ShimConfig& cfg,
                        const std::shared_ptr<Shim_Credentials>& creds,
                        const std::shared_ptr<Botan::TLS::Session_Manager>& sessions,
                        const std::shared_ptr<Botan::RandomNumberGenerator>& rng,
                        uint32_t connection_index) {
   ShimSocket socket(cfg.runner.host, cfg.runner.port, cfg.runner.ipv6);
   socket.write_shim_id(cfg.shim_id);

   auto policy = std::make_shared<Shim_Policy>(cfg);
   auto callbacks = std::make_shared<Shim_Callbacks>(cfg, socket);

   std::unique_ptr<Botan::TLS::Channel> chan;
   if(cfg.is_server()) {
      chan = std::make_unique<Botan::TLS::Server>(callbacks, sessions, creds, policy, rng, cfg.is_dtls());
   } else {
      const auto offer = policy->latest_supported_version(cfg.is_dtls());
      const Botan::TLS::Server_Information info(cfg.server_name, cfg.runner.port);
      chan =
         std::make_unique<Botan::TLS::Client>(callbacks, sessions, creds, policy, rng, info, offer, cfg.alpn.advertise);
   }
   callbacks->set_channel(chan.get());

   std::vector<uint8_t> buf(18 * 1024);

   if(cfg.is_dtls()) {
      bool renegotiated = false;

      // A timed-out initial handshake closes the channel: surface that as the
      // handshake failure it is. A timed-out renegotiation leaves the
      // association up (Botan keeps the established epoch), so the exception
      // is only a note there.
      auto run_timers = [&]() {
         try {
            callbacks->run_deferred_operations();
         } catch(...) {
            if(chan->is_closed()) {
               socket.write_dtls_timeout_expired();
               throw;
            }
         }
      };

      for(;;) {
         DtlsEvent ev = socket.read_dtls_event();
         if(ev.opcode == DtlsOpcode::Control) {
            // Runtime control ('C' frame) from a flow step.
            if(ev.command == static_cast<uint8_t>(DtlsControl::RotateCookieSecret)) {
               creds->rotate_cookie_secret();
               continue;
            }
            throw ShimSocketError("unknown DTLS control command " + std::to_string(ev.command));
         }
         if(ev.opcode == DtlsOpcode::Eof) {
            // The peer went away mid-handshake: that is a failed handshake,
            // not a clean end (a peer that rejects our flight without an
            // alert -- a bad Finished, an empty Certificate -- just closes).
            if(!callbacks->handshake_complete() && !chan->is_closed()) {
               throw ShimSocketError("peer closed the connection before the handshake completed");
            }
            break;
         }
         if(ev.opcode == DtlsOpcode::AdvanceClock) {
            callbacks->advance_dtls_timer_ns(ev.nanos);
            run_timers();
            socket.write_dtls_ack('t');
            if(callbacks->got_close() || chan->is_closed()) {
               break;
            }
            continue;
         }
         if(ev.opcode == DtlsOpcode::ExpectTimeout) {
            // Let a stale timer (eg from a flight the peer has since answered)
            // retire itself before reporting what is armed
            run_timers();
            const auto actual = callbacks->next_timeout_ms();
            const bool expected_none = ev.nanos == UINT64_MAX;
            if(expected_none != !actual.has_value()) {
               throw std::runtime_error(expected_none ? "expected no DTLS timeout, but one is armed"
                                                      : "expected an armed DTLS timeout, but got none");
            }
            if(actual.has_value()) {
               const uint64_t actual_ns = *actual * 1'000'000;
               if(actual_ns != ev.nanos) {
                  throw std::runtime_error("DTLS next timeout mismatch: expected " + std::to_string(ev.nanos) +
                                           "ns, got " + std::to_string(actual_ns) + "ns");
               }
            }
            socket.write_dtls_ack('e');
            continue;
         }
         if(ev.opcode == DtlsOpcode::UpdateTimeout) {
            // Requires.dynamic_timeout rejects this before the shim dials. Keep
            // the protocol guard explicit for hand-written configurations.
            throw std::runtime_error("set_timeout is unsupported by Botan's live Channel API");
         }
         chan->received_data(ev.packet.data(), ev.packet.size());
         callbacks->send_key_material(connection_index);
         // `uut { renegotiate_after_handshake }`: the DTLS client, like the TLS
         // one, starts a renegotiation after one application-data round trip.
         if(!cfg.is_server() && cfg.renegotiate_after_handshake && !renegotiated && callbacks->handshake_complete() &&
            callbacks->app_bytes_received() > 0 && chan->is_active()) {
            renegotiated = true;
            chan->renegotiate();
         }
         if(callbacks->got_close() || chan->is_closed()) {
            break;
         }
      }
   } else {
      bool half_rtt_sent = false;
      bool renegotiated = false;
      for(;;) {
         const size_t got = socket.read(buf.data(), buf.size());
         if(got == 0) {
            // The peer went away mid-handshake: that is a failed handshake,
            // not a clean end (a peer that rejects our flight without an
            // alert -- a bad Finished, an empty Certificate -- just closes).
            if(!callbacks->handshake_complete() && !chan->is_closed()) {
               throw ShimSocketError("peer closed the connection before the handshake completed");
            }
            break;
         }
         chan->received_data(buf.data(), got);
         callbacks->send_key_material(connection_index);

         // `uut { half_rtt_data }`: the server's application keys are usable
         // as soon as its own Finished is out (is_active), before the client's
         // Finished arrives (handshake_complete). Write each entry as one
         // record in that window.
         if(cfg.is_server() && !half_rtt_sent && !cfg.half_rtt_data.empty() && !callbacks->handshake_complete() &&
            chan->is_active()) {
            for(const auto& rec : cfg.half_rtt_data) {
               chan->send(rec);
            }
            half_rtt_sent = true;
         }
         // `uut { renegotiate_after_handshake }`: a client that has completed
         // one application-data round trip starts a renegotiation (TLS 1.2).
         if(!cfg.is_server() && cfg.renegotiate_after_handshake && !renegotiated && callbacks->handshake_complete() &&
            callbacks->app_bytes_received() > 0 && chan->is_active()) {
            renegotiated = true;
            chan->renegotiate();
         }

         if(cfg.is_server() && cfg.hello_request_after_app_data && !renegotiated && callbacks->handshake_complete() &&
            callbacks->app_bytes_received() > 0 && chan->is_active()) {
            renegotiated = true;
            if(cfg.require_client_cert_on_renegotiation) {
               policy->reneg_client_cert = true;
            }
            chan->renegotiate(true);
         }

         if(callbacks->handshake_complete() && cfg.app_data.mode == AppDataMode::ShimWrites &&
            !cfg.app_data.send.empty() && chan->is_active()) {
            chan->send(cfg.app_data.send);
            chan->close();
            break;
         }
         if(callbacks->handshake_complete() && cfg.app_data.mode == AppDataMode::ShutdownOnly && chan->is_active()) {
            chan->close();
            break;
         }
         if(callbacks->got_close() || chan->is_closed()) {
            break;
         }
      }
      if(cfg.is_server() && !cfg.half_rtt_data.empty() && !half_rtt_sent) {
         note_failure(
            "half_rtt_data: no half-RTT window opened (the server's application keys were never "
            "usable before the client's Finished; TLS 1.3 only)");
      }
   }
   // A fatal alert from the peer ended the connection: that is the peer's
   // rejection, i.e. a failed handshake/flow from the shim's side, not a clean
   // end. Report it through the TLS_Exception path so a negative test's
   // expectation ("the peer must close on a fatal alert") self-checks correctly.
   if(const auto fatal = callbacks->got_fatal_alert()) {
      throw Botan::TLS::TLS_Exception(fatal->type(), "peer sent fatal alert " + fatal->type_string());
   }
}

std::string json_string(std::string_view s) {
   std::string out = "\"";
   for(const char c : s) {
      if(c == '"' || c == '\\') {
         out += '\\';
      }
      out += c;
   }
   out += '"';
   return out;
}

// Discovery: `plzn run` asks for this JSON object before spawning any test.
// The expectations path (local xfails/skips) is baked in by the build system.
void print_shim_info() {
   std::cout << R"({"protocol":"plzn-shim","protocol_version":1,"name":"botan")";
#if defined(BOTAN_PLZN_SHIM_EXPECTATIONS)
   std::cout << ",\"expectations\":" << json_string(BOTAN_PLZN_SHIM_EXPECTATIONS);
#endif
   std::cout << "}" << std::endl;
}

}  // namespace

int main(int argc, char* argv[]) {
   plzn::exit_when_orphaned();
   std::string config_path;
   for(int i = 1; i < argc; ++i) {
      const std::string a = argv[i];
      if(a == "--plzn-shim-info") {
         print_shim_info();
         return 0;
      } else if(a == "-config" && i + 1 < argc) {
         config_path = argv[++i];
      } else if(a.rfind("-config=", 0) == 0) {
         config_path = a.substr(std::string("-config=").size());
      }
   }
   if(config_path.empty()) {
      std::cerr << "usage: botan_plzn_shim -config <file.json> | --plzn-shim-info" << std::endl;
      return 2;
   }

   ShimConfig cfg;
   try {
      cfg = ShimConfig::from_file(config_path);
   } catch(const std::exception& e) {
      std::cerr << "config error: " << e.what() << std::endl;
      return 2;
   }

   if(cfg.requests_dtls13()) {
      plzn::report_unsupported("versions", "Botan does not currently implement DTLS 1.3");
   }
   if(!cfg.is_dtls() && (cfg.min_version.value_or(0x0303) < 0x0303 || cfg.max_version.value_or(0x0304) < 0x0303)) {
      plzn::report_unsupported("versions", "Botan 3 does not implement TLS 1.0 or TLS 1.1");
   }
   const auto uses_rpk = [](const std::vector<uint8_t>& types) {
      return std::find(types.begin(), types.end(), 2) != types.end();
   };
   if((cfg.is_dtls() || cfg.min_version.value_or(0x0303) <= 0x0303) &&
      (uses_rpk(cfg.server_certificate_types) || uses_rpk(cfg.client_certificate_types))) {
      plzn::report_unsupported("certificate_types", "this Botan API supports raw public keys only in TLS 1.3");
   }
   if(std::any_of(cfg.key_material.begin(), cfg.key_material.end(), [&](const auto& request) {
         return request.kind.starts_with("tls_unique") ||
                (request.kind == "exporter" &&
                 (!request.context.has_value() || (cfg.max_version == 0x0303 && request.context->empty())));
      })) {
      plzn::report_result(
         plzn::ShimResult::UnsupportedConfig,
         "key_material: Botan cannot distinguish absent from explicitly empty TLS 1.2 exporter contexts and does not expose tls-unique");
   }

   // What plzn will offer: refuse the case before dialing when this build
   // implements none of the suites / groups it needs, so the runner SKIPs it
   // with the reason instead of failing on a capability gap.
   if(!cfg.requires_any_suite.empty()) {
      bool any = false;
      std::string list;
      for(const uint16_t id : cfg.requires_any_suite) {
         const auto suite = Botan::TLS::Ciphersuite::by_id(id);
         any = any || (suite.has_value() && suite->valid());
         char buf[16];
         std::snprintf(buf, sizeof(buf), "%s0x%04x", list.empty() ? "" : ", ", id);
         list += buf;
      }
      if(!any) {
         plzn::report_result(
            plzn::ShimResult::UnsupportedConfig,
            "peer.capabilities: this Botan build implements none of the offered cipher suites [" + list + "]");
      }
   }
   if(!cfg.requires_any_group.empty()) {
      bool any = false;
      for(const uint16_t id : cfg.requires_any_group) {
         const Botan::TLS::Group_Params g(static_cast<Botan::TLS::Group_Params_Code>(id));
         // Unknown/private-use codepoints may report as available even though
         // Botan cannot name them or put them in a policy. Require both, as
         // key_exchange_groups() does for an explicitly configured list.
         any = any || (g.to_string().has_value() && g.is_available());
      }
      if(!any) {
         plzn::report_result(plzn::ShimResult::UnsupportedConfig,
                             "peer.capabilities: this Botan build has none of the offered key exchange groups");
      }
   }
   if(cfg.requires_dynamic_timeout) {
      plzn::report_result(plzn::ShimResult::UnsupportedConfig,
                          "set_timeout: Botan has no API to rescale a live DTLS retransmission timer");
   }
   if(cfg.compress_certificate) {
      plzn::report_result(plzn::ShimResult::UnsupportedConfig,
                          "uut.compress_certificate: Botan does not implement RFC 8879 certificate compression");
   }

   // Botan has no rsa_pss_pss_* signature schemes (RFC 8446 4.2.3), so a
   // certificate carrying an id-RSASSA-PSS key can be neither verified (as
   // the client) nor used to sign (as the server): refuse, do not fail.
   if(!cfg.requires_server_keys.empty() && std::all_of(cfg.requires_server_keys.begin(),
                                                       cfg.requires_server_keys.end(),
                                                       [](const std::string& k) { return k == "rsa_pss"; })) {
      plzn::report_result(plzn::ShimResult::UnsupportedConfig,
                          "--cert rsa-pss: Botan has no rsa_pss_pss_* signature schemes, so an id-RSASSA-PSS "
                          "server key cannot be verified");
   }
   // A shim SERVER with chains: refuse only when every chain is id-RSASSA-PSS
   // (a PSS chain among others is simply never selected).
   if(cfg.is_server() && !cfg.credentials.chains.empty()) {
      try {
         bool all_pss = true;
         for(const auto& ch : cfg.credentials.chains) {
            Botan::DataSource_Stream cert_stream(ch.cert_file);
            const Botan::X509_Certificate leaf(cert_stream);
            if(leaf.subject_public_key_algo().oid() != Botan::OID("1.2.840.113549.1.1.10")) {
               all_pss = false;
            }
         }
         if(all_pss) {
            plzn::report_result(plzn::ShimResult::UnsupportedConfig,
                                "--cert rsa-pss: Botan has no rsa_pss_pss_* signature schemes, so an "
                                "id-RSASSA-PSS server key cannot sign");
         }
      } catch(const std::exception&) {
         // A certificate that does not parse fails later, with its own error.
      }
   }

   // Policy knobs this library has no switch for: refuse before dialing so the
   // runner SKIPs the case with the reason (never a vacuous pass).
   if(cfg.max_early_data.value_or(0) > 0) {
      plzn::report_unsupported("max_early_data", "Botan does not currently implement TLS 1.3 0-RTT early data");
   }
   if(cfg.record_size_limit.has_value() && (cfg.min_version != 0x0304 || cfg.max_version != 0x0304)) {
      plzn::report_unsupported("record_size_limit",
                               "Botan implements RFC 8449 only for TLS 1.3 without a TLS 1.2 downgrade");
   }
   if(cfg.key_update) {
      plzn::report_unsupported("key_update",
                               "the Botan shim does not expose manual post-handshake KeyUpdate initiation");
   }
   if(cfg.early_data_send > 0 || cfg.early_data_expect > 0) {
      plzn::report_result(plzn::ShimResult::UnsupportedConfig,
                          "flow.EarlyData: Botan does not currently implement TLS 1.3 0-RTT early data");
   }
   if(cfg.extended_master_secret.has_value() && *cfg.extended_master_secret == "off") {
      plzn::report_unsupported(
         "extended_master_secret",
         "Botan always offers extended_master_secret (RFC 7627); only require/allow are controllable");
   }
   // T6: Botan's TLS 1.3 server never requests post-handshake authentication.
   if(!cfg.post_handshake_auth.empty()) {
      plzn::report_unsupported("post_handshake_auth",
                               "Botan has no server-side post-handshake client authentication (RFC 8446 4.6.2)");
   }
   if(cfg.renegotiation.has_value()) {
      const std::string& r = *cfg.renegotiation;
      if(r != "none" && r != "client" && r != "server" && r != "both") {
         plzn::report_result(plzn::ShimResult::LocalError, "invalid renegotiation value: " + r);
      }
   }
   if(cfg.extended_master_secret.has_value()) {
      const std::string& e = *cfg.extended_master_secret;
      if(e != "require" && e != "allow" && e != "off") {
         plzn::report_result(plzn::ShimResult::LocalError, "invalid extended_master_secret value: " + e);
      }
   }

   auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
   auto creds = std::make_shared<Shim_Credentials>(cfg);
   // Stateless (self-contained, ticket-key-encrypted) sessions so a fresh shim
   // process on a resumed connection can decrypt a ticket issued by an earlier
   // process -- required for cross-process TLS 1.3 resumption (and keeps TLS 1.2
   // ticket resumption working). The key comes from Shim_Credentials::psk.
   // `uut { session_tickets: 0 }` = no resumption at all: a Noop manager issues
   // no tickets and remembers no sessions (TLS 1.2 and 1.3 alike).
   std::shared_ptr<Botan::TLS::Session_Manager> sessions;
   if(cfg.session_tickets.has_value() && *cfg.session_tickets == 0) {
      sessions = std::make_shared<Botan::TLS::Session_Manager_Noop>();
   } else if(!cfg.is_server()) {
      // A CLIENT must remember the tickets it is issued to resume on a later
      // connection of the same process (multi-session tests); the stateless
      // manager only encrypts server-side state and stores nothing.
      sessions = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
   } else {
      sessions = std::make_shared<Botan::TLS::Session_Manager_Hybrid>(
         std::make_unique<Botan::TLS::Session_Manager_In_Memory>(rng), creds, rng, true);
   }

   const bool expect_handshake_failure = cfg.expect.handshake_error.has_value();
   // plzn abandons the handshake on purpose: a failure from the abrupt close
   // and a completed connection are both fine.
   const bool abandoned = cfg.expect.handshake_abandoned;

   try {
      for(uint32_t i = 0; i <= cfg.resume_count; ++i) {
         const auto connection_cfg = cfg.for_connection(i);
         run_tls_connection(connection_cfg, creds, sessions, rng, i);
         if(!g_fail_reason.empty()) {
            break;
         }
      }
   } catch(const Botan::TLS::TLS_Exception& e) {
      const std::string detail =
         std::string("TLS exception (alert ") + plzn::alert_name(static_cast<uint8_t>(e.type())) + "): " + e.what();
      if(expect_handshake_failure || abandoned) {
         report_success(detail);
      }
      report_result(ShimResult::HandshakeFailed, detail);
   } catch(const ShimSocketError& e) {
      const std::string detail = std::string("socket error: ") + e.what();
      if(expect_handshake_failure || abandoned) {
         report_success(detail);
      }
      report_result(ShimResult::IoError, detail);
   } catch(const Botan::Decoding_Error& e) {
      // A malformed peer message Botan could not even parse (it answers with a
      // decode_error alert). That is the peer's protocol failure, not a shim
      // problem, so it is a handshake failure like a TLS_Exception -- a
      // negative test that expects the rejection passes on it.
      const std::string detail = std::string("decoding error: ") + e.what();
      if(expect_handshake_failure || abandoned) {
         report_success(detail);
      }
      report_result(ShimResult::HandshakeFailed, detail);
   } catch(const Botan::Invalid_Authentication_Tag& e) {
      // Botan surfaces a peer record-authentication failure directly from the
      // AEAD rather than wrapping it in TLS_Exception. This is a specific
      // authenticated-record rejection path, not the arbitrary catch-all
      // covered below.
      const std::string detail = std::string("authentication failure: ") + e.what();
      if(expect_handshake_failure || abandoned) {
         report_success(detail);
      }
      report_result(ShimResult::HandshakeFailed, detail);
   } catch(const std::exception& e) {
      const std::string detail = std::string("error: ") + e.what();
      report_result(ShimResult::LocalError, detail);
   }

   if(expect_handshake_failure && !abandoned) {
      report_result(ShimResult::UnexpectedSuccess, "expected handshake to fail but it succeeded");
   }
   if(!g_fail_reason.empty()) {
      // note_failure is only used for negotiated-parameter expectation mismatches.
      report_result(ShimResult::ExpectationMismatch, g_fail_reason);
   }
   report_success();
}
