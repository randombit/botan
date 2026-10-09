/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hpke.h>

#include <botan/aead.h>
#include <botan/exceptn.h>
#include <botan/mac.h>
#include <botan/pk_keys.h>
#include <botan/rng.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/hpke_kem.h>
#include <botan/internal/mem_utils.h>
#include <array>
#include <limits>

namespace Botan::HPKE {

namespace {

struct KEM_Info {
      size_t nsecret;
      size_t nenc;
      size_t npk;
      size_t nsk;
      const char* name;
};

std::optional<KEM_Info> kem_info(KEM_Code code) {
   // See RFC 9180 Section 7.1
   switch(code) {
      case KEM_Code::DHKEM_P256:
         return KEM_Info{32, 65, 65, 32, "DHKEM(P-256, HKDF-SHA256)"};
      case KEM_Code::DHKEM_P384:
         return KEM_Info{48, 97, 97, 48, "DHKEM(P-384, HKDF-SHA384)"};
      case KEM_Code::DHKEM_P521:
         return KEM_Info{64, 133, 133, 66, "DHKEM(P-521, HKDF-SHA512)"};
      case KEM_Code::DHKEM_X25519:
         return KEM_Info{32, 32, 32, 32, "DHKEM(X25519, HKDF-SHA256)"};
      case KEM_Code::DHKEM_X448:
         return KEM_Info{64, 56, 56, 56, "DHKEM(X448, HKDF-SHA512)"};
   }
   return std::nullopt;
}

KEM_Info require_kem_info(const KEM_Id& kem) {
   if(const auto info = kem_info(kem.code())) {
      return *info;
   }
   throw Invalid_State(fmt("Unknown HPKE KEM {}", kem.wire_code()));
}

struct KDF_Info {
      size_t nh;
      const char* hash;
      const char* name;
};

std::optional<KDF_Info> kdf_info(KDF_Code code) {
   // See RFC 9180 Section 7.2
   switch(code) {
      case KDF_Code::HKDF_SHA256:
         return KDF_Info{32, "SHA-256", "HKDF-SHA256"};
      case KDF_Code::HKDF_SHA384:
         return KDF_Info{48, "SHA-384", "HKDF-SHA384"};
      case KDF_Code::HKDF_SHA512:
         return KDF_Info{64, "SHA-512", "HKDF-SHA512"};
   }
   return std::nullopt;
}

std::string kdf_hash_name(KDF_Id kdf) {
   if(const auto info = kdf_info(kdf.code())) {
      return info->hash;
   }
   throw Not_Implemented(fmt("Unknown HPKE KDF {}", kdf.wire_code()));
}

struct AEAD_Info {
      size_t nk;
      size_t nn;
      size_t nt;
      const char* name;
      const char* spec;
};

std::optional<AEAD_Info> aead_info(AEAD_Code code) {
   // See RFC 9180 Section 7.3
   switch(code) {
      case AEAD_Code::AES_128_GCM:
         return AEAD_Info{16, 12, 16, "AES-128-GCM", "AES-128/GCM"};
      case AEAD_Code::AES_256_GCM:
         return AEAD_Info{32, 12, 16, "AES-256-GCM", "AES-256/GCM"};
      case AEAD_Code::ChaCha20Poly1305:
         return AEAD_Info{32, 12, 16, "ChaCha20Poly1305", "ChaCha20Poly1305"};
      case AEAD_Code::ExportOnly:
         return std::nullopt;
   }
   return std::nullopt;
}

std::string aead_spec(AEAD_Id aead) {
   if(const auto info = aead_info(aead.code())) {
      return info->spec;
   }
   throw Not_Implemented(fmt("Unknown HPKE AEAD {}", aead.wire_code()));
}

}  // namespace

/*
* Identifier metadata
*/

bool KEM_Id::is_available() const {
   try {
      KEM_Ops::create(*this);
      return true;
   } catch(Exception&) {
      return false;
   }
}

size_t KEM_Id::shared_secret_length() const {
   return require_kem_info(*this).nsecret;
}

size_t KEM_Id::encapsulation_length() const {
   return require_kem_info(*this).nenc;
}

size_t KEM_Id::public_key_length() const {
   return require_kem_info(*this).npk;
}

size_t KEM_Id::private_key_length() const {
   return require_kem_info(*this).nsk;
}

std::optional<std::string> KEM_Id::to_string() const {
   if(const auto info = kem_info(m_code)) {
      return std::string(info->name);
   }
   return std::nullopt;
}

bool KDF_Id::is_available() const {
   if(const auto info = kdf_info(m_code)) {
      return MessageAuthenticationCode::create(fmt("HMAC({})", info->hash)) != nullptr;
   }
   return false;
}

size_t KDF_Id::output_length() const {
   if(const auto info = kdf_info(m_code)) {
      return info->nh;
   }
   throw Invalid_State(fmt("Unknown HPKE KDF {}", wire_code()));
}

std::optional<std::string> KDF_Id::to_string() const {
   if(const auto info = kdf_info(m_code)) {
      return std::string(info->name);
   }
   return std::nullopt;
}

bool AEAD_Id::is_available() const {
   if(is_export_only()) {
      return true;
   }
   if(const auto info = aead_info(m_code)) {
      return AEAD_Mode::create(info->spec, Cipher_Dir::Encryption) != nullptr;
   }
   return false;
}

size_t AEAD_Id::key_length() const {
   if(const auto info = aead_info(m_code)) {
      return info->nk;
   }
   throw Invalid_State(fmt("HPKE AEAD {} does not define a key length", wire_code()));
}

size_t AEAD_Id::nonce_length() const {
   if(const auto info = aead_info(m_code)) {
      return info->nn;
   }
   throw Invalid_State(fmt("HPKE AEAD {} does not define a nonce length", wire_code()));
}

size_t AEAD_Id::tag_length() const {
   if(const auto info = aead_info(m_code)) {
      return info->nt;
   }
   throw Invalid_State(fmt("HPKE AEAD {} does not define a tag length", wire_code()));
}

std::optional<std::string> AEAD_Id::to_string() const {
   if(is_export_only()) {
      return std::string("export-only");
   }
   if(const auto info = aead_info(m_code)) {
      return std::string(info->name);
   }
   return std::nullopt;
}

std::optional<std::string> Suite::to_string() const {
   const auto kem = m_kem.to_string();
   const auto kdf = m_kdf.to_string();
   const auto aead = m_aead.to_string();
   if(kem && kdf && aead) {
      return fmt("{}/{}/{}", *kem, *kdf, *aead);
   }
   return std::nullopt;
}

/*
* Keys
*/

class Public_Key::Data final {
   public:
      Data(std::shared_ptr<const KEM_Ops> ops, std::unique_ptr<const Botan::Public_Key> key) :
            m_ops(std::move(ops)), m_key(std::move(key)), m_serialized(m_ops->serialize_public(*m_key)) {}

      const KEM_Ops& ops() const { return *m_ops; }

      const std::shared_ptr<const KEM_Ops>& ops_ptr() const { return m_ops; }

      const Botan::Public_Key& key() const { return *m_key; }

      const std::vector<uint8_t>& serialized() const { return m_serialized; }

   private:
      std::shared_ptr<const KEM_Ops> m_ops;
      std::unique_ptr<const Botan::Public_Key> m_key;
      std::vector<uint8_t> m_serialized;
};

Public_Key Public_Key::deserialize(KEM_Id kem, std::span<const uint8_t> bytes) {
   std::shared_ptr<const KEM_Ops> ops = KEM_Ops::create(kem);
   auto key = ops->deserialize_public(bytes);
   return Public_Key(std::make_shared<Data>(std::move(ops), std::move(key)));
}

Public_Key Public_Key::from_key(KEM_Id kem, std::unique_ptr<Botan::Public_Key> key) {
   BOTAN_ARG_CHECK(key != nullptr, "HPKE::Public_Key::from_key: key is null");
   std::shared_ptr<const KEM_Ops> ops = KEM_Ops::create(kem);
   auto adopted = ops->adopt_public(std::move(key));
   return Public_Key(std::make_shared<Data>(std::move(ops), std::move(adopted)));
}

KEM_Id Public_Key::kem() const {
   return m_data->ops().kem_id();
}

std::vector<uint8_t> Public_Key::serialize() const {
   return m_data->serialized();
}

const Botan::Public_Key& Public_Key::underlying() const {
   return m_data->key();
}

class Private_Key::Data final {
   public:
      Data(std::shared_ptr<const KEM_Ops> ops, std::unique_ptr<const Botan::Private_Key> key) :
            m_ops(std::move(ops)), m_key(std::move(key)) {}

      const KEM_Ops& ops() const { return *m_ops; }

      const std::shared_ptr<const KEM_Ops>& ops_ptr() const { return m_ops; }

      const Botan::Private_Key& key() const { return *m_key; }

   private:
      std::shared_ptr<const KEM_Ops> m_ops;
      std::unique_ptr<const Botan::Private_Key> m_key;
};

Private_Key Private_Key::generate(KEM_Id kem, RandomNumberGenerator& rng) {
   std::shared_ptr<const KEM_Ops> ops = KEM_Ops::create(kem);
   auto key = ops->generate_key(rng);
   return Private_Key(std::make_shared<Data>(std::move(ops), std::move(key)));
}

Private_Key Private_Key::derive(KEM_Id kem, std::span<const uint8_t> ikm) {
   std::shared_ptr<const KEM_Ops> ops = KEM_Ops::create(kem);
   auto key = ops->derive_key_pair(ikm);
   return Private_Key(std::make_shared<Data>(std::move(ops), std::move(key)));
}

Private_Key Private_Key::deserialize(KEM_Id kem, std::span<const uint8_t> bytes) {
   std::shared_ptr<const KEM_Ops> ops = KEM_Ops::create(kem);
   auto key = ops->deserialize_private(bytes);
   return Private_Key(std::make_shared<Data>(std::move(ops), std::move(key)));
}

Private_Key Private_Key::from_key(KEM_Id kem, std::unique_ptr<Botan::Private_Key> key) {
   BOTAN_ARG_CHECK(key != nullptr, "HPKE::Private_Key::from_key: key is null");
   std::shared_ptr<const KEM_Ops> ops = KEM_Ops::create(kem);
   auto adopted = ops->adopt_private(std::move(key));
   return Private_Key(std::make_shared<Data>(std::move(ops), std::move(adopted)));
}

KEM_Id Private_Key::kem() const {
   return m_data->ops().kem_id();
}

Public_Key Private_Key::public_key() const {
   auto pub = m_data->key().public_key();
   return Public_Key(std::make_shared<Public_Key::Data>(m_data->ops_ptr(), std::move(pub)));
}

secure_vector<uint8_t> Private_Key::serialize() const {
   return m_data->ops().serialize_private(m_data->key());
}

const Botan::Private_Key& Private_Key::underlying() const {
   return m_data->key();
}

/*
* PSK
*/

PSK::PSK(std::span<const uint8_t> psk, std::span<const uint8_t> psk_id) :
      m_psk(psk.begin(), psk.end()), m_psk_id(psk_id.begin(), psk_id.end()) {
   // See RFC 9180 Section 5.1
   BOTAN_ARG_CHECK(!m_psk.empty() && !m_psk_id.empty(), "HPKE PSK and PSK identity must both be non-empty");
   // See RFC 9180 Section 9.5
   BOTAN_ARG_CHECK(m_psk.size() >= 32, "HPKE PSK must be at least 32 bytes");
}

/*
* Key schedule and contexts (RFC 9180 Section 5)
*/

namespace detail {

class Context_Data final {
   public:
      Context_Data(const Suite& suite,
                   Mode mode,
                   Cipher_Dir direction,
                   std::span<const uint8_t> shared_secret,
                   std::span<const uint8_t> info,
                   const PSK* psk,
                   std::vector<uint8_t> enc) :
            m_suite(suite), m_mode(mode), m_hash(kdf_hash_name(suite.kdf())), m_enc(std::move(enc)) {
         // See RFC 9180 Section 5.1
         const auto id_octets = [](uint16_t code) {
            return std::array<uint8_t, 2>{static_cast<uint8_t>(code >> 8), static_cast<uint8_t>(code & 0xFF)};
         };

         m_suite_id = concat<std::vector<uint8_t>>(as_span_of_bytes(std::string_view("HPKE")),
                                                   id_octets(suite.kem().wire_code()),
                                                   id_octets(suite.kdf().wire_code()),
                                                   id_octets(suite.aead().wire_code()));

         std::span<const uint8_t> psk_bytes;
         std::span<const uint8_t> psk_id;
         if(psk != nullptr) {
            psk_bytes = psk->secret();
            psk_id = psk->identity();
         }

         const auto psk_id_hash = labeled_extract(m_hash, m_suite_id, {}, "psk_id_hash", psk_id);
         const auto info_hash = labeled_extract(m_hash, m_suite_id, {}, "info_hash", info);
         const std::array<uint8_t, 1> mode_octet{static_cast<uint8_t>(mode)};
         const auto ks_context = concat<std::vector<uint8_t>>(mode_octet, psk_id_hash, info_hash);

         const auto secret = labeled_extract(m_hash, m_suite_id, shared_secret, "secret", psk_bytes);

         // See RFC 9180 Section 5.3
         if(!suite.is_export_only()) {
            m_aead = AEAD_Mode::create_or_throw(aead_spec(suite.aead()), direction);

            const auto key = labeled_expand(m_hash, m_suite_id, secret, "key", ks_context, suite.aead().key_length());
            m_base_nonce =
               labeled_expand(m_hash, m_suite_id, secret, "base_nonce", ks_context, suite.aead().nonce_length());
            m_aead->set_key(key);

            // RFC 9180 Section 5.2 permits sequence numbers up to 2^(8*Nn) - 2.
            // Every AEAD defined there has Nn = 12, which exceeds the 64-bit
            // counter used here, so the effective limit becomes 2^64 - 2: the
            // final counter value is never used, so that the increment following
            // a successful operation cannot overflow.
            const size_t nn = m_base_nonce.size();
            m_seq_limit = (nn >= 8) ? std::numeric_limits<uint64_t>::max() : ((uint64_t(1) << (8 * nn)) - 1);
         }

         m_exporter_secret = labeled_expand(m_hash, m_suite_id, secret, "exp", ks_context, suite.kdf().output_length());
      }

      Suite suite() const { return m_suite; }

      Mode mode() const { return m_mode; }

      const std::vector<uint8_t>& enc() const { return m_enc; }

      uint64_t seq() const { return m_seq; }

      template <typename T>
      T crypt(std::optional<uint64_t> at_seq, std::span<const uint8_t> aad, std::span<const uint8_t> msg) {
         // See RFC 9180 Section 7.3
         if(!m_aead) {
            throw Invalid_State("This HPKE suite is export-only and cannot seal or open messages");
         }

         // See RFC 9180 Section 5.2
         const uint64_t seq = at_seq.value_or(m_seq);
         if(seq >= m_seq_limit) {
            throw Invalid_State("HPKE context message limit reached");
         }

         auto nonce = m_base_nonce;
         for(size_t i = 0; i != 8 && i != nonce.size(); ++i) {
            nonce[nonce.size() - 1 - i] ^= static_cast<uint8_t>(seq >> (8 * i));
         }

         if(msg.size() < m_aead->minimum_final_size()) {
            throw Invalid_Authentication_Tag("HPKE ciphertext is shorter than the authentication tag");
         }

         T buf(msg.begin(), msg.end());
         try {
            m_aead->set_associated_data(aad);
            m_aead->start(nonce);
            m_aead->finish(buf);
         } catch(...) {
            // Failed messages must not leave the AEAD in a partially processed
            // state: the caller may retry at the same sequence number.
            m_aead->reset();
            throw;
         }

         // Consume the sequence number only on success, and only when
         // an explicit sequence number was not provided
         if(!at_seq.has_value()) {
            m_seq += 1;
         }

         return buf;
      }

      secure_vector<uint8_t> export_secret(std::span<const uint8_t> exporter_context, size_t length) const {
         // See RFC 9180 Section 5.3
         BOTAN_ARG_CHECK(length <= 255 * m_exporter_secret.size(), "HPKE export length too large");
         return labeled_expand(m_hash, m_suite_id, m_exporter_secret, "sec", exporter_context, length);
      }

   private:
      Suite m_suite;
      Mode m_mode;
      std::string m_hash;
      std::vector<uint8_t> m_suite_id;
      std::unique_ptr<AEAD_Mode> m_aead;
      secure_vector<uint8_t> m_base_nonce;
      secure_vector<uint8_t> m_exporter_secret;
      uint64_t m_seq = 0;
      uint64_t m_seq_limit = 0;
      std::vector<uint8_t> m_enc;
};

}  // namespace detail

/*
* Sender context
*/

Sender_Context::Sender_Context(std::unique_ptr<detail::Context_Data> data) : m_data(std::move(data)) {}

Sender_Context::Sender_Context(Sender_Context&&) noexcept = default;
Sender_Context& Sender_Context::operator=(Sender_Context&&) noexcept = default;
Sender_Context::~Sender_Context() = default;

Sender_Context Sender_Context::setup(Mode mode,
                                     const Suite& suite,
                                     const Public_Key& recipient_key,
                                     const Private_Key* sender_identity_key,
                                     const PSK* psk,
                                     RandomNumberGenerator& rng,
                                     std::span<const uint8_t> info) {
   // See RFC 9180 Section 5.1
   if(recipient_key.kem() != suite.kem()) {
      throw Invalid_Argument("HPKE recipient key does not match the suite's KEM");
   }

   const auto& ops = recipient_key.m_data->ops();

   auto encap = [&]() {
      if(sender_identity_key != nullptr) {
         if(sender_identity_key->kem() != suite.kem()) {
            throw Invalid_Argument("HPKE sender identity key does not match the suite's KEM");
         }
         return ops.auth_encap(recipient_key.m_data->key(), sender_identity_key->m_data->key(), rng);
      }
      return ops.encap(recipient_key.m_data->key(), rng);
   }();

   return Sender_Context(std::make_unique<detail::Context_Data>(
      suite, mode, Cipher_Dir::Encryption, encap.shared_secret, info, psk, std::move(encap.enc)));
}

Sender_Context Sender_Context::setup_base(const Suite& suite,
                                          const Public_Key& recipient_key,
                                          RandomNumberGenerator& rng,
                                          std::span<const uint8_t> info) {
   // See RFC 9180 Section 5.1.1
   return setup(Mode::Base, suite, recipient_key, nullptr, nullptr, rng, info);
}

Sender_Context Sender_Context::setup_psk(const Suite& suite,
                                         const Public_Key& recipient_key,
                                         RandomNumberGenerator& rng,
                                         const PSK& psk,
                                         std::span<const uint8_t> info) {
   // See RFC 9180 Section 5.1.2
   return setup(Mode::PSK, suite, recipient_key, nullptr, &psk, rng, info);
}

Sender_Context Sender_Context::setup_auth(const Suite& suite,
                                          const Public_Key& recipient_key,
                                          const Private_Key& sender_identity_key,
                                          RandomNumberGenerator& rng,
                                          std::span<const uint8_t> info) {
   // See RFC 9180 Section 5.1.3
   return setup(Mode::Auth, suite, recipient_key, &sender_identity_key, nullptr, rng, info);
}

Sender_Context Sender_Context::setup_auth_psk(const Suite& suite,
                                              const Public_Key& recipient_key,
                                              const Private_Key& sender_identity_key,
                                              RandomNumberGenerator& rng,
                                              const PSK& psk,
                                              std::span<const uint8_t> info) {
   // See RFC 9180 Section 5.1.4
   return setup(Mode::AuthPSK, suite, recipient_key, &sender_identity_key, &psk, rng, info);
}

const std::vector<uint8_t>& Sender_Context::encapsulated_key() const {
   return m_data->enc();
}

std::vector<uint8_t> Sender_Context::seal(std::span<const uint8_t> aad, std::span<const uint8_t> ptext) {
   // See RFC 9180 Section 5.2
   return m_data->crypt<std::vector<uint8_t>>(std::nullopt, aad, ptext);
}

secure_vector<uint8_t> Sender_Context::export_secret(std::span<const uint8_t> exporter_context, size_t length) const {
   // See RFC 9180 Section 5.3
   return m_data->export_secret(exporter_context, length);
}

uint64_t Sender_Context::next_sequence() const {
   return m_data->seq();
}

Mode Sender_Context::mode() const {
   return m_data->mode();
}

Suite Sender_Context::suite() const {
   return m_data->suite();
}

/*
* Recipient context
*/

Recipient_Context::Recipient_Context(std::unique_ptr<detail::Context_Data> data) : m_data(std::move(data)) {}

Recipient_Context::Recipient_Context(Recipient_Context&&) noexcept = default;
Recipient_Context& Recipient_Context::operator=(Recipient_Context&&) noexcept = default;
Recipient_Context::~Recipient_Context() = default;

Recipient_Context Recipient_Context::setup(Mode mode,
                                           const Suite& suite,
                                           const Private_Key& recipient_key,
                                           std::span<const uint8_t> enc,
                                           const Public_Key* sender_identity_key,
                                           const PSK* psk,
                                           RandomNumberGenerator& rng,
                                           std::span<const uint8_t> info) {
   // See RFC 9180 Section 5.1
   if(recipient_key.kem() != suite.kem()) {
      throw Invalid_Argument("HPKE recipient key does not match the suite's KEM");
   }

   const auto& ops = recipient_key.m_data->ops();

   auto shared_secret = [&]() {
      if(sender_identity_key != nullptr) {
         if(sender_identity_key->kem() != suite.kem()) {
            throw Invalid_Argument("HPKE sender identity key does not match the suite's KEM");
         }
         return ops.auth_decap(enc, recipient_key.m_data->key(), sender_identity_key->m_data->key(), rng);
      }
      return ops.decap(enc, recipient_key.m_data->key(), rng);
   }();

   return Recipient_Context(std::make_unique<detail::Context_Data>(
      suite, mode, Cipher_Dir::Decryption, shared_secret, info, psk, std::vector<uint8_t>{}));
}

Recipient_Context Recipient_Context::setup_base(const Suite& suite,
                                                const Private_Key& recipient_key,
                                                std::span<const uint8_t> enc,
                                                RandomNumberGenerator& rng,
                                                std::span<const uint8_t> info) {
   // See RFC 9180 Section 5.1.1
   return setup(Mode::Base, suite, recipient_key, enc, nullptr, nullptr, rng, info);
}

Recipient_Context Recipient_Context::setup_psk(const Suite& suite,
                                               const Private_Key& recipient_key,
                                               std::span<const uint8_t> enc,
                                               RandomNumberGenerator& rng,
                                               const PSK& psk,
                                               std::span<const uint8_t> info) {
   // See RFC 9180 Section 5.1.2
   return setup(Mode::PSK, suite, recipient_key, enc, nullptr, &psk, rng, info);
}

Recipient_Context Recipient_Context::setup_auth(const Suite& suite,
                                                const Private_Key& recipient_key,
                                                std::span<const uint8_t> enc,
                                                const Public_Key& sender_identity_key,
                                                RandomNumberGenerator& rng,
                                                std::span<const uint8_t> info) {
   // See RFC 9180 Section 5.1.3
   return setup(Mode::Auth, suite, recipient_key, enc, &sender_identity_key, nullptr, rng, info);
}

Recipient_Context Recipient_Context::setup_auth_psk(const Suite& suite,
                                                    const Private_Key& recipient_key,
                                                    std::span<const uint8_t> enc,
                                                    const Public_Key& sender_identity_key,
                                                    RandomNumberGenerator& rng,
                                                    const PSK& psk,
                                                    std::span<const uint8_t> info) {
   // See RFC 9180 Section 5.1.4
   return setup(Mode::AuthPSK, suite, recipient_key, enc, &sender_identity_key, &psk, rng, info);
}

secure_vector<uint8_t> Recipient_Context::open(std::span<const uint8_t> aad, std::span<const uint8_t> ctext) {
   // See RFC 9180 Section 5.2
   return m_data->crypt<secure_vector<uint8_t>>(std::nullopt, aad, ctext);
}

secure_vector<uint8_t> Recipient_Context::open_at_sequence(uint64_t seq,
                                                           std::span<const uint8_t> aad,
                                                           std::span<const uint8_t> ctext) {
   return m_data->crypt<secure_vector<uint8_t>>(seq, aad, ctext);
}

secure_vector<uint8_t> Recipient_Context::export_secret(std::span<const uint8_t> exporter_context,
                                                        size_t length) const {
   // See RFC 9180 Section 5.3
   return m_data->export_secret(exporter_context, length);
}

uint64_t Recipient_Context::next_sequence() const {
   return m_data->seq();
}

Mode Recipient_Context::mode() const {
   return m_data->mode();
}

Suite Recipient_Context::suite() const {
   return m_data->suite();
}

}  // namespace Botan::HPKE
