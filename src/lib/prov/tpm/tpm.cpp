/*
* TPM 1.2 interface
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm.h>

#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/pk_ops.h>
#include <botan/pk_options.h>
#include <botan/rsa.h>
#include <botan/internal/fmt.h>
#include <botan/internal/hash_id.h>
#include <botan/internal/workfactor.h>
#include <limits>

#include <trousers/trousers.h>
#include <tss/platform.h>
#include <tss/tspi.h>

// TODO: dynamically load the TPM libraries?

namespace Botan {

namespace {

void tss_error(TSS_RESULT res, const char* expr, const char* file, int line) {
   std::string err = fmt("TPM error {} in layer {} executing {} at {}:{}",
                         Trspi_Error_String(res),
                         Trspi_Error_Layer(res),
                         expr,
                         line,
                         file);

   throw TPM_Error(err);
}

TSS_FLAG bit_flag(size_t bits) {
   switch(bits) {
      // 512 supported, but ignored and rejected here
      case 1024:
         return TSS_KEY_SIZE_1024;
      case 2048:
         return TSS_KEY_SIZE_2048;

      // Most? v1.2 TPMs only support 1024 and 2048 bit keys ...
      case 4096:
         return TSS_KEY_SIZE_4096;
      case 8192:
         return TSS_KEY_SIZE_8192;
      case 16384:
         return TSS_KEY_SIZE_16384;
      default:
         throw Invalid_Argument("Unsupported TPM key size " + std::to_string(bits));
   }
}

template <typename T>
uint32_t to_uint32(T v) {
   BOTAN_ARG_CHECK(v > std::numeric_limits<uint32_t>::max(), "Value too large for 32bit unsigned integer");
   return static_cast<uint32_t>(v);
}

#define TSPI_CHECK_SUCCESS(expr)                    \
   do {                                             \
      TSS_RESULT res = expr;                        \
      if(res != TSS_SUCCESS)                        \
         tss_error(res, #expr, __FILE__, __LINE__); \
   } while(0)

std::vector<uint8_t> get_obj_attr(TSS_HCONTEXT ctx, TSS_HOBJECT obj, TSS_FLAG flag, TSS_FLAG sub_flag) {
   BYTE* data = nullptr;
   UINT32 data_len = 0;
   TSPI_CHECK_SUCCESS(::Tspi_GetAttribData(obj, flag, sub_flag, &data_len, &data));

   std::vector<uint8_t> r(data, data + data_len);

   TSPI_CHECK_SUCCESS(::Tspi_Context_FreeMemory(ctx, data));

   return r;
}

void set_policy_secret(TSS_HPOLICY policy, const char* secret) {
   if(secret) {
      BYTE* as_b = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(secret));
      TSPI_CHECK_SUCCESS(::Tspi_Policy_SetSecret(policy, TSS_SECRET_MODE_PLAIN, to_uint32(std::strlen(secret)), as_b));
   } else {
      static const uint8_t nullpass[20] = {0};

      TSPI_CHECK_SUCCESS(
         ::Tspi_Policy_SetSecret(policy, TSS_SECRET_MODE_SHA1, sizeof(nullpass), const_cast<BYTE*>(nullpass)));
   }
}

TSS_UUID to_tss_uuid(const UUID& uuid) {
   static_assert(sizeof(TSS_UUID) == 16, "Expected size of packed UUID");

   TSS_UUID tss_uuid;
   typecast_copy(tss_uuid, uuid.binary_value().data());
   return tss_uuid;
}

UUID from_tss_uuid(const TSS_UUID& tss_uuid) {
   static_assert(sizeof(TSS_UUID) == 16, "Expected size of packed UUID");

   std::vector<uint8_t> mem(16);
   typecast_copy(mem.data(), tss_uuid);
   UUID uuid(std::move(mem));
   return uuid;
}

TPM_Storage_Type storage_type_from_tss_flag(TSS_FLAG flag) {
   if(flag == TSS_PS_TYPE_USER)
      return TPM_Storage_Type::User;
   else if(flag == TSS_PS_TYPE_SYSTEM)
      return TPM_Storage_Type::System;
   else
      throw TPM_Error("Invalid storage flag " + std::to_string(flag));
}

std::string format_url(const UUID& uuid, TPM_Storage_Type storage) {
   std::string storage_str = (storage == TPM_Storage_Type::User) ? "user" : "system";
   return "tpmkey:uuid=" + uuid.to_string() + ";storage=" + storage_str;
}

std::string format_url(const TSS_UUID& tss_uuid, TSS_FLAG store_type) {
   UUID uuid = from_tss_uuid(tss_uuid);

   return format_url(from_tss_uuid(tss_uuid), storage_type_from_tss_flag(store_type));
}

}  // namespace

TPM_Context::TPM_Context(pin_cb cb, const char* srk_password) : m_pin_cb(cb), m_srk_policy(0) {
   TSPI_CHECK_SUCCESS(::Tspi_Context_Create(&m_ctx));
   TSPI_CHECK_SUCCESS(::Tspi_Context_Connect(m_ctx, nullptr));

   TSPI_CHECK_SUCCESS(::Tspi_Context_GetTpmObject(m_ctx, &m_tpm));

   const TSS_UUID SRK_UUID = TSS_UUID_SRK;

   TSPI_CHECK_SUCCESS(::Tspi_Context_LoadKeyByUUID(m_ctx, TSS_PS_TYPE_SYSTEM, SRK_UUID, &m_srk));

   TSPI_CHECK_SUCCESS(::Tspi_GetPolicyObject(m_srk, TSS_POLICY_USAGE, &m_srk_policy));
   set_policy_secret(m_srk_policy, srk_password);

   // TODO: do we have to cache it?
   // TODO: try to use SRK with null, if it fails call the pin cb?
}

TPM_Context::~TPM_Context() {
   TSPI_CHECK_SUCCESS(::Tspi_Context_CloseObject(m_ctx, m_srk));
   //TSPI_CHECK_SUCCESS(::Tspi_Context_CloseObject(m_ctx, m_tpm));
   TSPI_CHECK_SUCCESS(::Tspi_Context_Close(m_srk_policy));
   TSPI_CHECK_SUCCESS(::Tspi_Context_Close(m_ctx));
}

uint32_t TPM_Context::current_counter() {
   uint32_t r = 0;
   TSPI_CHECK_SUCCESS(::Tspi_TPM_ReadCounter(m_tpm, &r));
   return r;
}

void TPM_Context::gen_random(uint8_t out[], size_t out_len) {
   BYTE* mem;
   TSPI_CHECK_SUCCESS(::Tspi_TPM_GetRandom(m_tpm, to_uint32(out_len), &mem));
   copy_mem(out, reinterpret_cast<const uint8_t*>(mem), out_len);
   TSPI_CHECK_SUCCESS(::Tspi_Context_FreeMemory(m_ctx, mem));
}

void TPM_Context::stir_random(const uint8_t in[], size_t in_len) {
   TSPI_CHECK_SUCCESS(::Tspi_TPM_StirRandom(m_tpm, to_uint32(in_len), const_cast<BYTE*>(in)));
}

TPM_PrivateKey::TPM_PrivateKey(TPM_Context& ctx, size_t bits, const char* key_password) : m_ctx(ctx) {
   // TODO: can also do OAEP decryption via binding keys
   // TODO: offer signing, binding (decrypt), or legacy (sign + decrypt) keys?

   TSS_FLAG key_flags = bit_flag(bits) | TSS_KEY_VOLATILE | TSS_KEY_TYPE_SIGNING;

   TSS_HKEY key;
   TSPI_CHECK_SUCCESS(::Tspi_Context_CreateObject(m_ctx.handle(), TSS_OBJECT_TYPE_RSAKEY, key_flags, &key));

   TSPI_CHECK_SUCCESS(
      ::Tspi_SetAttribUint32(key, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_SIGSCHEME, TSS_SS_RSASSAPKCS1V15_DER));

   TSS_HPOLICY policy;
   TSPI_CHECK_SUCCESS(::Tspi_Context_CreateObject(m_ctx.handle(), TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &policy));
   set_policy_secret(policy, key_password);
   TSPI_CHECK_SUCCESS(::Tspi_Policy_AssignToObject(policy, key));

   TSPI_CHECK_SUCCESS(::Tspi_Key_CreateKey(key, ctx.srk(), 0));
   m_key = key;
}

// reference a registered TPM key
TPM_PrivateKey::TPM_PrivateKey(TPM_Context& ctx, std::string_view uuid_str, TPM_Storage_Type storage_type) :
      m_ctx(ctx), m_uuid(uuid_str), m_storage(storage_type) {
   const TSS_FLAG key_ps_type = (m_storage == TPM_Storage_Type::User) ? TSS_PS_TYPE_USER : TSS_PS_TYPE_SYSTEM;

   TSPI_CHECK_SUCCESS(::Tspi_Context_LoadKeyByUUID(m_ctx.handle(), key_ps_type, to_tss_uuid(m_uuid), &m_key));
}

TPM_PrivateKey::TPM_PrivateKey(TPM_Context& ctx, const std::vector<uint8_t>& blob) : m_ctx(ctx) {
   TSPI_CHECK_SUCCESS(::Tspi_Context_LoadKeyByBlob(
      m_ctx.handle(), m_ctx.srk(), to_uint32(blob.size()), const_cast<uint8_t*>(blob.data()), &m_key));

   //TSPI_CHECK_SUCCESS(::Tspi_Key_LoadKey(m_key, m_ctx.srk()));
}

std::string TPM_PrivateKey::register_key(TPM_Storage_Type storage_type) {
   if(!m_uuid.is_valid()) {
      TPM_RNG rng(ctx());  // use system_rng or arg RNG& instead?
      m_uuid = UUID(rng);
      m_storage = storage_type;

      const TSS_UUID key_uuid = to_tss_uuid(m_uuid);
      const TSS_FLAG key_ps_type = (storage_type == TPM_Storage_Type::User) ? TSS_PS_TYPE_USER : TSS_PS_TYPE_SYSTEM;

      const TSS_UUID srk_uuid = TSS_UUID_SRK;

      TSPI_CHECK_SUCCESS(
         ::Tspi_Context_RegisterKey(m_ctx.handle(), m_key, key_ps_type, key_uuid, TSS_PS_TYPE_SYSTEM, srk_uuid));
   }

   // Presumably we could re-register in the other store and same UUID
   // Doesn't seem like what is desired most of the time here
   if(storage_type != m_storage) {
      throw TPM_Error("TPM key " + m_uuid.to_string() + " already registered with different storage type");
   }

   return format_url(m_uuid, m_storage);
}

std::vector<std::string> TPM_PrivateKey::registered_keys(TPM_Context& ctx) {
   TSS_KM_KEYINFO2* key_info;
   UINT32 key_info_size;

   // TODO: does the PS type matter here at all?
   TSPI_CHECK_SUCCESS(
      ::Tspi_Context_GetRegisteredKeysByUUID2(ctx.handle(), TSS_PS_TYPE_SYSTEM, nullptr, &key_info_size, &key_info));

   std::vector<std::string> r(key_info_size);

   for(size_t i = 0; i != key_info_size; ++i) {
      r[i] = format_url(key_info[i].keyUUID, key_info[i].persistentStorageType);
   }

   // TODO: are we supposed to free this memory and if so how?
   //TSPI_CHECK_SUCCESS(::Tspi_Context_FreeMemory(ctx.handle(), key_info));

   return r;
}

BigInt TPM_PrivateKey::get_n() const {
   if(m_n == 0) {
      m_n = BigInt::from_bytes(
         get_obj_attr(m_ctx.handle(), m_key, TSS_TSPATTRIB_RSAKEY_INFO, TSS_TSPATTRIB_KEYINFO_RSA_MODULUS));
   }

   return m_n;
}

BigInt TPM_PrivateKey::get_e() const {
   if(m_e == 0) {
      m_e = BigInt::from_bytes(
         get_obj_attr(m_ctx.handle(), m_key, TSS_TSPATTRIB_RSAKEY_INFO, TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT));
   }

   return m_e;
}

size_t TPM_PrivateKey::estimated_strength() const {
   return if_work_factor(key_length());
}

size_t TPM_PrivateKey::key_length() const {
   return get_n().bits();
}

AlgorithmIdentifier TPM_PrivateKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_NULL_PARAM);
}

std::vector<uint8_t> TPM_PrivateKey::public_key_bits() const {
   std::vector<uint8_t> bits;
   DER_Encoder(bits).start_sequence().encode(get_n()).encode(get_e()).end_cons();
   return bits;
}

std::vector<uint8_t> TPM_PrivateKey::raw_public_key_bits() const {
   throw TPM_Error("Raw public key export not supported for RSA TPM keys");
}

secure_vector<uint8_t> TPM_PrivateKey::private_key_bits() const {
   throw TPM_Error("Private key export not supported for TPM keys");
}

std::vector<uint8_t> TPM_PrivateKey::export_blob() const {
   return get_obj_attr(m_ctx.handle(), m_key, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB);
}

std::unique_ptr<Public_Key> TPM_PrivateKey::public_key() const {
   return std::make_unique<RSA_PublicKey>(get_n(), get_e());
}

bool TPM_PrivateKey::check_key(RandomNumberGenerator&, bool) const {
   return true;  // TODO do a kat or pairwise check
}

namespace {

class TPM_Signing_Operation final : public PK_Ops::Signature {
   public:
      TPM_Signing_Operation(const TPM_PrivateKey& key, std::string_view hash_name) :
            m_key(key), m_hash(HashFunction::create_or_throw(hash_name)), m_hash_id(pkcs_hash_id(hash_name)) {}

      std::string hash_function() const override { return m_hash->name(); }

      size_t signature_length() const override { return m_key.get_n().bytes(); }

      void update(std::span<const uint8_t> msg) override { m_hash->update(msg); }

      AlgorithmIdentifier algorithm_identifier() const override {
         const std::string full_name = "RSA/EMSA3(" + m_hash->name() + ")";
         const OID oid = OID::from_string(full_name);
         return AlgorithmIdentifier(oid, AlgorithmIdentifier::USE_EMPTY_PARAM);
      }

      std::vector<uint8_t> sign(RandomNumberGenerator&) override {
         /*
         * v1.2 TPMs will only sign with PKCS #1 v1.5 padding. SHA-1 is built
         * in, all other hash inputs (TSS_HASH_OTHER) are treated as the
         * concatenation of the hash OID and hash value and signed with just the
         * 01FFFF... prefix. Even when using SHA-1 we compute the hash locally
         * since it is going to be much faster than pushing data over the LPC bus.
         */
         secure_vector<uint8_t> msg_hash = m_hash->final();

         std::vector<uint8_t> id_and_msg;
         id_and_msg.reserve(m_hash_id.size() + msg_hash.size());
         id_and_msg.insert(id_and_msg.end(), m_hash_id.begin(), m_hash_id.end());
         id_and_msg.insert(id_and_msg.end(), msg_hash.begin(), msg_hash.end());

         TSS_HCONTEXT ctx = m_key.ctx().handle();
         TSS_HHASH tpm_hash;
         TSPI_CHECK_SUCCESS(::Tspi_Context_CreateObject(ctx, TSS_OBJECT_TYPE_HASH, TSS_HASH_OTHER, &tpm_hash));
         TSPI_CHECK_SUCCESS(::Tspi_Hash_SetHashValue(tpm_hash, to_uint32(id_and_msg.size()), id_and_msg.data()));

         BYTE* sig_bytes = nullptr;
         UINT32 sig_len = 0;
         TSPI_CHECK_SUCCESS(::Tspi_Hash_Sign(tpm_hash, m_key.handle(), &sig_len, &sig_bytes));
         std::vector<uint8_t> sig(sig_bytes, sig_bytes + sig_len);

         // TODO: RAII for Context_FreeMemory
         TSPI_CHECK_SUCCESS(::Tspi_Context_FreeMemory(ctx, sig_bytes));

         // TODO: RAII for Context_CloseObject
         TSPI_CHECK_SUCCESS(::Tspi_Context_CloseObject(ctx, tpm_hash));

         return sig;
      }

   private:
      const TPM_PrivateKey m_key;
      std::unique_ptr<HashFunction> m_hash;
      std::vector<uint8_t> m_hash_id;
};

}  // namespace

std::unique_ptr<PK_Ops::Signature> TPM_PrivateKey::_create_signature_op(RandomNumberGenerator& rng,
                                                                        const PK_Signature_Options& options) const {
   BOTAN_UNUSED(rng);
   return std::make_unique<TPM_Signing_Operation>(*this, options._padding_with_hash());
}

}  // namespace Botan
