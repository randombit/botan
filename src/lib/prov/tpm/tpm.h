
/*
* TPM 1.2 interface
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM_H_
#define BOTAN_TPM_H_

#include <botan/bigint.h>
#include <botan/exceptn.h>
#include <botan/pk_keys.h>
#include <botan/rng.h>
#include <botan/uuid.h>
#include <functional>

BOTAN_DEPRECATED_HEADER("tpm.h")

//TODO remove this
#include <tss/tspi.h>

namespace Botan {

class BOTAN_PUBLIC_API(2, 0) TPM_Error final : public Exception {
   public:
      TPM_Error(std::string_view err) : Exception(err) {}

      ErrorType error_type() const noexcept override { return ErrorType::TPMError; }
};

/**
* Creates a connection to the TPM. All other TPM types take and hold
* a TPM_Context reference, so all other objects must be deallocated
* before ~TPM_Context runs.
*
* Use nullptr for the srk_password to indicate the well known secret
* (ie, an unencrypted SRK). This is usually what you want.
*
* TODO: handling owner password?
*/
class BOTAN_PUBLIC_API(2, 0) TPM_Context final {
   public:
      /**
      * User callback for getting the PIN. Will be passed the best available
      * description of what we are attempting to load.
      */
      typedef std::function<std::string(std::string)> pin_cb;

      BOTAN_DEPRECATED("TPM support is deprecated see #3877") TPM_Context(pin_cb cb, const char* srk_password);

      ~TPM_Context();

      // Get data from the TPM's RNG, whatever that is
      void gen_random(uint8_t out[], size_t out_len);

      // Uses Tspi_TPM_StirRandom to add data to TPM's internal pool
      void stir_random(const uint8_t in[], size_t in_len);

      std::string get_user_pin(const std::string& who) { return m_pin_cb(who); }

      uint32_t current_counter();

      TSS_HCONTEXT handle() const { return m_ctx; }

      TSS_HKEY srk() const { return m_srk; }

   private:
      std::function<std::string(std::string)> m_pin_cb;
      TSS_HCONTEXT m_ctx;
      TSS_HKEY m_srk;
      TSS_HTPM m_tpm;
      TSS_HPOLICY m_srk_policy;
};

class BOTAN_PUBLIC_API(2, 0) TPM_RNG final : public Hardware_RNG {
   public:
      TPM_RNG(TPM_Context& ctx) : m_ctx(ctx) {}

      bool accepts_input() const override { return true; }

      std::string name() const override { return "TPM_RNG"; }

      bool is_seeded() const override { return true; }

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) override {
         if(!input.empty()) {
            m_ctx.stir_random(input.data(), input.size());
         }

         if(!output.empty()) {
            m_ctx.gen_random(output.data(), output.size());
         }
      }

   private:
      TPM_Context& m_ctx;
};

enum class TPM_Storage_Type { User, System };

/*
* Also implements the public interface, but does not have usable
* TODO: derive from RSA_PublicKey???
*/
class BOTAN_PUBLIC_API(2, 0) TPM_PrivateKey final : public Private_Key {
   public:
      // TODO: key import?

      /*
      * Create a new key on the TPM parented to the SRK
      * @param bits must be 1024 or 2048
      */
      TPM_PrivateKey(TPM_Context& ctx, size_t bits, const char* key_password);

      // reference an existing TPM key using URL syntax from GnuTLS
      // "tpmkey:uuid=79f07ca9-73ac-478a-9093-11ca6702e774;storage=user"
      //TPM_PrivateKey(TPM_Context& ctx, std::string_view tpm_url);

      TPM_PrivateKey(TPM_Context& ctx, std::string_view uuid, TPM_Storage_Type storage_type);

      TPM_PrivateKey(TPM_Context& ctx, const std::vector<uint8_t>& blob);

      /**
      * If the key is not currently registered under a known UUID,
      * generates a new random UUID and registers the key.
      * Returns the access URL.
      */
      std::string register_key(TPM_Storage_Type storage_type);

      /**
      * Returns a copy of the public key
      */
      std::unique_ptr<Public_Key> public_key() const override;

      std::vector<uint8_t> export_blob() const;

      TPM_Context& ctx() const { return m_ctx; }

      TSS_HKEY handle() const { return m_key; }

      /*
      * Returns the list of all keys (in URL format) registered with the system
      */
      static std::vector<std::string> registered_keys(TPM_Context& ctx);

      size_t estimated_strength() const override;

      size_t key_length() const override;

      AlgorithmIdentifier algorithm_identifier() const override;

      std::vector<uint8_t> public_key_bits() const override;

      std::vector<uint8_t> raw_public_key_bits() const override;

      secure_vector<uint8_t> private_key_bits() const override;

      bool check_key(RandomNumberGenerator& rng, bool) const override;

      BigInt get_n() const;

      BigInt get_e() const;

      std::string algo_name() const override { return "RSA"; }  // ???

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator&) const override {
         throw Not_Implemented("Cannot generate a new TPM-based keypair from this asymmetric key");
      }

      bool supports_operation(PublicKeyOperation op) const override { return (op == PublicKeyOperation::Signature); }

      std::unique_ptr<PK_Ops::Signature> _create_signature_op(RandomNumberGenerator& rng,
                                                              PK_Signature_Options& options) const override;

   private:
      TPM_Context& m_ctx;
      TSS_HKEY m_key;

      // Only set for registered keys
      UUID m_uuid;
      TPM_Storage_Type m_storage;

      // Lazily computed in get_n, get_e
      mutable BigInt m_n, m_e;
};

// TODO: NVRAM interface
// TODO: PCR measurement, writing, key locking

}  // namespace Botan

#endif
