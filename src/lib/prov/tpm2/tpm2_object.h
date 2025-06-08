/*
* TPM 2.0 Base Object handling
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_BASE_OBJECT_H_
#define BOTAN_TPM2_BASE_OBJECT_H_

#include <botan/tpm2_context.h>

/// Forward declaration of TSS2 type for convenience
using TPMA_OBJECT = uint32_t;

/// Forward declaration of TSS2 type for convenience
using TPMI_ALG_PUBLIC = uint16_t;

namespace Botan::TPM2 {

struct PublicInfo;
struct ObjectHandles;
class ObjectSetter;
class SessionBundle;

/**
 * See TPM 2.0 Part 2, Section 8.3.2
 */
struct ObjectAttributes {
      static ObjectAttributes read(TPMA_OBJECT attributes);
      static TPMA_OBJECT render(ObjectAttributes attributes);

      /// The hierarchy of the object may or may not change (i.e. when keys are duplicated)
      bool fixed_tpm = false;

      /// Saved contexts of this object may or may not be loaded after Startup(CLEAR)
      bool st_clear = false;

      /// The parent of the object may or may not change
      bool fixed_parent = false;

      /// Indicates that the TPM generated all of the sensitive data other than the authValue
      bool sensitive_data_origin = false;

      /// USER role actions may or may not be performed without authorization (HMAC or password)
      bool user_with_auth = false;

      /// ADMIN role actions may or may not require a policy session
      bool admin_with_policy = false;

      /// If set, the object is not subject to dictionary attack protection
      bool no_da = false;

      /// If not set, the object may be duplicated without an inner wrapper on the private portion
      /// Otherwise, symmetricAlg must not be TPM_ALG_NULL and newParentHandle must not be TPM_RH_NULL
      bool encrypted_duplication = false;

      /// Key usage is restricted to structures of known format
      /// (e.g. it won't sign data whose hash was not calculated by the TPM)
      bool restricted = false;

      /// The private portion of the key might be used for data decryption
      bool decrypt = false;

      /// The private portion of the key might be used for data signing, or
      /// data encryption (if the key is a symmetric key)
      bool sign_encrypt = false;

      /// The private portion of the key might be used for X.509 certificate signing
      /// (normal signing, via Esys_Sign(), of arbitrary data is not allowed)
      bool x509sign = false;
};

/**
 * Wraps and manages the lifetime of TPM2 object handles both for transient and
 * persistent objects. When this object is destroyed, the handles are released
 * accordingly.
 *
 * Note that some TSS2 library functions may internally release handles passed
 * to them. In such cases, the Object instance can be disengaged, ensuring that
 * the handles are not released twice. This is an internal functionality and
 * should not be used directly.
 */
class BOTAN_PUBLIC_API(3, 6) Object {
   public:
      explicit Object(std::shared_ptr<Context> ctx);

      /**
       * Create an object wrapper from a user-provided transient handle.
       *
       * Use this to wrap an externally created transient object handle
       * into a Botan::TPM2::Object instance. This is useful when the object
       * is created by the application and not by the Botan::TPM2 library.
       *
       * Note that this will take ownership of the ESYS_TR handle and will
       * release it when the object is destroyed.
       *
       * @param ctx    the TPM context to use
       * @param handle the transient handle to wrap
       */
      Object(std::shared_ptr<Context> ctx, ESYS_TR handle);

      virtual ~Object();
      Object(const Object&) = delete;
      Object& operator=(const Object&) = delete;
      Object(Object&& other) noexcept;
      Object& operator=(Object&& other) noexcept;

      const std::shared_ptr<Context>& context() const { return m_ctx; }

      bool has_persistent_handle() const;
      bool has_transient_handle() const;

      TPM2_HANDLE persistent_handle() const;
      ESYS_TR transient_handle() const noexcept;

      ObjectAttributes attributes(const SessionBundle& sessions) const;

      void _reset() noexcept;
      void _disengage() noexcept;
      PublicInfo& _public_info(const SessionBundle& sessions, std::optional<TPMI_ALG_PUBLIC> expected_type = {}) const;

   private:
      friend class ObjectSetter;
      ObjectHandles& handles();

      void flush() const noexcept;
      void scrub();

   private:
      std::shared_ptr<Context> m_ctx;
      std::unique_ptr<ObjectHandles> m_handles;
      mutable std::unique_ptr<PublicInfo> m_public_info;
};

}  // namespace Botan::TPM2

#endif
