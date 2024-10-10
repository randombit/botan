/*
* TPM 2.0 Base Object handling
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_object.h>

#include <botan/tpm2_session.h>

#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_util.h>

#include <tss2/tss2_esys.h>

namespace Botan::TPM2 {

namespace {

using ObjectAttributesWrapper =
   AttributeWrapper<TPMA_OBJECT,
                    ObjectAttributes,
                    PropMap{&ObjectAttributes::fixed_tpm, TPMA_OBJECT_FIXEDTPM},
                    PropMap{&ObjectAttributes::st_clear, TPMA_OBJECT_STCLEAR},
                    PropMap{&ObjectAttributes::fixed_parent, TPMA_OBJECT_FIXEDPARENT},
                    PropMap{&ObjectAttributes::sensitive_data_origin, TPMA_OBJECT_SENSITIVEDATAORIGIN},
                    PropMap{&ObjectAttributes::user_with_auth, TPMA_OBJECT_USERWITHAUTH},
                    PropMap{&ObjectAttributes::admin_with_policy, TPMA_OBJECT_ADMINWITHPOLICY},
                    PropMap{&ObjectAttributes::no_da, TPMA_OBJECT_NODA},
                    PropMap{&ObjectAttributes::encrypted_duplication, TPMA_OBJECT_ENCRYPTEDDUPLICATION},
                    PropMap{&ObjectAttributes::restricted, TPMA_OBJECT_RESTRICTED},
                    PropMap{&ObjectAttributes::decrypt, TPMA_OBJECT_DECRYPT},
                    PropMap{&ObjectAttributes::sign_encrypt, TPMA_OBJECT_SIGN_ENCRYPT},
                    PropMap{&ObjectAttributes::x509sign, TPMA_OBJECT_X509SIGN}>;

}  // namespace

ObjectAttributes ObjectAttributes::read(TPMA_OBJECT attributes) {
   return ObjectAttributesWrapper::read(attributes);
}

TPMA_OBJECT ObjectAttributes::render(ObjectAttributes attributes) {
   return ObjectAttributesWrapper::render(attributes);
}

Object::Object(std::shared_ptr<Context> ctx) : m_ctx(std::move(ctx)), m_handles(std::make_unique<ObjectHandles>()) {
   BOTAN_ASSERT_NONNULL(m_ctx);
}

Object::Object(std::shared_ptr<Context> ctx, ESYS_TR handle) : Object(std::move(ctx)) {
   m_handles->transient = handle;
}

Object::Object(Object&& other) noexcept :
      m_ctx(std::move(other.m_ctx)),
      m_handles(std::move(other.m_handles)),
      m_public_info(std::move(other.m_public_info)) {
   other.scrub();
}

Object::~Object() {
   if(m_handles) {
      flush();
   }
}

Object& Object::operator=(Object&& other) noexcept {
   if(this != &other) {
      flush();
      m_ctx = std::move(other.m_ctx);
      m_handles = std::move(other.m_handles);
      m_public_info = std::move(other.m_public_info);
      other.scrub();
   }
   return *this;
}

/// Flush the object's TPM handles as necessary
void Object::flush() const noexcept {
   // Only purely transient objects have to be flushed
   if(has_transient_handle()) {
      if(has_persistent_handle()) {
         Esys_TR_Close(*m_ctx, &m_handles->transient);
      } else {
         Esys_FlushContext(*m_ctx, m_handles->transient);
      }
   }
}

/// Destroy the object's internal state, making the destructor a no-op.
/// No more operations except the destructor must be performed on that object.
void Object::scrub() {
   m_ctx.reset();
   m_handles.reset();
   m_public_info.reset();
}

/// Flush the object's TPM handles and reset its internal state
void Object::_reset() noexcept {
   flush();
   _disengage();
}

/// Reset the object's internal state without flushing its TPM handles
void Object::_disengage() noexcept {
   m_handles = std::make_unique<ObjectHandles>();
   m_public_info.reset();
}

bool Object::has_persistent_handle() const {
   return m_handles->persistent.has_value();
}

bool Object::has_transient_handle() const {
   return m_handles->transient != ESYS_TR_NONE;
}

TPM2_HANDLE Object::persistent_handle() const {
   BOTAN_STATE_CHECK(has_persistent_handle());
   return *m_handles->persistent;
}

ESYS_TR Object::transient_handle() const noexcept {
   return m_handles->transient;
}

ObjectAttributes Object::attributes(const SessionBundle& sessions) const {
   const auto attrs = _public_info(sessions).pub->publicArea.objectAttributes;
   return ObjectAttributes::read(attrs);
}

PublicInfo& Object::_public_info(const SessionBundle& sessions, std::optional<TPMI_ALG_PUBLIC> expected_type) const {
   if(!m_public_info) {
      m_public_info = std::make_unique<PublicInfo>();

      check_rc("Esys_ReadPublic",
               Esys_ReadPublic(*m_ctx,
                               m_handles->transient,
                               sessions[0],
                               sessions[1],
                               sessions[2],
                               out_ptr(m_public_info->pub),
                               out_ptr(m_public_info->name),
                               out_ptr(m_public_info->qualified_name)));
      BOTAN_ASSERT_NONNULL(m_public_info->pub);

      if(expected_type) {
         BOTAN_STATE_CHECK(m_public_info->pub->publicArea.type == *expected_type);
      }
   }

   return *m_public_info;
}

ObjectHandles& Object::handles() {
   return *m_handles;
}

}  // namespace Botan::TPM2
