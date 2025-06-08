/*
* TPM 2 Auth Session Wrapper
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2_session.h>

#include <botan/tpm2_key.h>

#include <botan/internal/stl_util.h>
#include <botan/internal/tpm2_algo_mappings.h>
#include <botan/internal/tpm2_util.h>

namespace Botan::TPM2 {

namespace {

using SessionAttributesWrapper =
   AttributeWrapper<TPMA_SESSION,
                    SessionAttributes,
                    PropMap{&SessionAttributes::continue_session, TPMA_SESSION_CONTINUESESSION},
                    PropMap{&SessionAttributes::audit_exclusive, TPMA_SESSION_AUDITEXCLUSIVE},
                    PropMap{&SessionAttributes::audit_reset, TPMA_SESSION_AUDITRESET},
                    PropMap{&SessionAttributes::decrypt, TPMA_SESSION_DECRYPT},
                    PropMap{&SessionAttributes::encrypt, TPMA_SESSION_ENCRYPT},
                    PropMap{&SessionAttributes::audit, TPMA_SESSION_AUDIT}>;

}  // namespace

SessionAttributes SessionAttributes::read(TPMA_SESSION attributes) {
   return SessionAttributesWrapper::read(attributes);
}

TPMA_SESSION SessionAttributes::render(SessionAttributes attributes) {
   return SessionAttributesWrapper::render(attributes);
}

// static
std::shared_ptr<Session> Session::unauthenticated_session(const std::shared_ptr<Context>& ctx,
                                                          std::string_view sym_algo,
                                                          std::string_view hash_algo) {
   Object session(ctx);
   const auto auth_sym = get_tpm2_sym_cipher_spec(sym_algo);
   const auto auth_hash_algo = get_tpm2_hash_type(hash_algo);

   BOTAN_ASSERT_NONNULL(ctx);

   check_rc("Esys_StartSession",
            Esys_StartAuthSession(*ctx,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  nullptr /*NonceCaller generated automatically*/,
                                  TPM2_SE_HMAC,
                                  &auth_sym,
                                  auth_hash_algo,
                                  out_transient_handle(session)));

   return std::shared_ptr<Session>(new Session(std::move(session),
                                               {
                                                  .continue_session = true,
                                                  .decrypt = true,
                                                  .encrypt = true,
                                               }));
}

std::shared_ptr<Session> Session::authenticated_session(const std::shared_ptr<Context>& ctx,
                                                        const TPM2::PrivateKey& tpm_key,
                                                        std::string_view sym_algo,
                                                        std::string_view hash_algo) {
   Object session(ctx);
   const auto auth_sym = get_tpm2_sym_cipher_spec(sym_algo);
   const auto auth_hash_algo = get_tpm2_hash_type(hash_algo);

   BOTAN_ASSERT_NONNULL(ctx);

   check_rc("Esys_StartSession",
            Esys_StartAuthSession(*ctx,
                                  tpm_key.handles().transient_handle(),
                                  tpm_key.handles().transient_handle(),
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  ESYS_TR_NONE,
                                  nullptr /*NonceCaller generated automatically*/,
                                  TPM2_SE_HMAC,
                                  &auth_sym,
                                  auth_hash_algo,
                                  out_transient_handle(session)));

   return std::shared_ptr<Session>(new Session(std::move(session),
                                               {
                                                  .continue_session = true,
                                                  .decrypt = true,
                                                  .encrypt = true,
                                               }));
}

Session::Session(Object session, SessionAttributes attributes) : m_session(std::move(session)) {
   set_attributes(attributes);
}

SessionAttributes Session::attributes() const {
   TPMA_SESSION attrs;
   check_rc("Esys_TRSess_GetAttributes",
            Esys_TRSess_GetAttributes(*m_session.context(), m_session.transient_handle(), &attrs));
   return SessionAttributes::read(attrs);
}

void Session::set_attributes(SessionAttributes attributes) {
   check_rc("Esys_TRSess_SetAttributes",
            Esys_TRSess_SetAttributes(
               *m_session.context(), m_session.transient_handle(), SessionAttributes::render(attributes), 0xFF));
}

secure_vector<uint8_t> Session::tpm_nonce() const {
   unique_esys_ptr<TPM2B_NONCE> nonce;
   check_rc("Esys_TRSess_GetNonceTPM",
            Esys_TRSess_GetNonceTPM(*m_session.context(), m_session.transient_handle(), out_ptr(nonce)));
   return copy_into<secure_vector<uint8_t>>(*nonce);
}

[[nodiscard]] detail::SessionHandle::operator ESYS_TR() && noexcept {
   if(m_session) {
      return m_session->get().transient_handle();
   } else {
      return ESYS_TR_NONE;
   }
}

}  // namespace Botan::TPM2
