/*
* TPM 2 Auth Session Wrapper
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#ifndef BOTAN_TPM2_SESSION_H_
#define BOTAN_TPM2_SESSION_H_

#include <botan/secmem.h>
#include <botan/tpm2_context.h>
#include <botan/tpm2_object.h>

#include <array>
#include <memory>

namespace Botan::TPM2 {

using TPMA_SESSION = uint8_t;

/**
 * See TPM 2.0 Part 2, Section 8.4
 */

struct SessionAttributes {
      static SessionAttributes read(TPMA_SESSION attributes);
      static TPMA_SESSION render(SessionAttributes attributes);

      /// The session may or may not remain active after the successful completion of any command.
      bool continue_session = false;

      /// Indicates that a command should only be executed if the session is exclusive.
      bool audit_exclusive = false;

      /// Indicates that the audit digest should be initialized and exclusive status of the session SET
      bool audit_reset = false;

      /// Indicates that the first parameter of the command is to be decrypted by the TPM
      bool decrypt = false;

      /// Indicates that the first parameter of a command's response is to be encrypted by the TPM
      bool encrypt = false;

      /// Indicates that the session is fused for audit and that audit_exclusive and audit_reset have meaning
      bool audit = false;
};

class Session;
class PrivateKey;

namespace detail {

/**
 * This wraps a Session object and ensures that the session's attributes are
 * restored to their original state after they have been modified by a (failing)
 * TSS2 library function.
 *
 * This is a workaround for the fact that TSS2 library calls may modify the
 * session's attributes and not reset them when the call fails.
 */
class BOTAN_UNSTABLE_API SessionHandle final {
   public:
      SessionHandle() = default;

      SessionHandle(const SessionHandle&) = delete;
      SessionHandle& operator=(const SessionHandle&) = delete;
      SessionHandle(SessionHandle&&) = delete;
      SessionHandle& operator=(SessionHandle&&) = delete;

      ~SessionHandle();
      [[nodiscard]] operator ESYS_TR() && noexcept;

   private:
      friend class Botan::TPM2::Session;

      SessionHandle(Session& session);

   private:
      std::optional<std::reference_wrapper<Session>> m_session;
      SessionAttributes m_original_attributes;
};

}  // namespace detail

class BOTAN_PUBLIC_API(3, 6) Session {
   public:
      /**
       * Instantiate an unauthenticated session that allows for the encryption
       * of sensitive parameters passed to and from the TPM. The application's
       * random salt is generated automatically (via the software RNG in the
       * TSS2's crypto backend).
       *
       * Note that such a session is not protected against man-in-the-middle
       * attacks with access to the data channel between the application and
       * the TPM.
       *
       * @param ctx       the TPM context
       * @param sym_algo  the symmetric algorithm used for parameter encryption
       * @param hash_algo the hash algorithm in the HMAC used for authentication
       */
      static std::shared_ptr<Session> unauthenticated_session(const std::shared_ptr<Context>& ctx,
                                                              std::string_view sym_algo = "CFB(AES-256)",
                                                              std::string_view hash_algo = "SHA-256");

      /**
       * Instantiate a session based on a salt encrypted for @p tpm_key. This
       * allows for the encryption of sensitive parameters passed to and from
       * the TPM. The application's random salt is generated automatically (via
       * the software RNG in the TSS2's crypto backend).
       *
       * Such a session is protected against man-in-the-middle attacks with
       * access to the data channel between the application and the TPM, under
       * the assumption that the @p tpm_key is not compromised.
       *
       * @param ctx       the TPM context
       * @param tpm_key   the key to use for session establishment
       * @param sym_algo  the symmetric algorithm used for parameter encryption
       * @param hash_algo the hash algorithm in the HMAC used for authentication
       */
      static std::shared_ptr<Session> authenticated_session(const std::shared_ptr<Context>& ctx,
                                                            const TPM2::PrivateKey& tpm_key,
                                                            std::string_view sym_algo = "CFB(AES-256)",
                                                            std::string_view hash_algo = "SHA-256");

   public:
      /**
       * Create a session object from a user-provided transient handle.
       *
       * Use this to wrap an externally created session handle into a
       * Botan::TPM2::Session instance to use it with the Botan::TPM2 library.
       *
       * Note that this will take ownership of the ESYS_TR handle and will
       * release it when the object is destroyed.
       *
       * @param ctx            the TPM context to use
       * @param session_handle the transient handle to wrap
       */
      Session(std::shared_ptr<Context> ctx, ESYS_TR session_handle) : m_session(std::move(ctx), session_handle) {}

      [[nodiscard]] detail::SessionHandle handle() { return *this; }

      SessionAttributes attributes() const;
      void set_attributes(SessionAttributes attributes);

      secure_vector<uint8_t> tpm_nonce() const;

   private:
      friend class detail::SessionHandle;

      Session(Object session, SessionAttributes attributes);

      ESYS_TR transient_handle() const noexcept { return m_session.transient_handle(); }

   private:
      Object m_session;
};

inline detail::SessionHandle::~SessionHandle() {
   if(m_session) {
      m_session->get().set_attributes(m_original_attributes);
   }
}

inline detail::SessionHandle::SessionHandle(Session& session) :
      m_session(session), m_original_attributes(session.attributes()) {}

/**
 * This bundles up to three sessions into a single object to be used in a
 * single TSS2 library function call to simplify passing the sessions around
 * internally.
 */
class SessionBundle {
   public:
      SessionBundle(std::shared_ptr<Session> s1 = nullptr,
                    std::shared_ptr<Session> s2 = nullptr,
                    std::shared_ptr<Session> s3 = nullptr) :
            m_sessions({std::move(s1), std::move(s2), std::move(s3)}) {}

      [[nodiscard]] detail::SessionHandle operator[](size_t i) const noexcept {
         if(m_sessions[i] == nullptr) {
            return {};
         } else {
            return m_sessions[i]->handle();
         }
      }

   private:
      std::array<std::shared_ptr<Session>, 3> m_sessions;
};

}  // namespace Botan::TPM2

#endif
