/*
* KDF defined in NIST SP 800-56a revision 2 (Single-step key-derivation function)
* (C) 2016 Krzysztof Kwiatkowski
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SP800_56A_H__
#define BOTAN_SP800_56A_H__

#include <botan/kdf.h>

namespace Botan {

/**
 * NIST SP 800-56A KDF
 */
template<class AuxiliaryFunction_t>
class BOTAN_DLL SP800_56A final : public KDF
   {
   public:
      std::string name() const override { return "SP800-56A(" + m_auxfunc->name() + ")"; }

      KDF* clone() const override { return new SP800_56A(m_auxfunc->clone()); }

      /**
      * Derive a key using the SP800-56A KDF.
      *
      * The implementation hard codes the context value for the
      * expansion step to the empty string.
      *
      * @param key derived keying material K_M
      * @param key_len the desired output length in bytes
      * @param secret shared secret Z
      * @param secret_len size of Z in bytes
      * @param salt salt used only if HMAC is used as a hash function
      * @param salt_len not used by an algorithm
      * @param label label for the expansion step
      * @param label_len size of label in bytes
      *
      * @throws Invalid_Argument key_len > 2^32 or MAC is not a HMAC
      */
      size_t kdf(uint8_t key[], size_t key_len,
                 const uint8_t secret[], size_t secret_len,
                 const uint8_t salt[], size_t salt_len,
                 const uint8_t label[], size_t label_len) const override;

      /**
      * @param auxfunc HASH or HMAC algorithm to be used as auxiliary function
      */
      explicit SP800_56A(AuxiliaryFunction_t* auxfunc) : m_auxfunc(auxfunc) {}
   private:
      std::unique_ptr<AuxiliaryFunction_t> m_auxfunc;
   };
}

#endif
