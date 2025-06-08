/*
 * Stateless Hash-Based Digital Signature Standard
 *
 * (C) 2024 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_SLH_DSA_H_
#define BOTAN_SLH_DSA_H_

// This is a bridge into a future where we don't support SPHINCS+ anymore to
// keep the API stable for users of the SHPINCS+ algorithm. We recommend new
// users to use the type-aliases declared in this header as the SPHINCS+ API
// might be deprecated and eventually removed in future releases.

#include <botan/sphincsplus.h>

namespace Botan {

#if defined(BOTAN_HAS_SLH_DSA_WITH_SHA2) || defined(BOTAN_HAS_SLH_DSA_WITH_SHAKE)

using SLH_DSA_Parameter_Set = Sphincs_Parameter_Set;
using SLH_DSA_Hash_Type = Sphincs_Hash_Type;
using SLH_DSA_Parameters = Sphincs_Parameters;

using SLH_DSA_PublicKey = SphincsPlus_PublicKey;
using SLH_DSA_PrivateKey = SphincsPlus_PrivateKey;

#endif

}  // namespace Botan

#endif
