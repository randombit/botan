/*
* HPKE KEMs from draft-ietf-hpke-pq
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HPKE_PQ_H_
#define BOTAN_HPKE_PQ_H_

#include <botan/internal/hpke_kem.h>

namespace Botan::HPKE {

/**
* Create the operations for one of the KEMs of draft-ietf-hpke-pq-05: ML-KEM
* (Section 3) or a hybrid of ML-KEM with an elliptic curve group (Section 4).
*
* Returns nullptr if @p kem is not such a KEM, or if the algorithms it
* requires are not available in this build.
*/
std::unique_ptr<const KEM_Ops> create_pq_kem_ops(KEM_Id kem);

}  // namespace Botan::HPKE

#endif
