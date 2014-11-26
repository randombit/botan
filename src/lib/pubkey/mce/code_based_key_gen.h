
/**
 * (C) Copyright Projet SECRET, INRIA, Rocquencourt
 * (C) Bhaskar Biswas and  Nicolas Sendrier
 *
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 *
 * Distributed under the terms of the Botan license
 *
 */
#ifndef __code_based_key_gen__H_
#define __code_based_key_gen__H_

#include <botan/mceliece_key.h>

namespace Botan {

McEliece_PrivateKey generate_mceliece_key(RandomNumberGenerator &rng,
                                          u32bit ext_deg,
                                          u32bit code_length,
                                          u32bit t);

}

#endif
