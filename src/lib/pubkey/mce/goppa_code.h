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

#ifndef __goppa_code__H_
#define __goppa_code__H_

#include <botan/polyn_gf2m.h>
#include <botan/mceliece_key.h>



namespace Botan
{

  std::vector<byte> mceliece_encrypt( const secure_vector<byte> & cleartext, std::vector<byte> const& public_matrix, const secure_vector<gf2m> & err_pos, u32bit code_length);


secure_vector<byte> mceliece_decrypt(
    secure_vector<gf2m> & error_pos,
    const byte *ciphertext, u32bit ciphertext_len,
    const McEliece_PrivateKey & key);
} //end namepace Botan

#endif /* h-guard */
