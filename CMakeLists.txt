# This camke is not intended to be used as botan default build or install system.
# For this purpose please use configure.py followed by make.
#
# However many modern IDE work well with camke and enable a lot of features for
# cmake based projects, so this cmake is introduced to make development process
# easier for these who like them.
#
# Current cmake configuration is based on that what configure.py generated for
# Mac OS X target with clang compiler when invoked without any additional options.

cmake_minimum_required(VERSION 3.0.0)
project(botan VERSION "2.0.1" LANGUAGES CXX)

option(BOTAN_I_KNOW_WHAT_IM_DOING_SO_GENTLY_PLEASE_NOT_STOP_ME "Enable this flag only if you are sure that you use cmake only for development reasons" OFF)
if(NOT BOTAN_I_KNOW_WHAT_IM_DOING_SO_GENTLY_PLEASE_NOT_STOP_ME)
    message(FATAL_ERROR "You shouldn't use cmake to build release version of botan."
                        "Instead use: configure.py -> make.")
endif()

set(BOTAN_SOURCES_DIR src/lib)
set(BOTAN_SOURCES
    ${BOTAN_SOURCES_DIR}/asn1/alg_id.cpp
    ${BOTAN_SOURCES_DIR}/asn1/asn1_alt_name.cpp
    ${BOTAN_SOURCES_DIR}/asn1/asn1_attribute.cpp
    ${BOTAN_SOURCES_DIR}/asn1/asn1_obj.cpp
    ${BOTAN_SOURCES_DIR}/asn1/asn1_oid.cpp
    ${BOTAN_SOURCES_DIR}/asn1/asn1_str.cpp
    ${BOTAN_SOURCES_DIR}/asn1/asn1_time.cpp
    ${BOTAN_SOURCES_DIR}/asn1/ber_dec.cpp
    ${BOTAN_SOURCES_DIR}/asn1/der_enc.cpp
    ${BOTAN_SOURCES_DIR}/asn1/oids.cpp
    ${BOTAN_SOURCES_DIR}/asn1/x509_dn.cpp
    ${BOTAN_SOURCES_DIR}/base/scan_name.cpp
    ${BOTAN_SOURCES_DIR}/base/symkey.cpp
    ${BOTAN_SOURCES_DIR}/block/aes/aes.cpp
    ${BOTAN_SOURCES_DIR}/block/aes/aes_ni/aes_ni.cpp
    ${BOTAN_SOURCES_DIR}/block/aes/aes_ssse3/aes_ssse3.cpp
    ${BOTAN_SOURCES_DIR}/block/block_cipher.cpp
    ${BOTAN_SOURCES_DIR}/block/blowfish/blowfish.cpp
    ${BOTAN_SOURCES_DIR}/block/camellia/camellia.cpp
    ${BOTAN_SOURCES_DIR}/block/cascade/cascade.cpp
    ${BOTAN_SOURCES_DIR}/block/cast/cast128.cpp
    ${BOTAN_SOURCES_DIR}/block/cast/cast256.cpp
    ${BOTAN_SOURCES_DIR}/block/des/des.cpp
    ${BOTAN_SOURCES_DIR}/block/des/des_tab.cpp
    ${BOTAN_SOURCES_DIR}/block/des/desx.cpp
    ${BOTAN_SOURCES_DIR}/block/gost_28147/gost_28147.cpp
    ${BOTAN_SOURCES_DIR}/block/idea/idea.cpp
    ${BOTAN_SOURCES_DIR}/block/idea/idea_sse2/idea_sse2.cpp
    ${BOTAN_SOURCES_DIR}/block/kasumi/kasumi.cpp
    ${BOTAN_SOURCES_DIR}/block/lion/lion.cpp
    ${BOTAN_SOURCES_DIR}/block/misty1/misty1.cpp
    ${BOTAN_SOURCES_DIR}/block/noekeon/noekeon.cpp
    ${BOTAN_SOURCES_DIR}/block/noekeon/noekeon_simd/noekeon_simd.cpp
    ${BOTAN_SOURCES_DIR}/block/seed/seed.cpp
    ${BOTAN_SOURCES_DIR}/block/serpent/serpent.cpp
    ${BOTAN_SOURCES_DIR}/block/serpent/serpent_simd/serpent_simd.cpp
    ${BOTAN_SOURCES_DIR}/block/threefish/threefish.cpp
    ${BOTAN_SOURCES_DIR}/block/threefish/threefish_avx2/threefish_avx2.cpp
    ${BOTAN_SOURCES_DIR}/block/twofish/twofish.cpp
    ${BOTAN_SOURCES_DIR}/block/twofish/twofish_tab.cpp
    ${BOTAN_SOURCES_DIR}/block/xtea/xtea.cpp
    ${BOTAN_SOURCES_DIR}/codec/base64/base64.cpp
    ${BOTAN_SOURCES_DIR}/codec/hex/hex.cpp
    ${BOTAN_SOURCES_DIR}/entropy/darwin_secrandom/darwin_secrandom.cpp
    ${BOTAN_SOURCES_DIR}/entropy/dev_random/dev_random.cpp
    ${BOTAN_SOURCES_DIR}/entropy/entropy_srcs.cpp
    ${BOTAN_SOURCES_DIR}/entropy/proc_walk/proc_walk.cpp
    ${BOTAN_SOURCES_DIR}/entropy/rdrand/rdrand.cpp
    ${BOTAN_SOURCES_DIR}/entropy/rdseed/rdseed.cpp
    ${BOTAN_SOURCES_DIR}/ffi/ffi.cpp
    ${BOTAN_SOURCES_DIR}/filters/algo_filt.cpp
    ${BOTAN_SOURCES_DIR}/filters/basefilt.cpp
    ${BOTAN_SOURCES_DIR}/filters/buf_filt.cpp
    ${BOTAN_SOURCES_DIR}/filters/cipher_filter.cpp
    ${BOTAN_SOURCES_DIR}/filters/codec_filt/b64_filt.cpp
    ${BOTAN_SOURCES_DIR}/filters/codec_filt/hex_filt.cpp
    ${BOTAN_SOURCES_DIR}/filters/comp_filter.cpp
    ${BOTAN_SOURCES_DIR}/filters/data_snk.cpp
    ${BOTAN_SOURCES_DIR}/filters/fd_unix/fd_unix.cpp
    ${BOTAN_SOURCES_DIR}/filters/filter.cpp
    ${BOTAN_SOURCES_DIR}/filters/key_filt.cpp
    ${BOTAN_SOURCES_DIR}/filters/out_buf.cpp
    ${BOTAN_SOURCES_DIR}/filters/pipe.cpp
    ${BOTAN_SOURCES_DIR}/filters/pipe_io.cpp
    ${BOTAN_SOURCES_DIR}/filters/pipe_rw.cpp
    ${BOTAN_SOURCES_DIR}/filters/secqueue.cpp
    ${BOTAN_SOURCES_DIR}/filters/threaded_fork.cpp
    ${BOTAN_SOURCES_DIR}/hash/blake2/blake2b.cpp
    ${BOTAN_SOURCES_DIR}/hash/checksum/adler32/adler32.cpp
    ${BOTAN_SOURCES_DIR}/hash/checksum/crc24/crc24.cpp
    ${BOTAN_SOURCES_DIR}/hash/checksum/crc32/crc32.cpp
    ${BOTAN_SOURCES_DIR}/hash/comb4p/comb4p.cpp
    ${BOTAN_SOURCES_DIR}/hash/gost_3411/gost_3411.cpp
    ${BOTAN_SOURCES_DIR}/hash/hash.cpp
    ${BOTAN_SOURCES_DIR}/hash/keccak/keccak.cpp
    ${BOTAN_SOURCES_DIR}/hash/md4/md4.cpp
    ${BOTAN_SOURCES_DIR}/hash/md5/md5.cpp
    ${BOTAN_SOURCES_DIR}/hash/mdx_hash/mdx_hash.cpp
    ${BOTAN_SOURCES_DIR}/hash/par_hash/par_hash.cpp
    ${BOTAN_SOURCES_DIR}/hash/rmd160/rmd160.cpp
    ${BOTAN_SOURCES_DIR}/hash/sha1/sha160.cpp
    ${BOTAN_SOURCES_DIR}/hash/sha1/sha1_sse2/sha1_sse2.cpp
    ${BOTAN_SOURCES_DIR}/hash/sha2_32/sha2_32.cpp
    ${BOTAN_SOURCES_DIR}/hash/sha2_64/sha2_64.cpp
    ${BOTAN_SOURCES_DIR}/hash/sha3/sha3.cpp
    ${BOTAN_SOURCES_DIR}/hash/shake/shake.cpp
    ${BOTAN_SOURCES_DIR}/hash/skein/skein_512.cpp
    ${BOTAN_SOURCES_DIR}/hash/tiger/tig_tab.cpp
    ${BOTAN_SOURCES_DIR}/hash/tiger/tiger.cpp
    ${BOTAN_SOURCES_DIR}/hash/whirlpool/whirlpool.cpp
    ${BOTAN_SOURCES_DIR}/hash/whirlpool/whrl_tab.cpp
    ${BOTAN_SOURCES_DIR}/kdf/hkdf/hkdf.cpp
    ${BOTAN_SOURCES_DIR}/kdf/kdf.cpp
    ${BOTAN_SOURCES_DIR}/kdf/kdf1/kdf1.cpp
    ${BOTAN_SOURCES_DIR}/kdf/kdf1_iso18033/kdf1_iso18033.cpp
    ${BOTAN_SOURCES_DIR}/kdf/kdf2/kdf2.cpp
    ${BOTAN_SOURCES_DIR}/kdf/prf_tls/prf_tls.cpp
    ${BOTAN_SOURCES_DIR}/kdf/prf_x942/prf_x942.cpp
    ${BOTAN_SOURCES_DIR}/kdf/sp800_108/sp800_108.cpp
    ${BOTAN_SOURCES_DIR}/kdf/sp800_56c/sp800_56c.cpp
    ${BOTAN_SOURCES_DIR}/mac/cbc_mac/cbc_mac.cpp
    ${BOTAN_SOURCES_DIR}/mac/cmac/cmac.cpp
    ${BOTAN_SOURCES_DIR}/mac/gmac/gmac.cpp
    ${BOTAN_SOURCES_DIR}/mac/hmac/hmac.cpp
    ${BOTAN_SOURCES_DIR}/mac/mac.cpp
    ${BOTAN_SOURCES_DIR}/mac/poly1305/poly1305.cpp
    ${BOTAN_SOURCES_DIR}/mac/siphash/siphash.cpp
    ${BOTAN_SOURCES_DIR}/mac/x919_mac/x919_mac.cpp
    ${BOTAN_SOURCES_DIR}/math/bigint/big_code.cpp
    ${BOTAN_SOURCES_DIR}/math/bigint/big_io.cpp
    ${BOTAN_SOURCES_DIR}/math/bigint/big_ops2.cpp
    ${BOTAN_SOURCES_DIR}/math/bigint/big_ops3.cpp
    ${BOTAN_SOURCES_DIR}/math/bigint/big_rand.cpp
    ${BOTAN_SOURCES_DIR}/math/bigint/bigint.cpp
    ${BOTAN_SOURCES_DIR}/math/bigint/divide.cpp
    ${BOTAN_SOURCES_DIR}/math/ec_gfp/curve_gfp.cpp
    ${BOTAN_SOURCES_DIR}/math/ec_gfp/curve_nistp.cpp
    ${BOTAN_SOURCES_DIR}/math/ec_gfp/point_gfp.cpp
    ${BOTAN_SOURCES_DIR}/math/mp/mp_comba.cpp
    ${BOTAN_SOURCES_DIR}/math/mp/mp_core.cpp
    ${BOTAN_SOURCES_DIR}/math/mp/mp_karat.cpp
    ${BOTAN_SOURCES_DIR}/math/mp/mp_monty.cpp
    ${BOTAN_SOURCES_DIR}/math/numbertheory/dsa_gen.cpp
    ${BOTAN_SOURCES_DIR}/math/numbertheory/jacobi.cpp
    ${BOTAN_SOURCES_DIR}/math/numbertheory/make_prm.cpp
    ${BOTAN_SOURCES_DIR}/math/numbertheory/mp_numth.cpp
    ${BOTAN_SOURCES_DIR}/math/numbertheory/numthry.cpp
    ${BOTAN_SOURCES_DIR}/math/numbertheory/pow_mod.cpp
    ${BOTAN_SOURCES_DIR}/math/numbertheory/powm_fw.cpp
    ${BOTAN_SOURCES_DIR}/math/numbertheory/powm_mnt.cpp
    ${BOTAN_SOURCES_DIR}/math/numbertheory/primes.cpp
    ${BOTAN_SOURCES_DIR}/math/numbertheory/reducer.cpp
    ${BOTAN_SOURCES_DIR}/math/numbertheory/ressol.cpp
    ${BOTAN_SOURCES_DIR}/misc/aont/package.cpp
    ${BOTAN_SOURCES_DIR}/misc/cryptobox/cryptobox.cpp
    ${BOTAN_SOURCES_DIR}/misc/fpe_fe1/fpe_fe1.cpp
    ${BOTAN_SOURCES_DIR}/misc/rfc3394/rfc3394.cpp
    ${BOTAN_SOURCES_DIR}/misc/srp6/srp6.cpp
    ${BOTAN_SOURCES_DIR}/misc/tss/tss.cpp
    ${BOTAN_SOURCES_DIR}/modes/aead/aead.cpp
    ${BOTAN_SOURCES_DIR}/modes/aead/ccm/ccm.cpp
    ${BOTAN_SOURCES_DIR}/modes/aead/chacha20poly1305/chacha20poly1305.cpp
    ${BOTAN_SOURCES_DIR}/modes/aead/eax/eax.cpp
    ${BOTAN_SOURCES_DIR}/modes/aead/gcm/clmul/clmul.cpp
    ${BOTAN_SOURCES_DIR}/modes/aead/gcm/gcm.cpp
    ${BOTAN_SOURCES_DIR}/modes/aead/ocb/ocb.cpp
    ${BOTAN_SOURCES_DIR}/modes/aead/siv/siv.cpp
    ${BOTAN_SOURCES_DIR}/modes/cbc/cbc.cpp
    ${BOTAN_SOURCES_DIR}/modes/cfb/cfb.cpp
    ${BOTAN_SOURCES_DIR}/modes/cipher_mode.cpp
    ${BOTAN_SOURCES_DIR}/modes/mode_pad/mode_pad.cpp
    ${BOTAN_SOURCES_DIR}/modes/xts/xts.cpp
    ${BOTAN_SOURCES_DIR}/passhash/bcrypt/bcrypt.cpp
    ${BOTAN_SOURCES_DIR}/passhash/passhash9/passhash9.cpp
    ${BOTAN_SOURCES_DIR}/pbkdf/pbkdf.cpp
    ${BOTAN_SOURCES_DIR}/pbkdf/pbkdf1/pbkdf1.cpp
    ${BOTAN_SOURCES_DIR}/pbkdf/pbkdf2/pbkdf2.cpp
    ${BOTAN_SOURCES_DIR}/pk_pad/eme.cpp
    ${BOTAN_SOURCES_DIR}/pk_pad/eme_oaep/oaep.cpp
    ${BOTAN_SOURCES_DIR}/pk_pad/eme_pkcs1/eme_pkcs.cpp
    ${BOTAN_SOURCES_DIR}/pk_pad/eme_raw/eme_raw.cpp
    ${BOTAN_SOURCES_DIR}/pk_pad/emsa.cpp
    ${BOTAN_SOURCES_DIR}/pk_pad/emsa1/emsa1.cpp
    ${BOTAN_SOURCES_DIR}/pk_pad/emsa_pkcs1/emsa_pkcs1.cpp
    ${BOTAN_SOURCES_DIR}/pk_pad/emsa_pssr/pssr.cpp
    ${BOTAN_SOURCES_DIR}/pk_pad/emsa_raw/emsa_raw.cpp
    ${BOTAN_SOURCES_DIR}/pk_pad/emsa_x931/emsa_x931.cpp
    ${BOTAN_SOURCES_DIR}/pk_pad/hash_id/hash_id.cpp
    ${BOTAN_SOURCES_DIR}/pk_pad/iso9796/iso9796.cpp
    ${BOTAN_SOURCES_DIR}/pk_pad/mgf1/mgf1.cpp
    ${BOTAN_SOURCES_DIR}/prov/pkcs11/p11.cpp
    ${BOTAN_SOURCES_DIR}/prov/pkcs11/p11_ecc_key.cpp
    ${BOTAN_SOURCES_DIR}/prov/pkcs11/p11_ecdh.cpp
    ${BOTAN_SOURCES_DIR}/prov/pkcs11/p11_ecdsa.cpp
    ${BOTAN_SOURCES_DIR}/prov/pkcs11/p11_mechanism.cpp
    ${BOTAN_SOURCES_DIR}/prov/pkcs11/p11_module.cpp
    ${BOTAN_SOURCES_DIR}/prov/pkcs11/p11_object.cpp
    ${BOTAN_SOURCES_DIR}/prov/pkcs11/p11_randomgenerator.cpp
    ${BOTAN_SOURCES_DIR}/prov/pkcs11/p11_rsa.cpp
    ${BOTAN_SOURCES_DIR}/prov/pkcs11/p11_session.cpp
    ${BOTAN_SOURCES_DIR}/prov/pkcs11/p11_slot.cpp
    ${BOTAN_SOURCES_DIR}/prov/pkcs11/p11_x509.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/blinding.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/cecpq1/cecpq1.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/curve25519/curve25519.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/curve25519/donna.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/dh/dh.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/dl_algo/dl_algo.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/dl_group/dl_group.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/dl_group/dl_named.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/dlies/dlies.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/dsa/dsa.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/ec_group/ec_group.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/ec_group/ec_named.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/ecc_key/ecc_key.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/ecdh/ecdh.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/ecdsa/ecdsa.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/ecgdsa/ecgdsa.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/ecies/ecies.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/eckcdsa/eckcdsa.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/elgamal/elgamal.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/gost_3410/gost_3410.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/keypair/keypair.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/mce/code_based_key_gen.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/mce/gf2m_rootfind_dcmp.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/mce/gf2m_small_m.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/mce/goppa_code.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/mce/mce_workfactor.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/mce/mceliece.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/mce/mceliece_key.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/mce/polyn_gf2m.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/mceies/mceies.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/newhope/newhope.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/pbes2/pbes2.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/pem/pem.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/pk_algs.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/pk_keys.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/pk_ops.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/pkcs8.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/pubkey.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/rfc6979/rfc6979.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/rsa/rsa.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/workfactor.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/x509_key.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/xmss/xmss_common_ops.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/xmss/xmss_hash.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/xmss/xmss_index_registry.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/xmss/xmss_parameters.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/xmss/xmss_privatekey.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/xmss/xmss_publickey.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/xmss/xmss_signature.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/xmss/xmss_signature_operation.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/xmss/xmss_verification_operation.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/xmss/xmss_wots_common_ops.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/xmss/xmss_wots_parameters.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/xmss/xmss_wots_privatekey.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/xmss/xmss_wots_publickey.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/xmss/xmss_wots_signature_operation.cpp
    ${BOTAN_SOURCES_DIR}/pubkey/xmss/xmss_wots_verification_operation.cpp
    ${BOTAN_SOURCES_DIR}/rng/auto_rng/auto_rng.cpp
    ${BOTAN_SOURCES_DIR}/rng/hmac_drbg/hmac_drbg.cpp
    ${BOTAN_SOURCES_DIR}/rng/rdrand_rng/rdrand_rng.cpp
    ${BOTAN_SOURCES_DIR}/rng/rng.cpp
    ${BOTAN_SOURCES_DIR}/rng/stateful_rng/stateful_rng.cpp
    ${BOTAN_SOURCES_DIR}/rng/system_rng/system_rng.cpp
    ${BOTAN_SOURCES_DIR}/stream/chacha/chacha.cpp
    ${BOTAN_SOURCES_DIR}/stream/chacha/chacha_sse2/chacha_sse2.cpp
    ${BOTAN_SOURCES_DIR}/stream/ctr/ctr.cpp
    ${BOTAN_SOURCES_DIR}/stream/ofb/ofb.cpp
    ${BOTAN_SOURCES_DIR}/stream/rc4/rc4.cpp
    ${BOTAN_SOURCES_DIR}/stream/salsa20/salsa20.cpp
    ${BOTAN_SOURCES_DIR}/stream/shake_cipher/shake_cipher.cpp
    ${BOTAN_SOURCES_DIR}/stream/stream_cipher.cpp
    ${BOTAN_SOURCES_DIR}/tls/credentials_manager.cpp
    ${BOTAN_SOURCES_DIR}/tls/msg_cert_req.cpp
    ${BOTAN_SOURCES_DIR}/tls/msg_cert_status.cpp
    ${BOTAN_SOURCES_DIR}/tls/msg_cert_verify.cpp
    ${BOTAN_SOURCES_DIR}/tls/msg_certificate.cpp
    ${BOTAN_SOURCES_DIR}/tls/msg_client_hello.cpp
    ${BOTAN_SOURCES_DIR}/tls/msg_client_kex.cpp
    ${BOTAN_SOURCES_DIR}/tls/msg_finished.cpp
    ${BOTAN_SOURCES_DIR}/tls/msg_hello_verify.cpp
    ${BOTAN_SOURCES_DIR}/tls/msg_server_hello.cpp
    ${BOTAN_SOURCES_DIR}/tls/msg_server_kex.cpp
    ${BOTAN_SOURCES_DIR}/tls/msg_session_ticket.cpp
    ${BOTAN_SOURCES_DIR}/tls/sessions_sql/tls_session_manager_sql.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_alert.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_blocking.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_callbacks.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_cbc/tls_cbc.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_channel.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_ciphersuite.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_client.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_extensions.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_handshake_hash.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_handshake_io.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_handshake_state.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_policy.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_record.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_server.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_session.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_session_key.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_session_manager_memory.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_suite_info.cpp
    ${BOTAN_SOURCES_DIR}/tls/tls_version.cpp
    ${BOTAN_SOURCES_DIR}/utils/assert.cpp
    ${BOTAN_SOURCES_DIR}/utils/barrier.cpp
    ${BOTAN_SOURCES_DIR}/utils/calendar.cpp
    ${BOTAN_SOURCES_DIR}/utils/charset.cpp
    ${BOTAN_SOURCES_DIR}/utils/cpuid.cpp
    ${BOTAN_SOURCES_DIR}/utils/data_src.cpp
    ${BOTAN_SOURCES_DIR}/utils/dyn_load/dyn_load.cpp
    ${BOTAN_SOURCES_DIR}/utils/filesystem.cpp
    ${BOTAN_SOURCES_DIR}/utils/http_util/http_util.cpp
    ${BOTAN_SOURCES_DIR}/utils/mem_ops.cpp
    ${BOTAN_SOURCES_DIR}/utils/os_utils.cpp
    ${BOTAN_SOURCES_DIR}/utils/parsing.cpp
    ${BOTAN_SOURCES_DIR}/utils/read_cfg.cpp
    ${BOTAN_SOURCES_DIR}/utils/semaphore.cpp
    ${BOTAN_SOURCES_DIR}/utils/version.cpp
    ${BOTAN_SOURCES_DIR}/x509/cert_status.cpp
    ${BOTAN_SOURCES_DIR}/x509/certstor.cpp
    ${BOTAN_SOURCES_DIR}/x509/certstor_sql/certstor_sql.cpp
    ${BOTAN_SOURCES_DIR}/x509/crl_ent.cpp
    ${BOTAN_SOURCES_DIR}/x509/datastor.cpp
    ${BOTAN_SOURCES_DIR}/x509/key_constraint.cpp
    ${BOTAN_SOURCES_DIR}/x509/name_constraint.cpp
    ${BOTAN_SOURCES_DIR}/x509/ocsp.cpp
    ${BOTAN_SOURCES_DIR}/x509/ocsp_types.cpp
    ${BOTAN_SOURCES_DIR}/x509/pkcs10.cpp
    ${BOTAN_SOURCES_DIR}/x509/x509_ca.cpp
    ${BOTAN_SOURCES_DIR}/x509/x509_crl.cpp
    ${BOTAN_SOURCES_DIR}/x509/x509_ext.cpp
    ${BOTAN_SOURCES_DIR}/x509/x509_obj.cpp
    ${BOTAN_SOURCES_DIR}/x509/x509cert.cpp
    ${BOTAN_SOURCES_DIR}/x509/x509opt.cpp
    ${BOTAN_SOURCES_DIR}/x509/x509path.cpp
    ${BOTAN_SOURCES_DIR}/x509/x509self.cpp
)

set(BOTAN_TESTS_DIR src/tests)
set(BOTAN_TESTS
    ${BOTAN_TESTS_DIR}/main.cpp
    ${BOTAN_TESTS_DIR}/test_aead.cpp
    ${BOTAN_TESTS_DIR}/test_bigint.cpp
    ${BOTAN_TESTS_DIR}/test_block.cpp
    ${BOTAN_TESTS_DIR}/test_c25519.cpp
    ${BOTAN_TESTS_DIR}/test_certstor.cpp
    ${BOTAN_TESTS_DIR}/test_compression.cpp
    ${BOTAN_TESTS_DIR}/test_cryptobox.cpp
    ${BOTAN_TESTS_DIR}/test_dh.cpp
    ${BOTAN_TESTS_DIR}/test_dl_group.cpp
    ${BOTAN_TESTS_DIR}/test_dlies.cpp
    ${BOTAN_TESTS_DIR}/test_dsa.cpp
    ${BOTAN_TESTS_DIR}/test_ecc_pointmul.cpp
    ${BOTAN_TESTS_DIR}/test_ecdh.cpp
    ${BOTAN_TESTS_DIR}/test_ecdsa.cpp
    ${BOTAN_TESTS_DIR}/test_ecgdsa.cpp
    ${BOTAN_TESTS_DIR}/test_ecies.cpp
    ${BOTAN_TESTS_DIR}/test_eckcdsa.cpp
    ${BOTAN_TESTS_DIR}/test_elg.cpp
    ${BOTAN_TESTS_DIR}/test_entropy.cpp
    ${BOTAN_TESTS_DIR}/test_ffi.cpp
    ${BOTAN_TESTS_DIR}/test_filters.cpp
    ${BOTAN_TESTS_DIR}/test_fpe.cpp
    ${BOTAN_TESTS_DIR}/test_fuzzer.cpp
    ${BOTAN_TESTS_DIR}/test_gf2m.cpp
    ${BOTAN_TESTS_DIR}/test_gost_3410.cpp
    ${BOTAN_TESTS_DIR}/test_hash.cpp
    ${BOTAN_TESTS_DIR}/test_kdf.cpp
    ${BOTAN_TESTS_DIR}/test_keywrap.cpp
    ${BOTAN_TESTS_DIR}/test_mac.cpp
    ${BOTAN_TESTS_DIR}/test_mceliece.cpp
    ${BOTAN_TESTS_DIR}/test_modes.cpp
    ${BOTAN_TESTS_DIR}/test_mp.cpp
    ${BOTAN_TESTS_DIR}/test_name_constraint.cpp
    ${BOTAN_TESTS_DIR}/test_newhope.cpp
    ${BOTAN_TESTS_DIR}/test_ocb.cpp
    ${BOTAN_TESTS_DIR}/test_ocsp.cpp
    ${BOTAN_TESTS_DIR}/test_octetstring.cpp
    ${BOTAN_TESTS_DIR}/test_os_utils.cpp
    ${BOTAN_TESTS_DIR}/test_package_transform.cpp
    ${BOTAN_TESTS_DIR}/test_pad.cpp
    ${BOTAN_TESTS_DIR}/test_passhash.cpp
    ${BOTAN_TESTS_DIR}/test_pbkdf.cpp
    ${BOTAN_TESTS_DIR}/test_pk_pad.cpp
    ${BOTAN_TESTS_DIR}/test_pkcs11.cpp
    ${BOTAN_TESTS_DIR}/test_pkcs11_high_level.cpp
    ${BOTAN_TESTS_DIR}/test_pkcs11_low_level.cpp
    ${BOTAN_TESTS_DIR}/test_pubkey.cpp
    ${BOTAN_TESTS_DIR}/test_rfc6979.cpp
    ${BOTAN_TESTS_DIR}/test_rng.cpp
    ${BOTAN_TESTS_DIR}/test_rsa.cpp
    ${BOTAN_TESTS_DIR}/test_simd.cpp
    ${BOTAN_TESTS_DIR}/test_srp6.cpp
    ${BOTAN_TESTS_DIR}/test_stream.cpp
    ${BOTAN_TESTS_DIR}/test_tls_messages.cpp
    ${BOTAN_TESTS_DIR}/test_tpm.cpp
    ${BOTAN_TESTS_DIR}/test_tss.cpp
    ${BOTAN_TESTS_DIR}/test_utils.cpp
    ${BOTAN_TESTS_DIR}/test_workfactor.cpp
    ${BOTAN_TESTS_DIR}/test_x509_path.cpp
    ${BOTAN_TESTS_DIR}/test_xmss.cpp
    ${BOTAN_TESTS_DIR}/tests.cpp
    ${BOTAN_TESTS_DIR}/unit_ecc.cpp
    ${BOTAN_TESTS_DIR}/unit_ecdh.cpp
    ${BOTAN_TESTS_DIR}/unit_ecdsa.cpp
    ${BOTAN_TESTS_DIR}/unit_tls.cpp
    ${BOTAN_TESTS_DIR}/unit_tls_policy.cpp
    ${BOTAN_TESTS_DIR}/unit_x509.cpp
)

set(BOTAN_CLI_DIR src/cli)
set(BOTAN_CLI
    ${BOTAN_CLI_DIR}/asn1.cpp
    ${BOTAN_CLI_DIR}/cc_enc.cpp
    ${BOTAN_CLI_DIR}/compress.cpp
    ${BOTAN_CLI_DIR}/main.cpp
    ${BOTAN_CLI_DIR}/math.cpp
    ${BOTAN_CLI_DIR}/pubkey.cpp
    ${BOTAN_CLI_DIR}/speed.cpp
    ${BOTAN_CLI_DIR}/timing_tests.cpp
    ${BOTAN_CLI_DIR}/tls_client.cpp
    ${BOTAN_CLI_DIR}/tls_proxy.cpp
    ${BOTAN_CLI_DIR}/tls_server.cpp
    ${BOTAN_CLI_DIR}/tls_utils.cpp
    ${BOTAN_CLI_DIR}/utils.cpp
    ${BOTAN_CLI_DIR}/x509.cpp
)

set_source_files_properties(${BOTAN_SOURCES_DIR}/block/aes/aes_ni/aes_ni.cpp PROPERTIES COMPILE_FLAGS -maes -mpclmul -mssse3)
set_source_files_properties(${BOTAN_SOURCES_DIR}/block/aes/aes_ssse3/aes_ssse3.cpp PROPERTIES COMPILE_FLAGS -mssse3)
set_source_files_properties(${BOTAN_SOURCES_DIR}/block/idea/idea_sse2/idea_sse2.cpp PROPERTIES COMPILE_FLAGS -msse2)
set_source_files_properties(${BOTAN_SOURCES_DIR}/block/noekeon/noekeon_simd/noekeon_simd.cpp PROPERTIES COMPILE_FLAGS -msse2)
set_source_files_properties(${BOTAN_SOURCES_DIR}/block/serpent/serpent_simd/serpent_simd.cpp PROPERTIES COMPILE_FLAGS -msse2)
set_source_files_properties(${BOTAN_SOURCES_DIR}/block/threefish/threefish_avx2/threefish_avx2.cpp PROPERTIES COMPILE_FLAGS -mavx2)
set_source_files_properties(${BOTAN_SOURCES_DIR}/entropy/rdseed/rdseed.cpp PROPERTIES COMPILE_FLAGS -mrdseed)
set_source_files_properties(${BOTAN_SOURCES_DIR}/hash/sha1/sha1_sse2/sha1_sse2.cpp PROPERTIES COMPILE_FLAGS -msse2)
set_source_files_properties(${BOTAN_SOURCES_DIR}/modes/aead/gcm/clmul/clmul.cpp PROPERTIES COMPILE_FLAGS -maes -mpclmul -mssse3)
set_source_files_properties(${BOTAN_SOURCES_DIR}/rng/rdrand_rng/rdrand_rng.cpp PROPERTIES COMPILE_FLAGS -mrdrnd)
set_source_files_properties(${BOTAN_SOURCES_DIR}/stream/chacha/chacha_sse2/chacha_sse2.cpp PROPERTIES COMPILE_FLAGS -msse2)
set_source_files_properties(${BOTAN_TESTS_DIR}/test_simd.cpp PROPERTIES COMPILE_FLAGS -msse2)

set(CONFIGURATION_FILES
    Makefile
    news.rst
    readme.rst
    authors.txt
    .gitignore
    .astylerc
)

set(COMPILER_FEATURES -flto -fstack-protector -m64 -pthread -stdlib=libc++ -std=c++11)
set(COMPILER_DEFINITIONS -D_REENTRANT)
set(COMPILER_WARNINGS -Wall -Wextra -Wpedantic -Wshadow -Wstrict-aliasing -Wstrict-overflow=5 -Wcast-align -Wmissing-declarations -Wpointer-arith -Wcast-qual -Wunreachable-code)
set(COMPILER_OPTIONAL_WARNINGS -Werror -Wctor-dtor-privacy -Wdeprecated -Winit-self -Wnon-virtual-dtor -Wunused-macros -Wold-style-cast -Wsign-promo -Wuninitialized -Wno-deprecated-declarations -Wunreachable-code-loop-increment -Wunreachable-code-return)
set(COMPILER_INCLUDE_DIRS build/include build/include/external)

file(GLOB_RECURSE DOCUMENTATION_FILES doc/* )
add_custom_target(CONFIGURATION_DUMMY SOURCES ${CONFIGURATION_FILES} ${DOCUMENTATION_FILES})

add_library(${PROJECT_NAME} STATIC ${BOTAN_SOURCES})
target_link_libraries(${PROJECT_NAME} PUBLIC pthread "-framework Security")
target_compile_options(${PROJECT_NAME} PUBLIC ${COMPILER_WARNINGS} ${COMPILER_FEATURES} ${COMPILER_OPTIONAL_WARNINGS})
target_compile_definitions(${PROJECT_NAME} PUBLIC ${COMPILER_DEFINITIONS})
target_include_directories(${PROJECT_NAME} PUBLIC ${COMPILER_INCLUDE_DIRS})

add_library(${PROJECT_NAME}_shared SHARED ${BOTAN_SOURCES})
target_link_libraries(${PROJECT_NAME}_shared PUBLIC pthread -ldl "-framework Security")
target_compile_options(${PROJECT_NAME}_shared PUBLIC ${COMPILER_WARNINGS} ${COMPILER_FEATURES} ${COMPILER_OPTIONAL_WARNINGS})
target_compile_definitions(${PROJECT_NAME}_shared PUBLIC ${COMPILER_DEFINITIONS})
target_include_directories(${PROJECT_NAME}_shared PUBLIC ${COMPILER_INCLUDE_DIRS})
set_target_properties(${PROJECT_NAME}_shared PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

add_executable(${PROJECT_NAME}_cli ${BOTAN_CLI})
target_link_libraries(${PROJECT_NAME}_cli PRIVATE ${PROJECT_NAME}_shared -headerpad_max_install_names)
set_target_properties(${PROJECT_NAME}_cli PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

add_executable(${PROJECT_NAME}_tests ${BOTAN_TESTS})
target_link_libraries(${PROJECT_NAME}_tests PRIVATE ${PROJECT_NAME}_shared -headerpad_max_install_names)
set_target_properties(${PROJECT_NAME}_tests PROPERTIES OUTPUT_NAME botan-test)




