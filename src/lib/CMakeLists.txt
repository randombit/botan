# Where ./configure.py puts them
set(INCLUDE_DIR "${CMAKE_SOURCE_DIR}/build/include")
include_directories(${INCLUDE_DIR})

# libbotan
set(BOTAN_SRC
    asn1/alg_id.cpp
    asn1/asn1_alt_name.cpp
    asn1/asn1_attribute.cpp
    asn1/asn1_obj.cpp
    asn1/asn1_oid.cpp
    asn1/asn1_str.cpp
    asn1/asn1_time.cpp
    asn1/ber_dec.cpp
    asn1/der_enc.cpp
    asn1/oid_lookup/default.cpp
    asn1/oid_lookup/oids.cpp
    asn1/x509_dn.cpp
    base/init.cpp
    base/scan_name.cpp
    base/symkey.cpp
    base/transform.cpp
    block/block_cipher.cpp
    block/aes/aes.cpp
    block/aes_ni/aes_ni.cpp
    block/aes_ssse3/aes_ssse3.cpp
    block/blowfish/blfs_tab.cpp
    block/blowfish/blowfish.cpp
    block/camellia/camellia.cpp
    block/cascade/cascade.cpp
    block/cast/cast128.cpp
    block/cast/cast256.cpp
    block/des/des.cpp
    block/des/des_tab.cpp
    block/des/desx.cpp
    block/gost_28147/gost_28147.cpp
    block/idea/idea.cpp
    block/idea_sse2/idea_sse2.cpp
    block/kasumi/kasumi.cpp
    block/lion/lion.cpp
    block/mars/mars.cpp
    block/misty1/misty1.cpp
    block/noekeon/noekeon.cpp
    block/noekeon_simd/noekeon_simd.cpp
    block/rc2/rc2.cpp
    block/rc5/rc5.cpp
    block/rc6/rc6.cpp
    block/safer/safer_sk.cpp
    block/seed/seed.cpp
    block/seed/seed_tab.cpp
    block/serpent/serpent.cpp
    block/serpent_simd/serp_simd.cpp
    block/tea/tea.cpp
    block/threefish_avx2/threefish_avx2.cpp
    block/threefish/threefish.cpp
    block/twofish/twofish.cpp
    block/twofish/two_tab.cpp
    block/xtea_simd/xtea_simd.cpp
    block/xtea/xtea.cpp
    cert/x509/certstor.cpp
    cert/x509/crl_ent.cpp
    cert/x509/key_constraint.cpp
    cert/x509/ocsp.cpp
    cert/x509/ocsp_types.cpp
    cert/x509/pkcs10.cpp
    cert/x509/x509_ca.cpp
    cert/x509/x509cert.cpp
    cert/x509/x509_crl.cpp
    cert/x509/x509_ext.cpp
    cert/x509/x509_obj.cpp
    cert/x509/x509opt.cpp
    cert/x509/x509path.cpp
    cert/x509/x509self.cpp
    codec/base64/base64.cpp
    codec/hex/hex.cpp
    compression/compression.cpp
    entropy/dev_random/dev_random.cpp
    entropy/egd/es_egd.cpp
    entropy/entropy_srcs.cpp
    entropy/hres_timer/hres_timer.cpp
    entropy/proc_walk/proc_walk.cpp
    entropy/rdrand/rdrand.cpp
    entropy/unix_procs/unix_procs.cpp
    entropy/unix_procs/unix_proc_sources.cpp
    ffi/ffi.cpp
    filters/algo_filt.cpp
    filters/basefilt.cpp
    filters/buf_filt.cpp
    filters/codec_filt/b64_filt.cpp
    filters/codec_filt/hex_filt.cpp
    filters/comp_filter.cpp
    filters/data_snk.cpp
    filters/fd_unix/fd_unix.cpp
    filters/filter.cpp
    filters/key_filt.cpp
    filters/out_buf.cpp
    filters/pipe.cpp
    filters/pipe_io.cpp
    filters/pipe_rw.cpp
    filters/secqueue.cpp
    filters/threaded_fork.cpp
    filters/transform_filter.cpp
    hash/checksum/adler32/adler32.cpp
    hash/checksum/crc24/crc24.cpp
    hash/checksum/crc32/crc32.cpp
    hash/comb4p/comb4p.cpp
    hash/gost_3411/gost_3411.cpp
    hash/has160/has160.cpp
    hash/hash.cpp
    hash/keccak/keccak.cpp
    hash/md2/md2.cpp
    hash/md4/md4.cpp
    hash/md5/md5.cpp
    hash/mdx_hash/mdx_hash.cpp
    hash/par_hash/par_hash.cpp
    hash/rmd128/rmd128.cpp
    hash/rmd160/rmd160.cpp
    hash/sha1/sha160.cpp
    hash/sha1_sse2/sha1_sse2.cpp
    hash/sha2_32/sha2_32.cpp
    hash/sha2_64/sha2_64.cpp
    hash/skein/skein_512.cpp
    hash/tiger/tiger.cpp
    hash/tiger/tig_tab.cpp
    hash/whirlpool/whirlpool.cpp
    hash/whirlpool/whrl_tab.cpp
    kdf/hkdf/hkdf.cpp
    kdf/kdf1/kdf1.cpp
    kdf/kdf2/kdf2.cpp
    kdf/kdf.cpp
    kdf/prf_tls/prf_tls.cpp
    kdf/prf_x942/prf_x942.cpp
    mac/cbc_mac/cbc_mac.cpp
    mac/cmac/cmac.cpp
    mac/hmac/hmac.cpp
    mac/mac.cpp
    mac/poly1305/poly1305.cpp
    mac/siphash/siphash.cpp
    mac/x919_mac/x919_mac.cpp
    math/bigint/big_code.cpp
    math/bigint/bigint.cpp
    math/bigint/big_io.cpp
    math/bigint/big_ops2.cpp
    math/bigint/big_ops3.cpp
    math/bigint/big_rand.cpp
    math/bigint/divide.cpp
    math/ec_gfp/curve_gfp.cpp
    math/ec_gfp/curve_nistp.cpp
    math/ec_gfp/point_gfp.cpp
    math/mp/mp_asm.cpp
    math/mp/mp_comba.cpp
    math/mp/mp_karat.cpp
    math/mp/mp_misc.cpp
    math/mp/mp_monty.cpp
    math/mp/mp_mulop.cpp
    math/mp/mp_shift.cpp
    math/numbertheory/dsa_gen.cpp
    math/numbertheory/jacobi.cpp
    math/numbertheory/make_prm.cpp
    math/numbertheory/mp_numth.cpp
    math/numbertheory/numthry.cpp
    math/numbertheory/powm_fw.cpp
    math/numbertheory/powm_mnt.cpp
    math/numbertheory/pow_mod.cpp
    math/numbertheory/primes.cpp
    math/numbertheory/reducer.cpp
    math/numbertheory/ressol.cpp
    misc/aont/package.cpp
    misc/benchmark/benchmark.cpp
    misc/cryptobox/cryptobox.cpp
    misc/fpe_fe1/fpe_fe1.cpp
    misc/openpgp/openpgp.cpp
    misc/pbes2/pbes2.cpp
    misc/pem/pem.cpp
    misc/rfc3394/rfc3394.cpp
    misc/srp6/srp6.cpp
    misc/srp6/srp6_files.cpp
    misc/tss/tss.cpp
    modes/aead/aead.cpp
    modes/aead/ccm/ccm.cpp
    modes/aead/chacha20poly1305/chacha20poly1305.cpp
    modes/aead/eax/eax.cpp
    modes/aead/gcm/clmul/clmul.cpp
    modes/aead/gcm/gcm.cpp
    modes/aead/ocb/ocb.cpp
    modes/aead/siv/siv.cpp
    modes/cbc/cbc.cpp
    modes/cfb/cfb.cpp
    modes/cipher_mode.cpp
    modes/ecb/ecb.cpp
    modes/mode_pad/mode_pad.cpp
    modes/xts/xts.cpp
    passhash/bcrypt/bcrypt.cpp
    passhash/passhash9/passhash9.cpp
    pbkdf/pbkdf1/pbkdf1.cpp
    pbkdf/pbkdf2/pbkdf2.cpp
    pbkdf/pbkdf.cpp
    pk_pad/eme.cpp
    pk_pad/eme_oaep/oaep.cpp
    pk_pad/eme_pkcs1/eme_pkcs.cpp
    pk_pad/eme_raw/eme_raw.cpp
    pk_pad/emsa.cpp
    pk_pad/emsa1_bsi/emsa1_bsi.cpp
    pk_pad/emsa1/emsa1.cpp
    pk_pad/emsa_pkcs1/emsa_pkcs1.cpp
    pk_pad/emsa_pssr/pssr.cpp
    pk_pad/emsa_raw/emsa_raw.cpp
    pk_pad/emsa_x931/emsa_x931.cpp
    pk_pad/hash_id/hash_id.cpp
    pk_pad/mgf1/mgf1.cpp
    pubkey/blinding.cpp
    pubkey/curve25519/curve25519.cpp
    pubkey/curve25519/donna.cpp
    pubkey/dh/dh.cpp
    pubkey/dl_algo/dl_algo.cpp
    pubkey/dl_group/dl_group.cpp
    pubkey/dl_group/named.cpp
    pubkey/dlies/dlies.cpp
    pubkey/dsa/dsa.cpp
    pubkey/ecc_key/ecc_key.cpp
    pubkey/ecdh/ecdh.cpp
    pubkey/ecdsa/ecdsa.cpp
    pubkey/ec_group/ec_group.cpp
    pubkey/ec_group/named.cpp
    pubkey/elgamal/elgamal.cpp
    pubkey/gost_3410/gost_3410.cpp
    pubkey/if_algo/if_algo.cpp
    pubkey/keypair/keypair.cpp
    pubkey/mce/code_based_key_gen.cpp
    pubkey/mce/gf2m_rootfind_dcmp.cpp
    pubkey/mce/gf2m_small_m.cpp
    pubkey/mce/goppa_code.cpp
    pubkey/mceies/mceies.cpp
    pubkey/mce/mce_kem.cpp
    pubkey/mce/mceliece.cpp
    pubkey/mce/mceliece_key.cpp
    pubkey/mce/polyn_gf2m.cpp
    pubkey/mce/workfactor.cpp
    pubkey/nr/nr.cpp
    pubkey/pk_algs.cpp
    pubkey/pkcs8.cpp
    pubkey/pk_keys.cpp
    pubkey/pk_ops.cpp
    pubkey/pubkey.cpp
    pubkey/rfc6979/rfc6979.cpp
    pubkey/rsa/rsa.cpp
    pubkey/rw/rw.cpp
    pubkey/workfactor.cpp
    pubkey/x509_key.cpp
    rng/hmac_drbg/hmac_drbg.cpp
    rng/hmac_rng/hmac_rng.cpp
    rng/rng.cpp
    rng/system_rng/system_rng.cpp
    rng/x931_rng/x931_rng.cpp
    stream/chacha/chacha.cpp
    stream/ctr/ctr.cpp
    stream/ofb/ofb.cpp
    stream/rc4/rc4.cpp
    stream/salsa20/salsa20.cpp
    stream/stream_cipher.cpp
    tls/credentials_manager.cpp
    tls/msg_certificate.cpp
    tls/msg_cert_req.cpp
    tls/msg_cert_verify.cpp
    tls/msg_client_hello.cpp
    tls/msg_client_kex.cpp
    tls/msg_finished.cpp
    tls/msg_hello_verify.cpp
    tls/msg_server_hello.cpp
    tls/msg_server_kex.cpp
    tls/msg_session_ticket.cpp
    tls/tls_alert.cpp
    tls/tls_blocking.cpp
    tls/tls_channel.cpp
    tls/tls_ciphersuite.cpp
    tls/tls_client.cpp
    tls/tls_extensions.cpp
    tls/tls_handshake_hash.cpp
    tls/tls_handshake_io.cpp
    tls/tls_handshake_state.cpp
    tls/tls_heartbeats.cpp
    tls/tls_policy.cpp
    tls/tls_record.cpp
    tls/tls_server.cpp
    tls/tls_session.cpp
    tls/tls_session_key.cpp
    tls/tls_session_manager_memory.cpp
    tls/tls_suite_info.cpp
    tls/tls_version.cpp
    utils/assert.cpp
    utils/calendar.cpp
    utils/charset.cpp
    utils/cpuid.cpp
    utils/data_src.cpp
    utils/datastor/datastor.cpp
    utils/dyn_load/dyn_load.cpp
    utils/filesystem.cpp
    utils/http_util/http_util.cpp
    utils/locking_allocator/locking_allocator.cpp
    utils/os_utils.cpp
    utils/parsing.cpp
    utils/read_cfg.cpp
    utils/semaphore.cpp
    # utils/sqlite3/sqlite3.cpp
    utils/version.cpp
    utils/zero_mem.cpp
)

# add a new target to show help for options that we add
# use add_custom_command(TARGET Botan-help ...) to extend the help text
add_custom_target(Botan-help)

# AVX2
set_source_files_properties(block/threefish_avx2/threefish_avx2.cpp PROPERTIES COMPILE_FLAGS "-mavx2")
# SSSE3
set_source_files_properties(block/aes_ssse3/aes_ssse3.cpp PROPERTIES COMPILE_FLAGS "-mssse3")
# AES-NI
set_source_files_properties(block/aes_ni/aes_ni.cpp        PROPERTIES COMPILE_FLAGS "-maes -mpclmul -mssse3")
set_source_files_properties(modes/aead/gcm/clmul/clmul.cpp PROPERTIES COMPILE_FLAGS "-maes -mpclmul -mssse3")

if ( WITH_LZMA )
    find_package( LZMA )
    if ( LZMA_FOUND )
        include_directories(${LZMA_INCLUDE_DIR})
        set(BOTAN_LIBRARIES ${BOTAN_LIBRARIES} ${LZMA_LIBRARIES})
        set(BOTAN_SRC ${BOTAN_SRC}
            compression/lzma/lzma.cpp)
    endif( LZMA_FOUND )
endif ( WITH_LZMA )
add_custom_command(TARGET Botan-help
    COMMAND echo "  To build with lzma support use: cmake -DWITH_LZMA=1")

if ( WITH_BZIP2 )
    find_package( BZip2 )
    if ( BZIP2_FOUND )
        include_directories(${BZIP_INCLUDE_DIRS})
        set(BOTAN_LIBRARIES ${BOTAN_LIBRARIES} ${BZIP2_LIBRARIES})
        set(BOTAN_SRC ${BOTAN_SRC}
            compression/bzip2/bzip2.cpp)
    endif( BZIP2_FOUND )
endif ( WITH_BZIP2 )
add_custom_command(TARGET Botan-help
    COMMAND echo "  To build with bzip2 support use: cmake -DWITH_BZIP2=1")

if ( WITH_ZLIB )
    find_package( ZLIB )
    if ( ZLIB_FOUND )
        include_directories(${ZLIB_INCLUDE_DIRS})
        set(BOTAN_LIBRARIES ${BOTAN_LIBRARIES} ${ZLIB_LIBRARIES})
        set(BOTAN_SRC ${BOTAN_SRC}
            compression/zlib/zlib.cpp)
    endif( ZLIB_FOUND )
endif ( WITH_ZLIB )
add_custom_command(TARGET Botan-help
    COMMAND echo "  To build with zlib support use: cmake -DWITH_ZLIB=1")

set(extra_link_libraries)
if(NOT WIN32)
    list(APPEND extra_link_libraries rt dl pthread)
endif()

set(CMAKE_DEBUG_POSTFIX "d")

if (NOT LIB_TYPE)
    set(LIB_TYPE STATIC)
endif()

add_custom_command(TARGET Botan-help
    COMMAND echo "  To build a static or shared Botan library use: cmake -DLIB_TYPE=STATIC or -DLIB_TYPE=SHARED")

message(STATUS "Building with LIB_TYPE=${LIB_TYPE}")
add_library(botan ${LIB_TYPE} ${BOTAN_SRC})

target_link_libraries(botan ${BOTAN_LIBRARIES} ${extra_link_libraries})

file(GLOB include_install_files "${INCLUDE_DIR}/botan/*.h")
foreach (include_install_file ${include_install_files})
    get_filename_component(full_include_install_file ${include_install_file} REALPATH)
    install(FILES ${full_include_install_file} DESTINATION "include/botan-1.11/botan/")
endforeach (include_install_file ${include_instal_files})
install(TARGETS botan ARCHIVE DESTINATION "lib/botan")

