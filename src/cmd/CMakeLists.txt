set(INCLUDE_DIR "../../build/include")
include_directories(${INCLUDE_DIR})

set(extra_link_libraries)
if(NOT WIN32)
#    list(APPEND extra_link_libraries dl pthread)
endif()

# botan-tests
add_executable(${PROJECT_NAME}
    ./asn1.cpp
    ./base64.cpp
    ./bcrypt.cpp
    ./ca.cpp
    ./cert_verify.cpp
    ./compress.cpp
    ./dsa_sign.cpp
    ./dsa_ver.cpp
    ./factor.cpp
    ./fpe.cpp
    ./fuzzer.cpp
    ./getopt.cpp
    ./hash.cpp
    ./is_prime.cpp
    ./keygen.cpp
    ./main.cpp
    ./ocsp.cpp
    ./pkcs10.cpp
    ./rng.cpp
    ./self_sig.cpp
    ./speed.cpp
    ./timer.cpp
    ./speed_pk.cpp
    ./tls_client.cpp
    ./tls_proxy.cpp
    ./tls_server.cpp
    ./x509print.cpp
)

#find_package( LZMA REQUIRED )
#if ( LZMA_FOUND )
#    include_directories(${LZMA_INCLUDE_DIR})
#    target_link_libraries(${PROJECT_NAME}-tests ${LZMA_LIBRARIES})
#endif( LZMA_FOUND )

#find_package( BZip2 REQUIRED )
#if ( BZIP2_FOUND )
#    include_directories(${BZIP_INCLUDE_DIRS})
#    target_link_libraries(${PROJECT_NAME}-tests ${BZIP2_LIBRARIES})
#endif( BZIP2_FOUND )
#
#find_package( ZLIB REQUIRED )
#if ( ZLIB_FOUND )
#    include_directories(${ZLIB_INCLUDE_DIRS})
#    target_link_libraries(${PROJECT_NAME}-tests ${ZLIB_LIBRARIES})
#endif( ZLIB_FOUND )

target_link_libraries(${PROJECT_NAME} botan ${extra_link_libraries})


