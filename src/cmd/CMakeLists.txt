set(INCLUDE_DIR "../../build/include")
include_directories(${INCLUDE_DIR})

set(extra_link_libraries)
if(NOT WIN32)
#    list(APPEND extra_link_libraries dl pthread)
endif()

# botan-tests
add_executable(${PROJECT_NAME}
    ./self_sig.cpp
    ./speed.cpp
    ./ocsp.cpp
    ./is_prime.cpp
    ./rng.cpp
    ./asn1.cpp
    ./dsa_sign.cpp
    ./keygen.cpp
    ./timer.cpp
    ./bcrypt.cpp
    ./getopt.cpp
    ./factor.cpp
    ./x509print.cpp
    ./speed_pk.cpp
    ./ca.cpp
    ./cert_verify.cpp
    ./tls_client.cpp
    ./pkcs10.cpp
    ./fpe.cpp
    ./dsa_ver.cpp
    ./main.cpp
    ./tls_server.cpp
    ./hash.cpp
    ./fuzzer.cpp
    ./tls_proxy.cpp
    ./base64.cpp
    ./compress.cpp
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


