
#include "../common.h"
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <iostream>

using namespace Botan;

#define DEFINE_EXAMPLE(cmd) int cmd ## _main(int argc, char* argv[]);

DEFINE_EXAMPLE(asn1);
DEFINE_EXAMPLE(bcrypt);
DEFINE_EXAMPLE(bzip);
DEFINE_EXAMPLE(base64);
DEFINE_EXAMPLE(ca);
DEFINE_EXAMPLE(factor);
DEFINE_EXAMPLE(fpe);
DEFINE_EXAMPLE(hash);
DEFINE_EXAMPLE(keygen);
DEFINE_EXAMPLE(dsa_sign);
DEFINE_EXAMPLE(dsa_verify);
DEFINE_EXAMPLE(cert_verify);
DEFINE_EXAMPLE(ocsp_check);
DEFINE_EXAMPLE(pkcs10);
DEFINE_EXAMPLE(read_ssh);
DEFINE_EXAMPLE(self_sig);
DEFINE_EXAMPLE(tls_client);
DEFINE_EXAMPLE(tls_server);
DEFINE_EXAMPLE(tls_server_asio);
DEFINE_EXAMPLE(x509);

int speed_main(int argc, char* argv[]);
