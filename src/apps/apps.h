
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <iostream>

#include "../getopt.h"

using namespace Botan;

int apps_main(const std::string& cmd, int argc, char* argv[]);

#define DEFINE_APP(cmd) int cmd ## _main(int argc, char* argv[]);

DEFINE_APP(asn1);
DEFINE_APP(bcrypt);
DEFINE_APP(bzip);
DEFINE_APP(base64);
DEFINE_APP(ca);
DEFINE_APP(factor);
DEFINE_APP(fpe);
DEFINE_APP(hash);
DEFINE_APP(keygen);
DEFINE_APP(dsa_sign);
DEFINE_APP(dsa_verify);
DEFINE_APP(cert_verify);
DEFINE_APP(ocsp_check);
DEFINE_APP(pkcs10);
DEFINE_APP(read_ssh);
DEFINE_APP(self_sig);
DEFINE_APP(tls_client);
DEFINE_APP(tls_server);
DEFINE_APP(tls_server_asio);
DEFINE_APP(x509);
DEFINE_APP(speed);
