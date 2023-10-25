# Script to run inside the CI container to test the botan
# TLS client/server with TLS-Anvil
#
# (C) 2023 Jack Lloyd
# (C) 2023 Fabian Albert, Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)
import sys
import argparse
import os
import subprocess


class Config:
    """ Hardcoded configurations for this CI script """
    tls_anvil_docker_image = "ghcr.io/tls-attacker/tlsanvil"
    tls_anvil_version_tag = "@sha256:e9abe034e6b1dac7fe204d524db338f379087a16aca71e94dc7b51ac835bb53f" # v1.2.2 + HelloRetry test fix
    key_and_cert_storage_path = "/tmp/"
    test_suite_results_dest = "."
    test_suite_results_dir_name = "TestSuiteResults"
    tmp_key_file_name = "tmp_rsa_key.pem"
    tmp_cert_file_name = "tmp_rsa_cert.pem"
    server_dest_ip = "127.0.0.1"
    server_dest_port = 4433
    botan_server_log = "./logs/botan_server.log"
    botan_config_args = ["--compiler-cache=ccache", "--build-targets=static,cli",
                          "--without-documentation", "--with-boost"]

def group_output(group_title: str, func):
    """
    Wraps a function to be called within a GitHub actions group, so that
    the console output is expandable.

    Returns the wrapped function
    """
    def wrapped_func(*args, **kwargs):
        print(f"::group::{group_title}", flush=True)
        ret = func(*args, **kwargs)
        print("\n::endgroup::", flush=True)
        return ret
    return wrapped_func


def create_cert_and_key(botan_dir_path):
    """
    Create a X.509 certificate and associated RSA key at Config.key_and_cert_storage_path
    using Botan's CLI.

    Returns: (<cert path>, <key path>)
    """

    key_path = os.path.join(Config.key_and_cert_storage_path, Config.tmp_key_file_name)
    cert_path = os.path.join(Config.key_and_cert_storage_path, Config.tmp_cert_file_name)

    with open(key_path, 'w', encoding='utf-8') as keyfile:
        subprocess.run([botan_dir_path, "keygen", "--algo=RSA", "--params=2048"], stdout=keyfile, check=True)

    with open(cert_path, 'w', encoding='utf-8') as certfile:
        subprocess.run([botan_dir_path, "gen_self_signed", key_path, "localhost"], stdout=certfile, check=True)

    return (cert_path, key_path)


def build_botan(botan_dir: str, parallel_jobs: int) -> str:
    """
    Configure and build botan.

    Returns the botan executable path
    """
    group_output("Configure Botan", subprocess.run)(["python3", "./configure.py"] + Config.botan_config_args, check=True, cwd=botan_dir)
    group_output("Build Botan with Make", subprocess.run)(["make", f"-j{parallel_jobs}"], check=True, cwd=botan_dir)

    return os.path.join(botan_dir, "botan")


def server_test(botan_dir_path: str, parallel: int):
    """ Test the Botan TLS server """
    cert_path, key_path = create_cert_and_key(botan_dir_path)
    docker_img = f"{Config.tls_anvil_docker_image}{Config.tls_anvil_version_tag}"

    group_output("Pull TLS-Anvil image", subprocess.run)(["docker", "pull", docker_img], check=True)

    tls_anvil_cmd = [
        "docker", "run",
        "--network", "host",
        "-v", f"{Config.test_suite_results_dest}:/output",
        docker_img,
        "-strength", "1",
        "-parallelHandshakes", str(parallel),
        "-disableTcpDump",
        "-outputFolder", os.path.join(Config.test_suite_results_dest, Config.test_suite_results_dir_name),
        "-connectionTimeout", "5000",
        "server", "-connect", f"{Config.server_dest_ip}:{Config.server_dest_port}"
    ]

    botan_server_cmd = [
        botan_dir_path, "tls_http_server", cert_path, key_path, f"--port={Config.server_dest_port}"
    ]

    os.makedirs(os.path.dirname(Config.botan_server_log), exist_ok=True)

    # Run Botan and test is with TLS-Anvil
    with open(Config.botan_server_log, 'w', encoding='utf-8') as server_log_file:
        botan_server_process = subprocess.Popen(botan_server_cmd, stdout=server_log_file, stderr=server_log_file)
        subprocess.run(tls_anvil_cmd, check=True)
        botan_server_process.kill()


def client_test(botan_dir_path: str, parallel: int):
    """ Test the Botan TLS server """
    raise NotImplementedError("Client tests not yet implemented")


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser()
    parser.add_argument("--botan-dir", help="Botan base directory", required=True)
    parser.add_argument("--test-target", help="The TLS side to test", choices=['client', 'server'], required=True)
    parser.add_argument("--parallel", help="The number of parallel handshakes", type=int, default=1)

    args = vars(parser.parse_args(args))

    if not os.path.isdir(args["botan_dir"]):
        raise FileNotFoundError(f"Unable to find '{args['botan_dir']}'")

    botan_exe_path = build_botan(args["botan_dir"], args["parallel"])

    if args["test_target"] == "server":
        server_test(botan_exe_path, args["parallel"])
    elif args["test_target"] == "client":
        client_test(botan_exe_path, args["parallel"])

    return 0


if __name__ == "__main__":
    sys.exit(main())
