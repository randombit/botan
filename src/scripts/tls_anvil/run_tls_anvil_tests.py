#!/usr/bin/env python3

# Script to run inside the CI container to test the botan
# TLS client/server with TLS-Anvil
#
# (C) 2023,2026 Jack Lloyd
# (C) 2023 Fabian Albert, Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)
import sys
import argparse
import os
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from repo_config import RepoConfig  # noqa: E402

_repo_config = RepoConfig()


class Config:
    """ Hardcoded configurations for this CI script """
    tls_anvil_docker_image = _repo_config["TLS_ANVIL_DOCKER_IMAGE"]
    tls_anvil_version_tag = _repo_config["TLS_ANVIL_VERSION_TAG"]
    key_and_cert_storage_path = "/tmp/"
    test_suite_results_dest = "."
    test_suite_results_dir_name = "TestSuiteResults"
    tmp_key_file_name = "tmp_rsa_key.pem"
    tmp_cert_file_name = "tmp_rsa_cert.pem"
    server_dest_ip = "127.0.0.1"
    server_dest_port = 4433
    client_test_port = 4433
    trigger_server_port = 8090
    botan_server_log = "./logs/botan_server.log"
    botan_client_log_dir = "./logs/botan_client"
    anvil_policy_file = "src/scripts/tls_anvil/anvil_policy.txt"

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


def create_cert_and_key(botan_cli):
    """
    Create a X.509 certificate and associated RSA key at Config.key_and_cert_storage_path
    using Botan's CLI.

    Returns: (<cert path>, <key path>)
    """

    key_path = os.path.join(Config.key_and_cert_storage_path, Config.tmp_key_file_name)
    cert_path = os.path.join(Config.key_and_cert_storage_path, Config.tmp_cert_file_name)

    with open(key_path, 'w', encoding='utf-8') as keyfile:
        subprocess.run([botan_cli, "keygen", "--algo=RSA", "--params=2048"], stdout=keyfile, check=True)

    with open(cert_path, 'w', encoding='utf-8') as certfile:
        subprocess.run([botan_cli, "gen_self_signed", key_path, "localhost"], stdout=certfile, check=True)

    return (cert_path, key_path)


def server_test(botan_cli: str, parallel: int):
    """ Test the Botan TLS server """
    cert_path, key_path = create_cert_and_key(botan_cli)
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
        botan_cli, "tls_http_server", cert_path, key_path,
        f"--port={Config.server_dest_port}",
        f"--policy={Config.anvil_policy_file}",
    ]

    os.makedirs(os.path.dirname(Config.botan_server_log), exist_ok=True)

    # Run Botan and test is with TLS-Anvil
    with open(Config.botan_server_log, 'w', encoding='utf-8') as server_log_file:
        botan_server_process = subprocess.Popen(botan_server_cmd, stdout=server_log_file, stderr=server_log_file)
        subprocess.run(tls_anvil_cmd, check=True)
        botan_server_process.kill()


def client_test(botan_cli: str, parallel: int):
    """ Test the Botan TLS client """
    docker_img = f"{Config.tls_anvil_docker_image}{Config.tls_anvil_version_tag}"

    group_output("Pull TLS-Anvil image", subprocess.run)(["docker", "pull", docker_img], check=True)

    trigger_server_script = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "tls_anvil_trigger_server.py")

    trigger_server_cmd = [
        "python3", trigger_server_script,
        "--botan-cli", botan_cli,
        "--tls-anvil-policy", Config.anvil_policy_file,
        "--tls-anvil-host", Config.server_dest_ip,
        "--tls-anvil-port", str(Config.client_test_port),
        "--listen-port", str(Config.trigger_server_port),
        "--log-dir", Config.botan_client_log_dir,
    ]

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
        "client",
        "-port", str(Config.client_test_port),
        "-triggerScript", "curl", "--connect-timeout", "2",
        f"http://{Config.server_dest_ip}:{Config.trigger_server_port}/trigger"
    ]

    os.makedirs(Config.botan_client_log_dir, exist_ok=True)

    trigger_server_process = subprocess.Popen(trigger_server_cmd)
    try:
        subprocess.run(tls_anvil_cmd, check=True)
    finally:
        trigger_server_process.terminate()
        trigger_server_process.wait()


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser()
    parser.add_argument("--botan-cli", help="Path to botan CLI executable", required=True)
    parser.add_argument("--test-target", help="The TLS side to test", choices=['client', 'server'], required=True)
    parser.add_argument("--parallel", help="The number of parallel handshakes", type=int, default=16)

    args = vars(parser.parse_args(args))

    botan_cli = args["botan_cli"]
    if not os.access(botan_cli, os.X_OK):
        raise FileNotFoundError(f"Botan CLI not found or not executable: '{botan_cli}'")

    if args["test_target"] == "server":
        server_test(botan_cli, args["parallel"])
    elif args["test_target"] == "client":
        client_test(botan_cli, args["parallel"])

    return 0


if __name__ == "__main__":
    sys.exit(main())
