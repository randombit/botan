#!/usr/bin/env python3

# (C) 2017 Jack Lloyd
# Botan is released under the Simplified BSD License (see license.txt)

import re
import subprocess
import sys
import time


def format_report(client_output):
    version_re = re.compile(r'TLS (v1\.[0-3]) using ([A-Z0-9_]+)')

    version_match = version_re.search(client_output)

    #print(client_output)

    if version_match:
        return "Established %s %s" % (version_match.group(1), version_match.group(2))
    else:
        return client_output

def scanner(args = None):
    if args is None:
        args = sys.argv

    if len(args) != 2:
        print("Error: Usage tls_scanner.py host_file")
        return 2

    scanners = {}

    for url in [s.strip() for s in open(args[1])]:
        scanners[url] = subprocess.Popen(['../../../botan', 'tls_client', '--policy=policy.txt', url],
                                         stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)

    for scan_proc in scanners.values():
        scan_proc.stdin.close()

    report = {}
    timeout = 10

    for url, scan_proc in scanners.items():
        print("waiting for", url)

        for i in range(timeout):
            scan_proc.poll()
            if scan_proc.returncode is not None:
                break
            #print("Waiting %d more seconds for %s" % (timeout-i, url))
            time.sleep(1)

        if scan_proc.returncode is not None:
            output = scan_proc.stdout.read() + scan_proc.stderr.read()
            report[url] = format_report(output.decode("utf-8"))

    for url, result in report.items():
        print(url, ":", result)

    return 0

if __name__ == '__main__':
    sys.exit(scanner())
