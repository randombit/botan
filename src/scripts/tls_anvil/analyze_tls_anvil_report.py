#!/usr/bin/env python3

# Parses a TLS-Anvil results directory. Returns 0 iff all results are expected.
#
# (C) 2023,2026 Jack Lloyd
# (C) 2023 Fabian Albert, Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)
import sys
import argparse
import os
import json
import logging


result_level = {
    "STRICTLY_SUCCEEDED": 0,
    "CONCEPTUALLY_SUCCEEDED": 1,
    "PARTIALLY_FAILED": 2,
    "FULLY_FAILED": 3,
}


def xfail_list(side):
    """Return list of tests that are expected to fail"""

    conceptually_succeeded = {
        # Okay: RFC does not specifically define an alert. Bogo Test expects an DecodeError Alert
        #   while TLS-Anvil expects an IllegalParameter Alert. We use the DecodeError Alert.
        "server.tls13.rfc8446.PreSharedKey.isLastButDuplicatedExtension",
    }

    partially_failed = {
        # We accept the TLS 1.2 brainpool curve IDs in 1.3
        "server.tls13.rfc8446.KeyShare.serverAcceptsDeprecatedGroups",
    }

    fully_failed = {
        # If ClientHello has no extensions that includes supported signatures; TLS 1.2 then
        # requires us to treat that as equivalent to supporting only SHA-1 -- which we do not support
        "server.tls12.rfc5246.ClientHello.leaveOutExtensions",

        # TLS-Anvil expects us to tolerate any legacy_version even ones that RFC 8446 explicitly
         # states we MUST reject - https://github.com/tls-attacker/TLS-Anvil/issues/60
        # 8446-bis has a change specifically mandating what we do right now
        "client.tls13.rfc8446.SupportedVersions.invalidLegacyVersion",

        # TLS-Anvil seems to assume KeyUpdate response is immediate rather than opportunistic
        # Possibly this can be fixed by using a dedicated util rather than tls_client
        "both.tls13.rfc8446.KeyUpdate.respondsWithValidKeyUpdate",
        "both.tls13.rfc8446.KeyUpdate.appDataUnderNewKeysSucceeds",

        # We accept the TLS 1.2 brainpool curve IDs in 1.3
        "server.tls13.rfc8446.KeyShare.serverAcceptsDeprecatedGroupsAllAtOnce",
    }

    if side == 'client':
        # TLS-Anvil's scanning phase seems to have a bug and decides we don't support handshake fragmentation
        # Works for server side though
        fully_failed.add("both.tls12.rfc5246.Fragmentation.recordFragmentationSupported")

    xfails = {}
    for test in conceptually_succeeded:
        if test.startswith('both.') or test.startswith(side):
            xfails[test] = result_level["CONCEPTUALLY_SUCCEEDED"]
    for test in partially_failed:
        if test.startswith('both.') or test.startswith(side):
            xfails[test] = result_level["PARTIALLY_FAILED"]
    for test in fully_failed:
        if test.startswith('both.') or test.startswith(side):
            xfails[test] = result_level["FULLY_FAILED"]
    return xfails


def extract_method_id(json_data):
    """Extract the method_id from a test result JSON."""
    return (json_data["TestClass"] + "." + json_data["TestMethod"]).removeprefix("de.rub.nds.tlstest.suite.tests.")


def failing_test_info(json_data, method_id, expected_label) -> str:
    """ Print debug information about a failing test """
    info_str = ""
    try:
        method_class, method_name = method_id.rsplit('.', 1)
        info = [f"Error: {method_id} - Unexpected result '{json_data['Result']}' (expected {expected_label})"]
        info += [""]
        info += [f"Class Name: 'de.rub.nds.tlstest.suite.tests.{method_class}'"]
        info += [f"Method Name: '{method_name}'"]
        info += [""]

        metadata = json_data.get("MetaData") or {}
        rfc = metadata.get("rfc")
        if rfc is not None:
            info += [f"RFC {rfc.get('number', '?')}, Section {rfc.get('section', '?')}:"]
        else:
            info += ["Custom Test Case:"]

        description = metadata.get("description", "")
        if description:
            info += [description]
        info += [""]

        info += [f"Result: {json_data['Result']}"]

        if json_data.get('DisabledReason'):
            info += [f"Disabled Reason: {json_data['DisabledReason']}"]
        if json_data.get('FailedReason'):
            info += [f"Failed Reason: {json_data['FailedReason']}"]

        info += [""]
        info_str = "\n".join(info)

        # Color in red
        info_str = "\n".join([f"\033[0;31m{line}\033[0m" for line in info_str.split("\n")])

        # In GitHub Actions logging group
        info_str = f"::group::{info_str}\n::endgroup::"

    except (KeyError, TypeError):
        logging.warning("Cannot process test info for %s", method_id)
        info_str = f"Error: {method_id} - Unexpected result '{json_data.get('Result', '?')}'"

    return info_str


def process_test_result(result_path: str, xfails: dict, seen_xfails: set):
    """
    Given a path, process the respective test result .json file.
    Returns True iff the results are expected.
    """
    success = False
    with open(result_path, "r", encoding="utf-8") as f:
        try:
            json_data = json.load(f)
            method_id = extract_method_id(json_data)
            result = json_data["Result"]

            if result == "DISABLED":
                logging.debug("%s: 'DISABLED' -> ok", method_id)
                return True

            if result not in result_level:
                logging.error("Unknown result '%s' for test '%s'", result, method_id)
                return False

            actual_level = result_level[result]

            if method_id in xfails:
                expected_level = xfails[method_id]
                seen_xfails.add(method_id)
                expected_label = [k for k, v in result_level.items() if v == expected_level][0]

                if actual_level != expected_level:
                    # Test is doing other than expected -> error
                    logging.error(
                        "Error: %s has result '%s' but is xfail as '%s'. "
                        "Remove or update the xfail entry.",
                        method_id, result, expected_label)
                    success = False
                else:
                    logging.debug("%s: '%s' -> ok (xfail as %s)", method_id, result, expected_label)
                    success = True
            else:
                # Not in xfail list: must strictly succeed
                if actual_level > result_level["STRICTLY_SUCCEEDED"]:
                    logging.error(failing_test_info(json_data, method_id, "STRICTLY_SUCCEEDED"))
                    success = False
                else:
                    logging.debug("%s: '%s' -> ok", method_id, result)
                    success = True

        except (KeyError, TypeError) as e:
            logging.error("Json file '%s' has missing entries: %s", result_path, e)

    return success


RESULT_FILE_NAME = "_testRun.json"


def main(args=None):
    """Parse args and check all result container files"""
    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true", default=False)
    parser.add_argument("side", help="which side of the protocol was tested (client or server)")
    parser.add_argument("results-dir", help="directory of TLS-Anvil test results")

    args = vars(parser.parse_args(args))

    logging.basicConfig(
        level=(logging.DEBUG if args["verbose"] else logging.INFO),
        format="%(message)s",
    )

    side = args["side"]

    if side not in ["client", "server"]:
        print("Unexpected side %s" % (side))
        return 1

    results_dir = args["results-dir"]

    if not os.access(results_dir, os.X_OK):
        raise FileNotFoundError("Unable to read TLS-Anvil results dir")

    xfails = xfail_list(side)
    seen_xfails = set()

    failed_methods_count = 0
    total_methods_count = 0
    for root, _, files in os.walk(results_dir):
        for file in files:
            if file == RESULT_FILE_NAME:
                abs_path = os.path.abspath(os.path.join(root, file))
                total_methods_count += 1
                if not process_test_result(abs_path, xfails, seen_xfails):
                    failed_methods_count += 1

    if total_methods_count == 0:
        logging.error("No test results found in '%s'", results_dir)
        return 1

    # Check that every xfail entry was actually seen in the results
    missing_xfails = set(xfails.keys()) - seen_xfails
    for method_id in sorted(missing_xfails):
        expected_label = [k for k, v in result_level.items() if v == xfails[method_id]][0]
        logging.warning(
            "xfailed test '%s' (expected %s) was not found in results.",
            method_id, expected_label)

    logging.info(
        "(%i/%i) test methods successful.",
        total_methods_count - failed_methods_count,
        total_methods_count,
    )
    total_success = failed_methods_count == 0
    logging.info("Total result: %s", "Success." if total_success else "Failed.")

    return int(not total_success)


if __name__ == "__main__":
    sys.exit(main())
