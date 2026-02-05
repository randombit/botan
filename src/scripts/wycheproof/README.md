
# Dynamic Wycheproof Test Integration

This directory contains scripts for running the latest Wycheproof test vectors via Botan's Python bindings.

The test vectors are pulled directly from [the Wycheproof test data repository](https://github.com/C2SP/wycheproof). The source URL is provided via an environment variable, and the JSON files are downloaded on the go.

## Running the Tests

To run the Wycheproof tests against Botan's Python bindings:

1. **Build Botan as shared library**
   Make sure that all relevant algorithms are enabled. Otherwise test failures may occur.

2. **Set up environment variables**
   Set `WYCHEPROOF_TESTDATA_URL` to the base URL containing the Wycheproof JSON test vector files.
   Optionally, set `WYCHEPROOF_TESTDATA_CACHE_DIR` to a local directory to cache the downloaded files.

   Example:
   ```sh
   export WYCHEPROOF_TESTDATA_URL="https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1"
   export WYCHEPROOF_TESTDATA_CACHE_DIR="/tmp/wycheproof-cache"
   ```

   You might also need to set up `LD_LIBRARY_PATH` and `PYTHONPATH` so that the `botan3.py` bindings
   can be found and the shared object can be loaded by it successfully.

3. **Run the tests using Python's unittest**
   From this directory (`src/scripts/wycheproof`), simply run:
   ```sh
   python3 -m unittest
   ```

   You can also run a specific test class or method using unittest's command-line interface if desired.

## Environment Variables

### `WYCHEPROOF_TESTDATA_URL`

The base URL pointing to the directory containing official Wycheproof JSON test vector files, typically `https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1`. This is required for the tests to find the test vectors. This variable is also defined in `src/configs/repo_config.env` for usage in our CI.

### `WYCHEPROOF_TESTDATA_CACHE_DIR`

Local directory path used to cache previously-retrieved Wycheproof test vector files. This is optional and meant for faster turnaround when testing locally by avoiding re-downloading megabytes of test data for every run. In CI this shouldn't be used, because we do want to pull the latest test data every time.

## Adding New Tests

To add a new Wycheproof test, create a new Python file such as `tests/test_*.py` and define a test class like so:

```python
import unittest
from .wycheproof import WycheproofTests

import botan3 as botan

class TestSomeAlgorithm(WycheproofTests, unittest.TestCase):
    def input_files(self) -> list[str]:
        # Replace with the actual Wycheproof test vector file(s) used for this test
        return ["dummy_test_file.json"]

    def run_test(self, data: dict, group: dict, test: dict) -> None:
        # Example: Check expected test values, typically according to Wycheproof's test data schema
        msg = test["input"]
        key = test["key"]
        expected = test["expected"]

        try:
            actual = some_algorithm(key, msg)
            self.assertEqual(actual, expected_value, "Dummy test comparison failed")
        except botan.BotanException:
            if test["result"] == "invalid":
                return
            raise
```

This gives you a starting template. Replace `dummy_test_file.json` with your intended test vector file(s), and add your test logic to the `run_test` method.

The `run_test` method will be called for each individual test vector within the Wycheproof test files. Usually, test vectors are grouped in the test files, and sometimes the `group` variable may contain information that is relevant for all of its test vectors. This may be a common algorithm spec or key material that is shared by all group test vectors.
