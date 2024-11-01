Continuous Integration and Automated Testing
===============================================

CI Build Script
----------------

The Github Actions builds are orchestrated using a script
``src/scripts/ci_build.py``. This allows one to easily reproduce the CI process
on a local machine.

Repository Configuration
------------------------

Specific configuration for test dependencies and CI-related global settings
are centralized in ``src/configs/repo_config.env``. This file is pulled into
the CI environment using the python script ``src/scripts/repo_config.py``.

If one needs direct access to the configuration variables (without relying on
environment variables in CI), use ``src/scripts/repo_config.py`` in one of the
following ways:

1. From the command line:

   .. code-block:: bash

      # print all key-value pairs, like: VAR=VALUE\n...
      python3 src/scripts/repo_config.py all

      # print the value of a specific key
      python3 src/scripts/repo_config.py get VAR

      # list all available variables in repo_config.env
      python3 src/scripts/repo_config.py list

2. As a python module (assuming the script is in the PYTHONPATH):

   .. code-block:: python

      from repo_config import RepoConfig
      config = RepoConfig()
      print(config['VAR'])

Github Actions
---------------

https://github.com/randombit/botan/actions/workflows/ci.yml

Github Actions is the primary CI, and tests the Linux, Windows, macOS, and iOS
builds. Among other things it runs tests using valgrind, cross-compilation
for various architectures (currently including ARM and PPC64), MinGW build,
and a build that produces the coverage report.

The Github Actions configuration is in ``.github/workflows/ci.yml`` which
executes platform dependent setup scripts ``src/scripts/ci/setup_gh_actions.sh``
or ``src/scripts/ci/setup_gh_actions.ps1`` and ``.../setup_gh_actions_after_vcvars.ps1``
to install needed packages and detect certain platform specifics like compiler
cache locations.

Then ``src/scripts/ci_build.py`` is invoked to steer the actual build and test
runs.

Github Actions (nightly)
-------------------------

https://github.com/randombit/botan/actions/workflows/nightly.yml

Some checks are just too slow to include in the main CI builds. These
are instead delegated to a scheduled job that runs every night against
master.

Currently these checks include a full run of ``valgrind`` (the valgrind build in
CI only runs a subset of the tests), and a run of ``clang-tidy`` with all
warnings (that we are currently clean for) enabled. Each of these jobs takes
about an hour to run. In the main CI, we aim to have no job take more than
half an hour.

OSS-Fuzz
----------

https://github.com/google/oss-fuzz/

OSS-Fuzz is a distributed fuzzer run by Google. Every night, the fuzzer harnesses
in ``src/fuzzer`` are built and run on many machines, with any findings reported
to the developers via email.
