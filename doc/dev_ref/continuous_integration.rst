Continuous Integration and Automated Testing
===============================================

CI Build Script
----------------

The Github Actions builds are orchestrated using a script
``src/scripts/ci_build.py``. This allows one to easily reproduce the CI process
on a local machine.

Github Actions
---------------

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

Coverity
---------

https://scan.coverity.com/projects/624

An automated source code scanner. Use of Coverity scanner is rate-limited,
sometimes it is very slow to produce a new report, and occasionally the service
goes offline for days or weeks at a time. New reports are kicked off manually by
rebasing branch ``coverity_scan`` against the most recent master and force
pushing it.

OSS-Fuzz
----------

https://github.com/google/oss-fuzz/

OSS-Fuzz is a distributed fuzzer run by Google. Every night, each library fuzzers
in ``src/fuzzer`` are built and run on many machines, with any findings reported
to the developers via email.
