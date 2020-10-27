Continuous Integration and Automated Testing
===============================================

CI Build Script
----------------

The Travis and AppVeyor builds are orchestrated using a script
``src/scripts/ci_build.py``. This allows one to easily reproduce the CI process
on a local machine.

Travis CI
-----------

https://travis-ci.com/github/randombit/botan

This is the primary CI, and tests the Linux, macOS, and iOS builds. Among other
things it runs tests using valgrind, compilation on various architectures
(currently including ARM, PPC64, and S390x), MinGW build, and a build that
produces the coverage report.

The Travis configurations is in ``src/scripts/ci/travis.yml``, which executes a
setup script ``src/scripts/ci/setup_travis.sh`` to install needed packages.
Then ``src/scripts/ci_build.py`` is invoked.

AppVeyor
----------

https://ci.appveyor.com/project/randombit/botan

Runs a build/test cycle using MSVC on Windows. Like Travis it uses
``src/scripts/ci_build.py``. The AppVeyor setup script is in
``src/scripts/ci/setup_appveyor.bat``

The AppVeyor build uses `sccache <https://github.com/mozilla/sccache>`_ as a
compiler cache. Since that is not available in the AppVeyor images, the setup
script downloads a release binary from the upstream repository.

LGTM
---------

https://lgtm.com/projects/g/randombit/botan/

An automated linter that is integrated with Github. It automatically checks each
incoming PR. It also supports custom queries/alerts, which likely would be worth
investigating but is not something currently in use.

Coverity
---------

https://scan.coverity.com/projects/624

An automated source code scanner. Use of Coverity scanner is rate-limited,
sometimes it is very slow to produce a new report, and occasionally the service
goes offline for days or weeks at a time. New reports are kicked off manually by
rebasing branch ``coverity_scan`` against the most recent master and force
pushing it.

Sonar
-------

https://sonarcloud.io/dashboard?id=botan

Sonar scanner is another software quality scanner. Unfortunately a recent update
of their scanner caused it to take over an hour to produce a report which caused
Travis CI timeouts, so it has been disabled. It should be re-enabled to run on
demand in the same way Coverity is.

OSS-Fuzz
----------

https://github.com/google/oss-fuzz/

OSS-Fuzz is a distributed fuzzer run by Google. Every night, each library fuzzers
in ``src/fuzzer`` are built and run on many machines, with any findings reported
to the developers via email.
