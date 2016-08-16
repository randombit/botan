#!/bin/sh
set -ev
which shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

if [ "$BUILD_MODE" = "coverage" ]; then
    GCOV="/usr/bin/gcov-4.8"
    /tmp/usr/bin/lcov --gcov-tool "$GCOV" --directory . --capture --output-file coverage.info
    /tmp/usr/bin/lcov --gcov-tool "$GCOV" --remove coverage.info 'tests/*' '/usr/*' --output-file coverage.info
    /tmp/usr/bin/lcov --gcov-tool "$GCOV" --list coverage.info

    LD_LIBRARY_PATH=. coverage run --branch src/python/botan.py

    codecov
fi

# Run SonarQube analysis
if [ "$TRAVIS_BRANCH" = "master" ] && [ "$TRAVIS_PULL_REQUEST" = "false" ] && [ "$BUILD_MODE" = "sonarqube" ]; then
    # => This will run a full analysis of the project and push results to the SonarQube server.
    #
    # Analysis is done only on master so that build of branches don't push analyses to the same project and therefore "pollute" the results
    echo "Starting analysis by SonarQube..."
    sonar-scanner -Dsonar.login=$SONAR_TOKEN
elif [ "$TRAVIS_PULL_REQUEST" != "false" ] && [ -n "${GITHUB_TOKEN-}" ]  && [ "$BUILD_MODE" = "sonarqube" ]; then
    # => This will analyse the PR and display found issues as comments in the PR, but it won't push results to the SonarQube server
    #
    # For security reasons environment variables are not available on the pull requests
    # coming from outside repositories
    # http://docs.travis-ci.com/user/pull-requests/#Security-Restrictions-when-testing-Pull-Requests
    # That's why the analysis does not need to be executed if the variable GITHUB_TOKEN is not defined.
    echo "Starting Pull Request analysis by SonarQube..."
    sonar-scanner -Dsonar.login=$SONAR_TOKEN \
    -Dsonar.analysis.mode=preview \
    -Dsonar.github.oauth=$GITHUB_TOKEN \
    -Dsonar.github.repository=$TRAVIS_REPO_SLUG \
    -Dsonar.github.pullRequest=$TRAVIS_PULL_REQUEST
fi
# When neither on master branch nor on a non-external pull request => nothing to do
