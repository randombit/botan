# Sublime Text Project

This provides a few convenience integrations for building, testing and debugging the library.

## Configuring and building

The build integrations simply run an already pre-configured `Makefile`. Hence, before build integrations work, a manual `./configure.py` must be executed. After that, the sublime integration will opportunistically re-configure using the same `./configure.py` arguments.

## Running a specific test

There is a special build command that runs the unit test currently in Sublime's active focus. Note that this command opportunistically re-configures and builds the test binary first. Usage of a compiler cache is hence strongly recommended.

## Running all tests

Builds and executes all unit tests.

## Applying Source Formatting

Use Botan's astyle formatting rules on the C++ or header file that is currently in active focus.
