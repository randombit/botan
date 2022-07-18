Visual Studio shell
===================

[![Test](https://github.com/egor-tensin/vs-shell/actions/workflows/test.yml/badge.svg)](https://github.com/egor-tensin/vs-shell/actions/workflows/test.yml)

This GitHub action sets up a Visual Studio shell in your workflow run.

This is similar to running one of the vcvars*.bat scripts or launching one of
the "Command Tools for VS" Start Menu shortcuts, but it's also shell-agnostic.

Use it in your workflow like this:

    - name: Set up Visual Studio shell
      uses: egor-tensin/vs-shell@v2
      with:
        arch: x64

* `x64` is the default value for the `arch` parameter and can be omitted.
Use `x86` (or `Win32`) if you want to build 32-bit binaries.

API
---

| Input | Value | Default | Description
| ----- | ----- | ------- | -----------
| arch  | x64   | ✓       | Build 64-bit executables.
|       | x86   |         | Build 32-bit executables.
|       | Win32 |         | Build 32-bit executables.

The action passes the environment variables set by one of the vcvars*.bat
scripts to the calling job.

License
-------

Distributed under the MIT License.
See [LICENSE.txt] for details.

[LICENSE.txt]: LICENSE.txt
