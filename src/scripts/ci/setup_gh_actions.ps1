# Setup script for Windows build hosts on GitHub Actions
#
# (C) 2022 Jack Lloyd
# (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
# (C) 2023 René Fischer, Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)

param(
    [Parameter()]
    [String]$TARGET,
    [String]$ARCH
)

choco install -y sccache

# find the sccache cache location and store it in the build job's environment
$raw_cl = (sccache --stats-format json --show-stats | ConvertFrom-Json).cache_location
$cache_location = ([regex] 'Local disk: "(.*)"').Match($raw_cl).groups[1].value
echo "COMPILER_CACHE_LOCATION=$cache_location" >> $env:GITHUB_ENV

# define a build requirements directory (to be populated in setup_gh_actions_after_vcvars.ps1)
$depsdir = Join-Path -Path (Get-Location) -ChildPath dependencies
echo "DEPENDENCIES_LOCATION=$depsdir" >> $env:GITHUB_ENV

# The 3rd-party action (egor-tensin/vs-shell) must be used with 'amd64' to
# request a 64-bit build environment.
$identifiers_for_64bit = @("x86_64", "x64", "amd64")
if($identifiers_for_64bit -contains $ARCH ) {
    echo "VSENV_ARCH=amd64" >> $env:GITHUB_ENV
} else {
    echo "VSENV_ARCH=$ARCH" >> $env:GITHUB_ENV
}

echo "SCCACHE_CACHE_SIZE=200M" >> $env:GITHUB_ENV
