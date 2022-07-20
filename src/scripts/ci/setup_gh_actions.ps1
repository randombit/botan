# Setup script for Windows build hosts on GitHub Actions
#
# (C) 2022 Jack Lloyd
# (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)

choco install -y jom
choco install -y sccache

# find the sccache cache location and store it in the build job's environment
$raw_cl = (sccache --stats-format json --show-stats | ConvertFrom-Json).cache_location
$cache_location = ([regex] 'Local disk: "(.*)"').Match($raw_cl).groups[1].value
echo "COMPILER_CACHE_LOCATION=$cache_location" >> $env:GITHUB_ENV
