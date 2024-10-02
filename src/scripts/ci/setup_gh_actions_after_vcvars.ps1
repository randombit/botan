# Secondary setup script for Windows build hosts on GitHub Actions
# that is invoked after the build agent set up its Visual Studio environment.
#
# (C) 2022 Jack Lloyd
# (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)

$targets_with_boost = @("shared", "amalgamation")

if ($targets_with_boost -contains $args[0]) {
    nuget install -NonInteractive -OutputDirectory $env:DEPENDENCIES_LOCATION -Version 1.79.0 boost

    $boostincdir = Join-Path -Path $env:DEPENDENCIES_LOCATION -ChildPath "boost.1.79.0/lib/native/include"
    echo "BOOST_INCLUDEDIR=$boostincdir" >> $env:GITHUB_ENV
}
