#!/usr/bin/perl -w

# Warning: This file is machine-generated; any changes will be lost. Instead,
# change mkconfig.pl and the system description files. If you find a bug in
# this program (such as generation of incorrect options), please mail
# lloyd@randombit.net with details.

# This file is in the public domain.

# It actually runs on a lot of 5.005 installs, but not all...
require 5.006;

use strict;
use DirHandle;
use Getopt::Long;
use File::Spec;
use File::Copy;
