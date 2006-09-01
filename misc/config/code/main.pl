# if($#ARGV < 0) { help(); }

my $debug = 0;
my $no_shared = 0;
my $make_style = '';
my $module_set = '';
my $dumb_gcc = 0;
my $autoconfig = 1;
my $user_set_root = '';
my $build_dir = '';
my $local_config = '';
my @using_mods;
my ($doc_dir, $lib_dir);

my %MODULES = get_modules_list($MOD_DIR);

##################################################
# Parse command line options                     #
##################################################
GetOptions('debug' => sub { $debug = 1; },
           'disable-shared' => sub { $no_shared = 1; },
           'noauto' => sub { $autoconfig = 0 },
           'gcc295x' => sub { $dumb_gcc = 1; },
           'dumb-gcc' => sub { $dumb_gcc = 1; },
           'make-style=s' => \$make_style,
           'modules=s' => \@using_mods,
           'module-set=s' => \$module_set,
           'prefix=s' => \$user_set_root,
           'docdir=s' => \$doc_dir,
           'libdir=s' => \$lib_dir,
           'build-dir=s' => \$build_dir,
           'local-config=s' => \$local_config,
           'help' => sub { help(); }
           );

if($^O eq 'MSWin32' or $^O eq 'dos' or $^O eq 'cygwin') {
  print "Disabling use of symlink()/link() due to Win32 FS limitations\n";
  $FORCE_COPY = 1;
}

my $cc_os_cpu_set = '';
if($#ARGV == 0) { $cc_os_cpu_set = $ARGV[0]; }
elsif($autoconfig) {
    $cc_os_cpu_set = guess_triple();
    print "(autoconfig): Guessing your system config is $cc_os_cpu_set\n";
}
else { help(); }

my ($cc,$os,$submodel) = split(/-/,$cc_os_cpu_set,3);
if(!defined($cc) or !defined($os) or !defined($submodel)) { help(); }

if($build_dir ne '')
{
    $BUILD_DIR = $build_dir;
    $BUILD_INCLUDE_DIR = $build_dir . '/include';
}

##################################################
# Some special hacks                             #
##################################################
#warn "(warning): OpenBSD's GCC 2.95.3 is often buggy with -O2\n" .
#     "         :    Run 'make check' before installing!\n"
#    if($os eq 'openbsd' && $cc eq 'gcc');

if($cc eq 'gcc' && $dumb_gcc != 1)
{
    my $gcc_version = '';

    # Stupid Apple. At least they fixed it after 10.2
    if($os eq 'darwin') { $gcc_version = `c++ -v 2>&1`; }
    else { $gcc_version = `g++ -v 2>&1`; }

    $gcc_version = '' if not defined $gcc_version;

    # GCC 2.95.x and 3.[34] are busted in handling long long in C++. The third
    # check is because on Cygwin (at least for me) $gcc_version doesn't get the
    # output from g++, not sure what's up with that. If it's Cygwin and we
    # didn't get output, assume it's a buggy GCC. There is no reduction in code
    # quality, etc, so even if we're wrong it's no big deal.

    if(($gcc_version =~ /4\.[01]/) ||
       ($gcc_version =~ /3\.[34]/) ||
       ($gcc_version =~ /2\.95\.[0-4]/) ||
       ($gcc_version eq '' && $^O eq 'cygwin'))
    {
        warn "(note): Enabling -fpermissive to work around possible GCC issues\n";
        $dumb_gcc = 1;
    }
    if($gcc_version =~ /2\.95\.[0-4]/)
    {
        print "(note): GCC 2.95.x issues a lot of warnings for things in\n" .
              "      Botan; either ignore the warnings or upgrade to 3.x\n";
    }
}

##################################################
# Check input                                    #
##################################################
$os = $OS_ALIAS{$os} if(defined $OS_ALIAS{$os});

die "(error): Compiler $cc isn't known\n" unless defined($CC_BINARY_NAME{$cc});

die "(error): OS $os isn't known\n" unless
    (defined($OS_SUPPORTS_ARCH{$os}) or $os eq 'generic');

# Get the canonical submodel name (like r8k -> r8000)
$submodel = $SUBMODEL_ALIAS{$submodel} if(defined($SUBMODEL_ALIAS{$submodel}));

my $arch = undef;
# Convert an arch alias to it's real name (like axp -> alpha)
if(defined($ARCH_ALIAS{$submodel}))
   { $arch = $ARCH_ALIAS{$submodel}; $submodel = $arch; }
# If it's a regular submodel type, figure out what arch it is
elsif(defined($ARCH{$submodel}))
   { $arch = $ARCH{$submodel}; }
elsif($submodel eq 'generic') { $arch = 'generic'; }
else { die "(error): Arch $submodel isn't known\n"; }

# If we got a generic family name as the model type
if($submodel eq $arch and $submodel ne 'generic') {
   $submodel = $DEFAULT_SUBMODEL{$arch};

   warn "(note): Using $submodel as default type for family ",
        $REALNAME{$arch},"\n" if($submodel ne $arch);
}

$make_style = $MAKEFILE_STYLE{$cc} unless($make_style);

die "(error): Module set $module_set isn't known\n"
    if($module_set && !defined($MODULE_SETS{$module_set}));

if($module_set) {
   foreach (@{ $MODULE_SETS{$module_set} }) { push @using_mods,$_; }
}

@using_mods = grep {/./} split(/,/,join(',',@using_mods));

if($autoconfig)
{
    foreach (guess_mods($cc,$os,$arch,$submodel))
    {
        # Print a notice, *unless* it was enabled explicitly or via module set
        my $picked_by_user = 0;
        foreach my $x (@using_mods) { $picked_by_user = 1 if($_ eq $x); }

        print "  (autoconfig): Enabling module $_\n" if(!$picked_by_user);
        push @using_mods, $_;
    }
}

# Uniqify @using_mods
my %uniqed_mods;
foreach my $mod (@using_mods) { $uniqed_mods{$mod} = 0; }
@using_mods = sort keys %uniqed_mods;

foreach (@using_mods) {
   die "(error): Module $_ isn't known (try --help)\n"
      unless(exists($MODULES{$_}));
}

##################################################
# Does the OS support the arch?                  #
##################################################
die "(error): $REALNAME{$os} doesn't run on $arch ($submodel)\n"
    unless($arch eq 'generic' or $os eq 'generic' or
           in_array($OS_SUPPORTS_ARCH{$os}, $arch));

##################################################
# Does the compiler support the arch?            #
##################################################
die "(error): $REALNAME{$cc} doesn't run on $arch ($submodel)\n"
    unless($arch eq 'generic' or (in_array($CC_SUPPORTS_ARCH{$cc}, $arch)));

##################################################
# Does the compiler support the OS?              #
##################################################
die "(error): $REALNAME{$cc} doesn't run on $REALNAME{$os}\n"
    unless($os eq 'generic' or (in_array($CC_SUPPORTS_OS{$cc}, $os)));

##################################################
# Check for conflicts in the module selections   #
##################################################
check_for_conflicts(@using_mods);
my (%ignored_src, %ignored_include, %added_src, %added_include);
foreach (@using_mods) {
   load_module($_, $cc, $os, $arch, $submodel, %{ $MODULES{$_} });
}

##################################################
# Print some source files                        #
##################################################
print_pkg_config($os, $MAJOR_VERSION, $MINOR_VERSION, $PATCH_VERSION,
                 using_libs($os, @using_mods));

##################################################
# Figure out the files involved                  #
##################################################
my $CPP_INCLUDE_DIR = catdir($BUILD_INCLUDE_DIR, $CPP_INCLUDE_DIR_DIRNAME);
my $BUILD_LIB_DIR = catdir($BUILD_DIR, $BUILD_DIR_LIB);
my $BUILD_CHECK_DIR = catdir($BUILD_DIR, $BUILD_DIR_CHECKS);

my %lib_src = list_dir($SRC_DIR, \%ignored_src);
my %check_src = list_dir($CHECK_DIR, undef);

my %include = list_dir($INCLUDE_DIR, \%ignored_include);

##################################################
# Set up the build tree                          #
##################################################
mkdirs(($BUILD_DIR,
        $BUILD_INCLUDE_DIR, $CPP_INCLUDE_DIR,
        $BUILD_LIB_DIR, $BUILD_CHECK_DIR));
clean_out_dirs(($CPP_INCLUDE_DIR));

##################################################
# Generate the config.h header                   #
##################################################
my $CONFIG_H_FILE = catfile($BUILD_DIR, $CONFIG_HEADER);

print_config_h($MAJOR_VERSION, $MINOR_VERSION, $PATCH_VERSION,
               $os, $arch, $submodel,
               find_mp_bits(@using_mods), defines(@using_mods),
               defines_base(@using_mods));

$added_include{$CONFIG_HEADER} = $BUILD_DIR;

##################################################
# Copy all headers                               #
##################################################
copy_files($CPP_INCLUDE_DIR, \%include, \%added_include);

##################################################
# Print the makefile                             #
##################################################
my %all_includes = list_dir($CPP_INCLUDE_DIR);

generate_makefile($make_style,
                  $cc, $os, $submodel, $arch,
                  $debug, $no_shared, $dumb_gcc,
                  \%lib_src, \%check_src, \%all_includes,
                  \%added_src, using_libs($os, @using_mods));

exit;
