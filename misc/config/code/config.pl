# If 1, then we always copy include files, without attempting to make symlinks
# or hardlinks. It seems that link("","") will succeed on Windows, but the
# actual operation will fail (FAT32 doesn't support any kind of links).
# This is automatically forced if $^O is 'dos', 'MSWin32', or 'cygwin'
my $FORCE_COPY = 0;

# A whole buncha filenames
my $INCLUDE_DIR = 'include';
my $SRC_DIR = 'src';
my $MOD_DIR = 'modules';
my $CHECK_DIR = 'checks';
my $DOC_DIR = 'doc';
my $BUILD_DIR = 'build';
my $BUILD_DIR_LIB = 'lib';
my $BUILD_DIR_CHECKS = 'checks';
my $MAKE_FILE = 'Makefile';
my $BUILD_INCLUDE_DIR = 'build/include';

my $CONFIG_HEADER = 'build.h';

my $CPP_INCLUDE_DIR_DIRNAME = $PROJECT_NAME_LC;

# Available module sets
my %MODULE_SETS = (
   'unix' => [ 'alloc_mmap', 'es_egd', 'es_ftw', 'es_unix', 'fd_unix',
               'tm_unix' ],
   'beos' => [ 'es_beos', 'es_unix', 'fd_unix', 'tm_unix' ],
   'win32' => ['es_capi', 'es_win32', 'mux_win32', 'tm_win32' ],
);

# Documentation list
my %DOCS = (
   'readme.txt' => undef, # undef = file is in top level directory

   'pgpkeys.asc' => $DOC_DIR,

   'api.pdf' => $DOC_DIR,
   'tutorial.pdf' => $DOC_DIR,
   'fips140.pdf' => $DOC_DIR,

   'api.tex' => $DOC_DIR,
   'tutorial.tex' => $DOC_DIR,
   'fips140.tex' => $DOC_DIR,

   'botan.rc' => $DOC_DIR,

   'credits.txt' => $DOC_DIR,
#   'deprecated.txt' => $DOC_DIR,
   'info.txt' => $DOC_DIR,
   'license.txt' => $DOC_DIR,
   'log.txt' => $DOC_DIR,
   'thanks.txt' => $DOC_DIR,
   'todo.txt' => $DOC_DIR
   );
