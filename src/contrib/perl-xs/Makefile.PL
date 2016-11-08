use ExtUtils::MakeMaker;

my ($cc, $cflags, $lids);
if ( $^O eq 'MSWin32' )
{
#    $cflags = '';
#    $libs = ':nosearch -lgdi32 -llibeay32';
}
else
{
    $cc = 'g++';
    $cflags = $Config::Config{ccflags} . ' -Wno-write-strings -fexceptions ' . qx( botan config cflags );
    $libs = qx( botan config libs );
}

WriteMakefile(
    'NAME'		=> 'Botan',
    'DISTNAME'		=> 'Botan-XS',
    'VERSION_FROM'	=> 'Botan.pm',		# finds $VERSION
    'XSOPT'		=> '-C++',
    'CC'                => $cc,
    'LD'                => '$(CC)',
    'CCFLAGS'		=> $cflags,
    'LIBS'		=> [ $libs ],
    'OPTIMIZE'		=> '-g',
#    'clean'		=> {
#	    'FILES'	=> 'neco.p12 rnd',
#	},
);
