sub help
   {
   print <<ENDOFHELP;
Usage: $0 [options] CC-OS-CPU

See doc/building.pdf for more information about this program.

Options:
  --prefix=/path: Set the installation path
  --libdir=/path: Install library files in \${prefix}/\${libdir}
  --docdir=/path: Install documentation in \${prefix}/\${docdir}

  --debug: tune compiler flags for debugging; inferior code can result
  --disable-shared: disable building shared libararies
  --noauto: Disable autoconfiguration
  --dumb-gcc: change makefile flags to support GCC 2.95.x, 3.[34].x, or 4.0.x
  --make-style=STYLE: override the guess as to what type of makefile to use
  --modules=MODS: add module(s) MODS to the library.
  --module-set=SET: add a pre-specified set of modules (unix|win32|beos)

You may use 'generic' for OS or CPU (useful if your OS or CPU isn't listed).

CPU can be a generic family name or a specific model name. Common aliases are
supported but not listed. Choosing a specific submodel will usually result in
code that will not run on earlier versions of that architecture.

ENDOFHELP
   print_listing('CC', %CC_BINARY_NAME);
   print_listing('OS', %OS_SUPPORTS_ARCH);
   print_listing('CPU', %DEFAULT_SUBMODEL);
   if(%MODULES) { print_listing('MODULES', %MODULES); }
   exit;
   }

sub print_listing
   {
   my ($header, %hash) = @_;
   print "$header: ";
   my $len = length "$header: ";
   foreach(sort(keys %hash)) {
       if($len > 71) { print "\n   "; $len = 3; }
       print "$_ ";
       $len += length "$_ ";
   }
   print "\n";
   }

