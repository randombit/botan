package Botan;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $AUTOLOAD);

require DynaLoader;
require AutoLoader;
use Carp;

@ISA = qw(DynaLoader);
$VERSION = '0.01';

@EXPORT_OK = qw(
	NONE
	IGNORE_WS
	FULL_CHECK
);

%EXPORT_TAGS = (
	'all'	=> [ @EXPORT_OK ],
	'decoder_checking'	=> [ qw(
	    NONE
	    IGNORE_WS
	    FULL_CHECK
	)],

);


sub AUTOLOAD
{
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname = $AUTOLOAD;
    $constname =~ s/.*:://;
    croak '& not defined' if $constname eq 'constant';
#    my $val = constant($constname, @_ ? $_[0] : 0);
    my $val = constant($constname);
    if ($! != 0) {
        if ( $! =~ /Invalid/ )
	{
            $AutoLoader::AUTOLOAD = $AUTOLOAD;
            goto &AutoLoader::AUTOLOAD;
        }
        else
	{
	    croak "Your vendor has not defined Botan symbol $constname";
        }
    }
    no strict 'refs';
    *$AUTOLOAD = sub { $val };
    goto &$AUTOLOAD;
}


bootstrap Botan $VERSION;

# to setup inheritance...

package Botan::Filter;
use vars qw(@ISA);
@ISA = qw();

package Botan::Chain;
use vars qw(@ISA);
@ISA = qw( Botan::Filter );

package Botan::Fork;
use vars qw(@ISA);
@ISA = qw( Botan::Filter );

package Botan::Hex_Encoder;
use vars qw(@ISA);
@ISA = qw( Botan::Filter );

package Botan::Hex_Decoder;
use vars qw(@ISA);
@ISA = qw( Botan::Filter );

package Botan::Base64_Decoder;
use vars qw(@ISA);
@ISA = qw( Botan::Filter );

package Botan::Base64_Encoder;
use vars qw(@ISA);
@ISA = qw( Botan::Filter );


package Botan;

1;
__END__

=head1 NAME

Botan - Perl extension for access to Botan ...

=head1 SYNOPSIS

  use Botan;
  blah blah blah

=head1 DESCRIPTION

Blah blah blah.

=head1 AUTHOR

Vaclav Ovsik <vaclav.ovsik@i.cz>

=head1 SEE ALSO

Bla

=cut
