#!/usr/bin/perl 

sub random_message_ok
{
    my ($pipe, $iter, $chunkmax) = @_;
    $iter = 100 unless defined $iter;
    $chunkmax = 300 unless defined $chunkmax;
    eval {
	my $input = '';
	$pipe->start_msg();
	for(my $i = 0; $i < $iter; $i++)
	{
	    my $chunk = '';
	    my $chunklen = int(rand($chunkmax));
	    $chunk .= pack("C", int(rand(256))) while $chunklen--;
	    $input .= $chunk;
	    $pipe->write($chunk);
	}
	$pipe->end_msg();
	my $msg_num = $pipe->message_count() -1;
	my $output = $pipe->read(0xFFFFFFFF, $msg_num);
	return $input eq $output;
    };
}

1;
