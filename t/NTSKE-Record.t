use strict;
use Test::More tests => 5;

require_ok("NTP::NTSKE::Record");
my $end = NTP::NTSKE::Record->new(type => 0, data => "");
is(unpack("H*",$end->to_packet), "00000000", "end data packet");
my $next_proto = NTP::NTSKE::Record->new(type => 1, data => pack("n", 0));
is(unpack("H*",$next_proto->to_packet), "000100020000", "next proto packet");
# 15 = AEAD_AES_SIV_CMAC_256 https://tools.ietf.org/html/rfc5297
my $aead = NTP::NTSKE::Record->new(type => 4, data => pack("n", 15));
is(unpack("H*",$aead->to_packet), "00040002000f", "aead packet");
my $error = NTP::NTSKE::Record->new(critical => 1, type => 2, data => pack("n", 0));
is(unpack("H*",$error->to_packet), "800200020000", "error packet");
