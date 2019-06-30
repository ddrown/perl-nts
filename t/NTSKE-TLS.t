use strict;
use Test::More tests => 2;

require_ok("NTP::NTSKE::TLS");

my $obj = NTP::NTSKE::TLS->new(hostname => "localhost");
is(ref($obj), "NTP::NTSKE::TLS", "got an object back");
