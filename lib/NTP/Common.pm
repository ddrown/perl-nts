package NTP::Common;

# Based on Net::NTP, which has the copyright 2009 by Ask Bjørn Hansen; 2004 by James G. Willmore
#
# This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

use strict;
use Exporter 'import';
our(@EXPORT_OK) = qw(unpack_ip);

sub unpack_ip {
  my($stratum,$tmp_ip) = @_;

  my $ip;
  if ($stratum < 2) {
    $ip = unpack("A4", pack("H8", $tmp_ip));
  }
  else {
    $ip = sprintf("%d.%d.%d.%d", unpack("C4", pack("H8", $tmp_ip)));
  }
  return $ip;
}

1;
