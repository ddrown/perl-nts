package NTP::Timestamp;

# Based on Net::NTP, which has the copyright 2009 by Ask Bjørn Hansen; 2004 by James G. Willmore
#
# This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

use strict;
use Time::HiRes qw(gettimeofday tv_interval);
use constant NTP_ADJ => 2208988800;

sub new {
  my $class = shift;
  my $self = {@_};
  bless($self,$class);

  return $self;
}

sub now {
  my $now = [gettimeofday];
  $now->[1] *= 1000; # us to ns;
  return NTP::Timestamp->new(now => $now);
}

sub from_kernel {
  my($kernel_ts) = @_;

  my($tv_sec,$tv_nsec) = unpack("qq", $kernel_ts);
  return NTP::Timestamp->new(now => [$tv_sec, $tv_nsec]);
}

sub from_ntp {
  my($ntp_sec,$ntp_frac) = @_;

  $ntp_sec = $ntp_sec - NTP_ADJ;
  return from_ntp_short($ntp_sec,$ntp_frac);
}

sub from_ntp_short {
  my($ntp_sec,$ntp_frac) = @_;

  my @bin = split '', $ntp_frac;
  my $frac = 0;
  while (@bin) {
      $frac = ($frac + pop @bin) / 2;
  }
  $frac *= 10**9; # convert from s to ns
  return NTP::Timestamp->new(now => [$ntp_sec, $frac]);
}

sub to_ntp {
  my($self) = @_;

  my $client_adj_localtime  = $self->{now}[0] + NTP_ADJ;
  my $client_frac_localtime = $self->_ntp_fractional();

  return ($client_adj_localtime, $client_frac_localtime);
}

sub to_string {
  my($self) = @_;
  return sprintf("%d.%09d",$self->{now}[0],$self->{now}[1]); # full timestamp as float hits precision limits
}

sub interval {
  my($self,$other) = @_;

  my $sec = $other->{now}[0] - $self->{now}[0];
  my $nsec = $other->{now}[1] - $self->{now}[1];
  return $sec + ($nsec / 10**9);
}

sub seconds {
  my($self) = @_;

  return $self->{now}[0];
}

sub _ntp_fractional {
  my($self) = @_;
  my $bin  = '';

  my $frac = int($self->{now}[1] * 2**32/10**9);
  while (length($bin) < 32) {
    $bin = ($frac % 2) . $bin;
    $frac = int($frac / 2);
  }
  return $bin;
}

1;
