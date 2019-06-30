package NTP::NTSKE::Context;

use strict;

sub new {
  my($class) = shift;
  my(%args) = @_;
  if(not defined $args{cookie}) {
    $args{cookie} = [];
  }
  if(not defined $args{server}) {
    $args{server} = [];
  }
  return bless \%args, $class;
}

sub cookie {
  my($self,$cookie) = @_;
  if(defined($cookie)) {
    push(@{$self->{cookie}}, $cookie);
  }
  return $self->{cookie};
}

sub server {
  my($self,$server) = @_;
  if(defined($server)) {
    push(@{$self->{server}}, $server);
  }
  return $self->{server};
}

sub port {
  my($self,$port) = @_;
  if(defined($port)) {
    $self->{port} = $port;
  }
  return $self->{port};
}

sub protocol {
  my($self,$protocol) = @_;
  if(defined($protocol)) {
    $self->{protocol} = $protocol;
  }
  return $self->{protocol};
}

sub aead {
  my($self,$aead) = @_;
  if(defined($aead)) {
    $self->{aead} = $aead;
  }
  return $self->{aead};
}

sub s2c {
  my($self,$s2c) = @_;
  if(defined($s2c)) {
    $self->{s2c} = $s2c;
  }
  return $self->{s2c};
}

sub c2s {
  my($self,$c2s) = @_;
  if(defined($c2s)) {
    $self->{c2s} = $c2s;
  }
  return $self->{c2s};
}

1;
