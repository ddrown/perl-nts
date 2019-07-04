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

sub _packload {
  my($line) = $_[0];
  chomp($line);
  return pack("H*", $line);
}

sub load {
  my($file) = @_;
  open(FILE, "<", $file) or die("unable to open $file: $!");
  my(@cookies);
  while(<FILE>) {
    push(@cookies, _packload($_));
  }
  close(FILE);
  my $c2s = shift(@cookies);
  my $s2c = shift(@cookies);

  return NTP::NTSKE::Context->new(c2s => $c2s, s2c => $s2c, cookie => \@cookies);
}

sub save {
  my($self,$file) = @_;

  open(FILE, ">", $file) or die("unable to open $file: $!");
  print FILE unpack("H*", $self->{c2s})."\n";
  print FILE unpack("H*", $self->{s2c})."\n";
  foreach my $cookie (@{ $self->{cookie} }) {
    print FILE unpack("H*", $cookie)."\n";
  }
  close(FILE);
}

sub cookie {
  my($self,$cookie) = @_;
  if(defined($cookie)) {
    push(@{$self->{cookie}}, $cookie);
  }
  return $self->{cookie};
}

sub pop_cookie {
  my($self) = @_;
  return pop(@{$self->{cookie}});
}

sub unshift_cookie {
  my($self,$cookie) = @_;
  unshift(@{$self->{cookie}}, $cookie);
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

sub last_uniq_id {
  my($self,$uniq_id) = @_;
  if(defined($uniq_id)) {
    $self->{uniq_id} = $uniq_id;
  }
  return $self->{uniq_id};
}

1;
