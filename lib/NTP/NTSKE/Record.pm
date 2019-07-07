package NTP::NTSKE::Record;

use strict;

sub new {
  my($class) = shift;
  my(%args) = @_;
  my $self = {
    critical => 0,
    %args,
  };
  return bless $self, $class;
}

sub to_packet {
  my($self) = @_;

  die("data length too long for type ".$self->{type}." = ".length($self->{data})) if(length($self->{data}) > 65535);

  my $typecrit = $self->{critical} << 15 | ($self->{type} & 0x7f);
  return pack("nn", $typecrit, length($self->{data})). $self->{data};
}

sub is_critical_without_name {
  my($self) = @_;

  return ($self->{critical} and not defined($self->{name}));
}

sub type {
  my($self) = @_;
  return $self->{type};
}

sub name {
  my($self) = @_;
  return $self->{name};
}

sub data {
  my($self) = @_;
  return $self->{data};
}

1;
