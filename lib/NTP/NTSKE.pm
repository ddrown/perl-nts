package NTP::NTSKE;

use strict;
use NTP::NTSKE::Records;
use NTP::NTSKE::Context;

our $VERSION = "0.1";

sub new {
  my($class) = shift;
  my(%args) = @_;
  return bless \%args, $class;
}

sub clientmsg {
  my($self) = @_;

  my(@records) = (
    NTP::NTSKE::Records::record_from_name("next-protocol", 1, pack("n", 0)),
    NTP::NTSKE::Records::record_from_name("aead-algorithm", 0, pack("n", 15)),
    NTP::NTSKE::Records::record_from_name("end-of-messages", 1, ""),
    );
  return NTP::NTSKE::Records::to_packet(\@records);
}

sub get_cookie {
  my($self) = @_;

  $self->{tls}->connect();

  my $request = $self->clientmsg();
  if($self->{debug}) {
    print STDERR ">>> ".unpack("H*", $request)."\n";
  }
  $self->{tls}->write($request);

  my $context = NTP::NTSKE::Context->new();

  # TODO: timeout
  my $response = $self->{tls}->read();
  if($self->{debug}) {
    print STDERR "<<< ".unpack("H*", $response)."\n";
  }

  # TODO: response spanning packets
  my(@records) = NTP::NTSKE::Records::parse($response);
  foreach my $record (@records) {
    if($record->is_critical_without_name()) {
      die("critical record of type ".$record->type()." unknown");
    }
    if($record->name() eq "new-cookie") {
      $context->cookie($record->data());
    } elsif($record->name() eq "ntpv4-server") {
      $context->server($record->data());
    } elsif($record->name() eq "ntpv4-port") {
      $context->port(unpack("n",$record->data()));
    } elsif($record->name() eq "next-protocol") {
      $context->protocol(unpack("n",$record->data()));
    } elsif($record->name() eq "aead-algorithm") {
      $context->aead(unpack("n",$record->data()));
    }
  }
  if(not defined($context->protocol())) {
    die("next protocol not set in server response");
  }
  my($c2s,$s2c) = $self->{tls}->get_keying_material(16, $context->protocol(), $context->aead());
  $context->c2s($c2s);
  $context->s2c($s2c);
  return $context;
}

1;
