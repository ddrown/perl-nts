package NTP::Request;

# Based on Net::NTP, which has the copyright 2009 by Ask Bjørn Hansen; 2004 by James G. Willmore
#
# This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

use strict;
use Net::SSLeay;
use NTP::NTSKE::AES_SIV;
use NTP::NTSKE::Constants qw(EXT_UniqueIdentifier EXT_NTSCookie EXT_NTSAuthenticatorAndEncryptedExtension);

sub new {
  my $class = shift;
  my $self = {@_};
  bless($self,$class);

  return $self;
}

sub uniq_id_pkt {
  my($self) = @_;

  my $uniq = pack("nn", EXT_UniqueIdentifier, 32+4);
  my $rv = Net::SSLeay::RAND_bytes(my $uniq_id, 32);
  if($rv < 1) {
    die("RAND_bytes failed");
  }
  $self->{context}->last_uniq_id($uniq_id);
  $uniq .= $uniq_id;

  return $uniq;
}

sub cookie_pkt {
  my($self) = @_;

  my $cookie = $self->{context}->pop_cookie();
  if(not length($cookie)) {
    die("ran out of cookies");
  }
  my $cookie_pkt = pack("nn", EXT_NTSCookie, length($cookie)+4);
  $cookie_pkt .= $cookie;

  return $cookie_pkt;
}

sub sign_and_encrypt_pkt {
  my($self, $packet) = @_;

  my $rv = Net::SSLeay::RAND_bytes(my $nonce, 16);
  if($rv < 1) {
    die("RAND_bytes failed");
  }
  my $aes_obj = NTP::NTSKE::AES_SIV->new();
  my($status, $aead_output) = $aes_obj->Encrypt($self->{context}->c2s(), $nonce, undef, $packet);
  if($status != 1) {
    die("AES_SIV failed status = $status");
  }

  my $aaee_data = pack("nn", length($nonce), length($aead_output));
  $aaee_data .= $nonce . $aead_output;
  if(length($aaee_data) % 4 != 0) {
    $aaee_data .= pack("C", 0) x (4-(length($aaee_data) % 4));
  }
  if(length($aaee_data) < 28-4) { # padding to minimum extension header length
    $aaee_data .= pack("C", 0) x (28-4-length($aaee_data));
  }

  my $aaee_pkt = pack("nn", EXT_NTSAuthenticatorAndEncryptedExtension, length($aaee_data)+4);
  $aaee_pkt .= $aaee_data;

  return $aaee_pkt;
}

sub packet {
  my($self) = @_;

  my($client_adj_localtime, $client_frac_localtime) = $self->{now}->to_ntp();

  my $packet = pack("B8 C3 N10 B32", '00100011', (0) x 12, $client_adj_localtime, $client_frac_localtime);

  if(defined($self->{context})) {
    $packet .= $self->uniq_id_pkt();
    $packet .= $self->cookie_pkt();
    $packet .= $self->sign_and_encrypt_pkt($packet);
  }

  return $packet;
}

1;
